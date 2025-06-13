use proc_macro::TokenStream;
use quote::{quote};

#[proc_macro_derive(FSerializable)]
pub fn exact_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();

    impl_exact(&ast)
}

fn impl_exact(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let generics = &ast.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let fields = match &ast.data {
        syn::Data::Struct(syn::DataStruct { fields: syn::Fields::Unnamed(fields), .. }) => &fields.unnamed,
        _ => panic!("FSerializable can only be derived for newtype structs"),
    };

    if fields.len() != 1 {
        panic!("FSerializable can only be derived for newtype structs with a single field");
    }

    let field_ty = &fields.first().unwrap().ty;

    let mut extended_where_clause = where_clause.cloned().unwrap_or_else(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });
    extended_where_clause.predicates.push(syn::parse_quote!(#field_ty: crate::serialization_hybrid::Size));
    // Ensure the SizeType from the field also implements Unsigned, as it will be our SizeType
    extended_where_clause.predicates.push(syn::parse_quote!(<#field_ty as crate::serialization_hybrid::Size>::SizeType: typenum::Unsigned));


    let generated_size_impl = quote! {
        impl #impl_generics crate::serialization_hybrid::Size for #name #ty_generics #extended_where_clause {
            type SizeType = <#field_ty as crate::serialization_hybrid::Size>::SizeType;
        }
    };

    let mut fserializable_where_clause = where_clause.cloned().unwrap_or_else(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });
    fserializable_where_clause.predicates.push(syn::parse_quote!(#field_ty: crate::serialization_hybrid::Size));
    fserializable_where_clause.predicates.push(syn::parse_quote!(<#field_ty as crate::serialization_hybrid::Size>::SizeType: typenum::Unsigned)); // Ensure field's SizeType is Unsigned
    fserializable_where_clause.predicates.push(syn::parse_quote!(
        #field_ty: crate::serialization_hybrid::FSerializable<<#field_ty as crate::serialization_hybrid::Size>::SizeType>
    ));
    // This bound is removed as it caused issues and might be redundant.
    // The FSerializable trait's own serialize_bytes/deserialize_bytes have specific bounds for [u8;N] conversion.
    // fserializable_where_clause.predicates.push(syn::parse_quote!(
    //     hybrid_array::Array<u8, <Self as crate::serialization_hybrid::Size>::SizeType>: From<[u8; <<Self as crate::serialization_hybrid::Size>::SizeType as typenum::Unsigned>::USIZE]>
    // ));

    // We need this for the struct SizeType itself, not just the field's one.
    fserializable_where_clause.predicates.push(syn::parse_quote!(<Self as crate::serialization_hybrid::Size>::SizeType: typenum::Unsigned));


    let generated_fserializable_impl = quote! {
        impl #impl_generics crate::serialization_hybrid::FSerializable<<Self as crate::serialization_hybrid::Size>::SizeType> for #name #ty_generics #fserializable_where_clause {
            fn serialize(&self) -> hybrid_array::Array<u8, <Self as crate::serialization_hybrid::Size>::SizeType> {
                self.0.serialize()
            }

            fn deserialize(bytes: hybrid_array::Array<u8, <Self as crate::serialization_hybrid::Size>::SizeType>) -> Result<Self, crate::serialization_hybrid::Error> {
                Ok(Self(#field_ty::deserialize(bytes)?))
            }
        }
    };

    let generated = quote! {
        #generated_size_impl
        #generated_fserializable_impl
    };
    generated.into()
}