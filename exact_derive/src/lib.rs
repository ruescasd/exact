use proc_macro::TokenStream;
use quote::{quote};

#[proc_macro_derive(FSerializable)]
pub fn exact_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();

    impl_exact(&ast)
}

fn impl_exact(ast: &syn::DeriveInput) -> TokenStream {
    let generated = quote! {
    };
    generated.into()
}