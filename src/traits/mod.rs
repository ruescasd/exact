pub mod element;
pub mod group;
pub mod scalar;

pub use element::GroupElement;
pub use group::CryptoGroup;
pub use scalar::GroupScalar;

// convenience to avoid repetitive "<G as CryptoGroup>::.." in types
pub(crate) type ElementT<G> = <G as CryptoGroup>::Element;
pub(crate) type ScalarT<G> = <G as CryptoGroup>::Scalar;
