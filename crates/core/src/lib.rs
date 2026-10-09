//! Groups, identities and contacts, with no network: MLS state through openmls's storage.

pub mod contacts;
pub mod device;
pub mod group;
pub mod identity;
pub mod provider;

use openmls_rust_crypto::RustCrypto;
use openmls_traits::random::OpenMlsRand;

/// Random bytes from openmls's generator, which works in the browser too.
pub fn random<const N: usize>() -> [u8; N] {
    RustCrypto::default().random_array().expect("the system has randomness")
}
