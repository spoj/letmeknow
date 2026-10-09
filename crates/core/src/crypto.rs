//! openmls's crypto and randomness as RustCrypto has them, but drawing every random byte from `lmk_proto::random`, so
//! that a simulator's seed decides them: RustCrypto's own generators, and HPKE's, are seeded by the system.

use std::convert::Infallible;

use hpke_rs::{Hpke, HpkePublicKey, Mode};
use hpke_rs_crypto::error::Error;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_crypto::{HpkeCrypto, HpkeTestRng, TryCryptoRng, TryRng};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use lmk_proto::random;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType,
    HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};
use openmls::prelude::tls_codec::SecretVLBytes;

#[derive(Default)]
pub struct Crypto(RustCrypto);

#[derive(Default)]
pub struct Rand;

impl OpenMlsRand for Rand {
    type Error = Infallible;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Infallible> {
        Ok(random::random())
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Infallible> {
        let mut bytes = vec![0; len];
        random::fill(&mut bytes);
        Ok(bytes)
    }
}

fn hpke(HpkeConfig(kem, kdf, aead): HpkeConfig) -> Hpke<Seeded> {
    let kem = match kem {
        HpkeKemType::DhKemP256 => KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => KemAlgorithm::DhKem448,
    };
    let kdf = match kdf {
        HpkeKdfType::HkdfSha256 => KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => KdfAlgorithm::HkdfSha512,
    };
    let aead = match aead {
        HpkeAeadType::AesGcm128 => AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => AeadAlgorithm::HpkeExport,
    };
    Hpke::new(Mode::Base, kem, kdf, aead)
}

impl OpenMlsCrypto for Crypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        self.0.supports(ciphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.0.supported_ciphersuites()
    }

    fn hkdf_extract(&self, hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.0.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(&self, hash_type: HashType, key: &[u8], message: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.0.hmac(hash_type, key, message)
    }

    fn hkdf_expand(&self, hash_type: HashType, prk: &[u8], info: &[u8], okm_len: usize) -> Result<SecretVLBytes, CryptoError> {
        self.0.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.hash(hash_type, data)
    }

    fn aead_encrypt(&self, alg: AeadType, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(&self, alg: AeadType, key: &[u8], ct_tag: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    /// Not used: sessions make their keys from `lmk_proto::random`.
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.0.signature_key_gen(alg)
    }

    fn verify_signature(&self, alg: SignatureScheme, data: &[u8], pk: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.0.verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.sign(alg, data, key)
    }

    fn hpke_seal(&self, config: HpkeConfig, pk_r: &[u8], info: &[u8], aad: &[u8], ptxt: &[u8]) -> Result<HpkeCiphertext, CryptoError> {
        let (kem_output, ciphertext) = hpke(config)
            .seal(&HpkePublicKey::from(pk_r), info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?;
        Ok(HpkeCiphertext { kem_output: kem_output.into(), ciphertext: ciphertext.into() })
    }

    fn hpke_open(&self, config: HpkeConfig, input: &HpkeCiphertext, sk_r: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        let (kem_output, context) =
            hpke(config).setup_sender(&HpkePublicKey::from(pk_r), info, None, None, None).map_err(|_| CryptoError::SenderSetupError)?;
        let exported = context.export(exporter_context, exporter_length).map_err(|_| CryptoError::ExporterError)?;
        Ok((kem_output, exported.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.0.hpke_setup_receiver_and_export(config, enc, sk_r, info, exporter_context, exporter_length)
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        self.0.derive_hpke_keypair(config, ikm)
    }
}

/// RustCrypto's HPKE, with a generator that draws from `lmk_proto::random`.
#[derive(Debug)]
struct Seeded;

struct Prng;

impl TryRng for Prng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes(random::random()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes(random::random()))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        random::fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for Prng {}

impl HpkeTestRng for Prng {
    type Error = Infallible;

    fn try_fill_test_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        random::fill(dest);
        Ok(())
    }

    fn seed(&mut self, _: &[u8]) {}
}

impl zeroize::Zeroize for Prng {
    fn zeroize(&mut self) {}
}

impl HpkeCrypto for Seeded {
    type HpkePrng = Prng;

    fn name() -> String {
        HpkeRustCrypto::name()
    }

    fn supports_kdf(alg: KdfAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_kdf(alg)
    }

    fn supports_kem(alg: KemAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_kem(alg)
    }

    fn supports_aead(alg: AeadAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_aead(alg)
    }

    fn prng() -> Prng {
        Prng
    }

    fn kdf_extract(alg: KdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_extract(alg, salt, ikm)
    }

    fn kdf_expand(alg: KdfAlgorithm, prk: &[u8], info: &[u8], output_size: usize) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_expand(alg, prk, info, output_size)
    }

    fn dh(alg: KemAlgorithm, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::dh(alg, pk, sk)
    }

    fn secret_to_public(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::secret_to_public(alg, sk)
    }

    fn kem_key_gen(alg: KemAlgorithm, _: &mut Prng) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_key_gen_derand(alg, &random::random::<32>())
    }

    fn kem_key_gen_derand(alg: KemAlgorithm, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_key_gen_derand(alg, seed)
    }

    /// For KEMs other than DH, which no ciphersuite of ours uses.
    fn kem_encaps(alg: KemAlgorithm, pk_r: &[u8], _: &mut Prng) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_encaps(alg, pk_r, &mut HpkeRustCrypto::prng())
    }

    fn kem_decaps(alg: KemAlgorithm, ct: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kem_decaps(alg, ct, sk_r)
    }

    fn dh_validate_sk(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::dh_validate_sk(alg, sk)
    }

    fn aead_seal(alg: AeadAlgorithm, key: &[u8], nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::aead_seal(alg, key, nonce, aad, msg)
    }

    fn aead_open(alg: AeadAlgorithm, key: &[u8], nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::aead_open(alg, key, nonce, aad, msg)
    }
}
