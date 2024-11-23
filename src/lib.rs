use centipede::{
    juggling::{
        proof_system::{Helgamalsegmented, Proof, Witness},
        segmentation::Msegmentation,
    },
    wallet::SecretShare,
};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

pub const SEGMENT_SIZE: usize = 8;
pub const NUM_OF_SEGMENTS: usize = 32;

#[derive(Debug)]
pub enum EncryptError {
    FromHexError(hex::FromHexError),
    DeserializationError(curv::elliptic::curves::DeserializationError),
    ParseBigIntError(curv::arithmetic::ParseBigIntError),
    CentipedeErrors(centipede::Errors),
    MismatchedPointOrder(curv::elliptic::curves::MismatchedPointOrder),
}

pub use EncryptError::*;

pub type Result<T, E = EncryptError> = std::result::Result<T, E>;

#[repr(transparent)]
pub struct EncKeyPair(pub SecretShare);

impl Default for EncKeyPair {
    #[inline(always)]
    fn default() -> Self {
        Self(SecretShare::generate())
    }
}

impl EncKeyPair {
    #[inline(always)]
    pub fn encrypt(&self, secret: &DLogKeyPair) -> (Witness, Helgamalsegmented) {
        let EncKeyPair(enc) = self;
        let DLogKeyPair(dlog) = secret;
        Msegmentation::to_encrypted_segments(
            &dlog.secret,
            &SEGMENT_SIZE,
            NUM_OF_SEGMENTS,
            &enc.pubkey,
            &Point::generator(),
        )
    }

    #[inline(always)]
    pub fn decrypt(&self, ciphertexts: Helgamalsegmented) -> Result<Scalar<Secp256k1>> {
        let EncKeyPair(enc) = self;
        let g = Point::generator();
        let secret = Msegmentation::decrypt(&ciphertexts, &g, &enc.secret, &SEGMENT_SIZE)
            .map_err(CentipedeErrors)?;

        Ok(secret)
    }

    #[inline(always)]
    pub fn prove(&self, witness: Witness, encryptions: &Helgamalsegmented) -> Proof {
        let EncKeyPair(enc) = self;
        let g = Point::generator();
        Proof::prove(&witness, encryptions, &g, &enc.pubkey, &SEGMENT_SIZE)
    }
}

#[repr(transparent)]
pub struct DLogKeyPair(pub SecretShare);

impl Default for DLogKeyPair {
    #[inline(always)]
    fn default() -> Self {
        Self(SecretShare::generate())
    }
}

pub trait Verifiable {
    fn check(&self, enc: &EncKeyPair, dlog: &DLogKeyPair, ciphertexts: &Helgamalsegmented) -> bool;
}

impl Verifiable for Proof {
    #[inline(always)]
    fn check(&self, enc: &EncKeyPair, dlog: &DLogKeyPair, ciphertexts: &Helgamalsegmented) -> bool {
        let EncKeyPair(enc) = enc;
        let DLogKeyPair(dlog) = dlog;
        let g = Point::generator();
        self.verify(ciphertexts, &g, &enc.pubkey, &dlog.pubkey, &SEGMENT_SIZE)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probabilistic_test() {
        let enc = EncKeyPair::default();
        let dlog = DLogKeyPair::default();

        let a = serde_json::to_string(&enc.encrypt(&dlog)).unwrap();
        let b = serde_json::to_string(&enc.encrypt(&dlog)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn zk_test() {
        let enc = EncKeyPair::default();
        let dlog = DLogKeyPair::default();
        let (witness, ciphertexts) = enc.encrypt(&dlog);
        let proof = enc.prove(witness, &ciphertexts);
        let verified = proof.check(&enc, &dlog, &ciphertexts);

        assert!(verified);
    }

    #[test]
    fn zk_wrong_test_1() {
        let enc = EncKeyPair::default();
        let dlog = DLogKeyPair::default();
        let random_dlog = DLogKeyPair::default();
        let (witness, ciphertexts) = enc.encrypt(&dlog);
        let proof = enc.prove(witness, &ciphertexts);
        let verified = proof.check(&enc, &random_dlog, &ciphertexts);

        assert!(!verified);
    }
}
