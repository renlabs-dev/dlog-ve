use centipede::juggling::{
    proof_system::{Helgamalsegmented, Proof, Witness},
    segmentation::Msegmentation,
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

pub fn encrypt(
    public_key: Point<Secp256k1>,
    secret: Scalar<Secp256k1>,
) -> Result<(Witness, Helgamalsegmented), EncryptError> {
    let (witness, segments) = Msegmentation::to_encrypted_segments(
        &secret,
        &SEGMENT_SIZE,
        NUM_OF_SEGMENTS,
        &public_key,
        &Point::generator(),
    );

    Ok((witness, segments))
}

pub fn decrypt(
    private_key: Scalar<Secp256k1>,
    encryptions: Helgamalsegmented,
) -> Result<Scalar<Secp256k1>, EncryptError> {
    let g = Point::generator();
    let secret = Msegmentation::decrypt(&encryptions, &g, &private_key, &SEGMENT_SIZE)
        .map_err(CentipedeErrors)?;

    Ok(secret)
}

pub fn prove(
    public_key: Point<Secp256k1>,
    witness: Witness,
    encryptions: &Helgamalsegmented,
) -> Result<Proof, EncryptError> {
    let g = Point::generator();
    let proof = Proof::prove(&witness, encryptions, &g, &public_key, &SEGMENT_SIZE);

    Ok(proof)
}

pub fn verify(
    proof: Proof,
    encryption_key: Point<Secp256k1>,
    public_key: Point<Secp256k1>,
    encryptions: &Helgamalsegmented,
) -> bool {
    let g = Point::generator();
    proof
        .verify(encryptions, &g, &encryption_key, &public_key, &SEGMENT_SIZE)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use centipede::wallet::SecretShare;

    use super::*;

    #[test]
    fn probabilistic_test() {
        let enc = SecretShare::generate();
        let dlog = SecretShare::generate();

        let a = serde_json::to_string(&encrypt(enc.pubkey.clone(), dlog.secret.clone()).unwrap())
            .unwrap();
        let b = serde_json::to_string(&encrypt(enc.pubkey, dlog.secret).unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn zk_test() {
        let enc = SecretShare::generate();
        let dlog = SecretShare::generate();
        let (witness, ciphertexts) = encrypt(enc.pubkey.clone(), dlog.secret.clone()).unwrap();
        let proof = prove(enc.pubkey.clone(), witness, &ciphertexts).unwrap();
        let verified = verify(proof, enc.pubkey, dlog.pubkey, &ciphertexts);

        assert!(dbg!(verified));
    }

    #[test]
    fn zk_wrong_test_1() {
        let enc = SecretShare::generate();
        let dlog = SecretShare::generate();
        let random_dlog = SecretShare::generate();
        let (witness, ciphertexts) = encrypt(enc.pubkey.clone(), dlog.secret.clone()).unwrap();
        let proof = prove(enc.pubkey.clone(), witness, &ciphertexts).unwrap();
        let verified = verify(proof, random_dlog.pubkey, dlog.pubkey, &ciphertexts);

        assert!(!verified);
    }
}
