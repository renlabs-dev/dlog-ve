use centipede::juggling::{
    proof_system::{Helgamalsegmented, Proof, Witness},
    segmentation::Msegmentation,
};
use curv::{
    arithmetic::Converter,
    elliptic::curves::{
        secp256_k1::{Secp256k1Point, Secp256k1Scalar},
        ECPoint, ECScalar, Point, Scalar,
    },
    BigInt,
};

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
    public_key: Secp256k1Point,
    secret: Secp256k1Scalar,
) -> Result<(Witness, Helgamalsegmented), EncryptError> {
    let public_key = Point::from_raw(public_key).map_err(MismatchedPointOrder)?;
    let secret = Scalar::from_raw(secret);

    let g = Secp256k1Point::generator();
    let g = Point::from_raw(*g).map_err(MismatchedPointOrder)?;

    let (witness, segments) = Msegmentation::to_encrypted_segments(
        &secret,
        &SEGMENT_SIZE,
        NUM_OF_SEGMENTS,
        &public_key,
        &g,
    );

    Ok((witness, segments))
}

pub fn decrypt(
    public_key: Secp256k1Point,
    witness: Witness,
    encryptions: Helgamalsegmented,
) -> Result<Proof, EncryptError> {
    let public_key = Point::from_raw(public_key).map_err(MismatchedPointOrder)?;

    let g = Secp256k1Point::generator();
    let g = Point::from_raw(*g).map_err(MismatchedPointOrder)?;
    let proof = Proof::prove(&witness, &encryptions, &g, &public_key, &SEGMENT_SIZE);

    Ok(proof)
}

pub fn verify(
    proof: Proof,
    encryption_key: Secp256k1Point,
    public_key: Secp256k1Point,
    encryptions: Helgamalsegmented,
) -> Result<bool, EncryptError> {
    let encryption_key = Point::from_raw(encryption_key).map_err(MismatchedPointOrder)?;

    let public_key = Point::from_raw(public_key).map_err(MismatchedPointOrder)?;

    let g = Secp256k1Point::generator();
    let g = Point::from_raw(*g).map_err(MismatchedPointOrder)?;
    let Ok(()) = proof.verify(
        &encryptions,
        &g,
        &encryption_key,
        &public_key,
        &SEGMENT_SIZE,
    ) else {
        return Ok(false);
    };

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let pk = *Secp256k1Point::generator();
        let sk = Secp256k1Scalar::random();
        let a = serde_json::to_string(&encrypt(pk, sk.clone()).unwrap()).unwrap();
        let b = serde_json::to_string(&encrypt(pk, sk).unwrap()).unwrap();
        assert_ne!(a, b);
    }
}
