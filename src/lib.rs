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
}

pub use EncryptError::*;

pub fn encrypt(
    public_key: String,
    secret: String,
) -> Result<(Witness, Helgamalsegmented), EncryptError> {
    let public_key = hex::decode(public_key).map_err(FromHexError)?;
    let public_key = Secp256k1Point::deserialize(&public_key).map_err(DeserializationError)?;

    let secret = BigInt::from_hex(&secret).map_err(ParseBigIntError)?;
    let secret: Secp256k1Scalar = ECScalar::from_bigint(&secret);

    let g = Secp256k1Point::generator();

    let (witness, segments) = Msegmentation::to_encrypted_segments(
        &Scalar::from_raw(secret),
        &SEGMENT_SIZE,
        NUM_OF_SEGMENTS,
        &Point::from_raw(public_key).unwrap(),
        &Point::from_raw(*g).unwrap(),
    );

    Ok((witness, segments))
}

pub fn decrypt(
    public_key: String,
    witness: Witness,
    encryptions: Helgamalsegmented,
) -> Result<Proof, EncryptError> {
    let public_key = hex::decode(public_key).map_err(FromHexError)?;
    let public_key = Secp256k1Point::deserialize(&public_key).map_err(DeserializationError)?;

    let g = Secp256k1Point::generator();
    let proof = Proof::prove(
        &witness,
        &encryptions,
        &Point::from_raw(*g).unwrap(),
        &Point::from_raw(public_key).unwrap(),
        &SEGMENT_SIZE,
    );

    Ok(proof)
}

pub fn verify(
    proof: Proof,
    encryption_key: String,
    public_key: String,
    encryptions: Helgamalsegmented,
) -> Result<bool, EncryptError> {
    let encryption_key = hex::decode(encryption_key).map_err(FromHexError)?;
    let encryption_key =
        Secp256k1Point::deserialize(&encryption_key).map_err(DeserializationError)?;

    let public_key = hex::decode(public_key).map_err(FromHexError)?;
    let public_key = Secp256k1Point::deserialize(&public_key).map_err(DeserializationError)?;

    let g = Secp256k1Point::generator();
    let Ok(()) = proof.verify(
        &encryptions,
        &Point::from_raw(*g).unwrap(),
        &Point::from_raw(encryption_key).unwrap(),
        &Point::from_raw(public_key).unwrap(),
        &SEGMENT_SIZE,
    ) else {
        return Ok(false);
    };

    Ok(true)
}