use centipede::juggling::{
    proof_system::{Helgamalsegmented, Proof, Witness},
    segmentation::Msegmentation,
};
use curv::{
    arithmetic::{Converter, Modulo},
    elliptic::curves::{Point, Scalar, Secp256k1},
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

use rand::Rng;
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
        .inspect_err(|err| {
            dbg!(err);
        })
        .is_ok()
}

pub fn gen_key_pair<R: Rng>(rng: &mut R) -> (Point<Secp256k1>, Scalar<Secp256k1>) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    (gen_random_point(&bytes), Scalar::random())
}

fn gen_random_point(bytes: &[u8]) -> Point<Secp256k1> {
    let compressed_point_len = secp256k1::constants::PUBLIC_KEY_SIZE;
    let truncated = if bytes.len() > compressed_point_len - 1 {
        &bytes[0..compressed_point_len - 1]
    } else {
        bytes
    };
    let mut buffer = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
    buffer[0] = 0x2;
    buffer[1..1 + truncated.len()].copy_from_slice(truncated);
    if let Ok(point) = Point::from_bytes(&buffer) {
        return point;
    }

    let bn = BigInt::from_bytes(bytes);
    let two = BigInt::from(2);
    let bn_times_two = BigInt::mod_mul(&bn, &two, Scalar::<Secp256k1>::group_order());
    let bytes = BigInt::to_bytes(&bn_times_two);
    gen_random_point(&bytes)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn probabilistic_test() {
        let (encryption_key, _decryption_key) = gen_key_pair(&mut thread_rng());
        let (_public_key, secret_key) = gen_key_pair(&mut thread_rng());

        let a =
            serde_json::to_string(&encrypt(encryption_key.clone(), secret_key.clone()).unwrap())
                .unwrap();
        let b = serde_json::to_string(&encrypt(encryption_key, secret_key).unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn zk_test() {
        let (encryption_key, _decryption_key) = gen_key_pair(&mut thread_rng());
        let (public_key, secret_key) = gen_key_pair(&mut thread_rng());
        let (witness, ciphertexts) = encrypt(encryption_key.clone(), secret_key.clone()).unwrap();
        let proof = prove(encryption_key.clone(), witness, &ciphertexts).unwrap();
        let verified = verify(proof, encryption_key, public_key, &ciphertexts);

        assert!(dbg!(verified));
    }
}
