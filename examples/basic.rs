//! # Basic example
//!
//! This example shows a basic usage of the `vrf-rs` crate:
//!
//! 1. Instantiate the `ECVRF` by specifying the `CipherSuite`
//! 2. Generate a VRF proof by using the `prove()` function
//! 3. (Optional) Convert the VRF proof to a hash (e.g. to be used as pseudo-random value)
//! 4. Verify a VRF proof by using `verify()` function

use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

fn main() {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    // let message: &[u8] = b"sample";
    let message =
        hex::decode("95e8035be646f7092dcf1ff720377d040236d546724332557a3f05ad3865c992").unwrap();
    println!("message: 0x{}", hex::encode(&message));

    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();
    println!("Generated VRF proof(pi): 0x{}", hex::encode(&pi));
    println!(
        "Generated hash(beta, hash of gamma): 0x{}",
        hex::encode(&hash)
    );

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &pi, &message);

    match beta {
        Ok(beta) => {
            println!("VRF proof is valid!\nHash output: 0x{}", hex::encode(&beta));
            assert_eq!(hash, beta);
        }
        Err(e) => {
            println!("VRF proof is not valid: {}", e);
        }
    }
}
