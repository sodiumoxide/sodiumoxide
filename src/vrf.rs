//! Libsodium VRF helper functions
use ffi;
#[cfg(not(feature = "std"))]
use prelude::*;

use sha2::{Digest, Sha512Trunc256};
use std::convert::TryInto;

/// defining public key length
pub const VRF_PUBKEY_BYTE_LENGTH: usize = ffi::crypto_vrf_PUBLICKEYBYTES as usize;

/// A VrfPrivkey is a private key used for producing VRF proofs.
/// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct VrfPrivKey(pub [u8; 64]);

/// A VrfPubKey is a public key that can be used to verify VRF proofs.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct VrfPubKey(pub [u8; VRF_PUBKEY_BYTE_LENGTH]);

/// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
/// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct VrfProof(pub [u8; 80]);

/// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
/// The VRF scheme guarantees that such output will be unique
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct VrfOutput(pub [u8; 64]);

impl VrfOutput {
    /// VrfOutput as a bytes vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// HashID hashed object identifier
pub type HashID<'a> = &'a str;

/// Digest represents a 32-byte value holding the 256-bit Hash digest.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct CryptoDigest(pub [u8; 32]);

/// Trait for types that can be encoded into byte slices
pub trait Hashable {
    /// Encode type into a hashID and byte slice
    fn to_be_hashed(&self) -> (HashID, Vec<u8>);
}

/// HashObj computes a hash of a Hashable object and its type
pub fn hash_obj<H: Hashable>(h: H) -> CryptoDigest {
    hash(hash_rep(h))
}

/// Hash computes the SHASum512_256 hash of an array of bytes
pub fn hash(h: Vec<u8>) -> CryptoDigest {
    let mut hasher = Sha512Trunc256::new();

    // write input message
    hasher.update(h);

    // read hash digest and consume hasher
    let r: [u8; 32] = hasher
        .finalize()
        .try_into()
        .expect("Hashing failed due to wrong lenght");
    CryptoDigest(r)
}

fn hash_rep<H: Hashable>(h: H) -> Vec<u8> {
    let (hashid, data) = h.to_be_hashed();
    let mut r = hashid.as_bytes().to_vec();
    r.extend_from_slice(&data);
    r
}

/// VrfKeygenFromSeed deterministically generates a VRF keypair from 32 bytes of (secret) entropy.
pub fn vrf_keygen_from_seed(seed: [u8; 32]) -> (VrfPubKey, VrfPrivKey) {
    unsafe {
        let mut pubkey = VrfPubKey([0; VRF_PUBKEY_BYTE_LENGTH]);
        let mut privkey = VrfPrivKey([0; 64]);
        ffi::crypto_vrf_keypair_from_seed(
            pubkey.0.as_mut_ptr(),
            privkey.0.as_mut_ptr(),
            seed.as_ptr(),
        );
        return (pubkey, privkey);
    }
}

/// VrfKeygen generates a random VRF keypair.
pub fn vrf_keygen() -> (VrfPubKey, VrfPrivKey) {
    unsafe {
        let mut pubkey = VrfPubKey([0; VRF_PUBKEY_BYTE_LENGTH]);
        let mut privkey = VrfPrivKey([0; 64]);
        ffi::crypto_vrf_keypair(pubkey.0.as_mut_ptr(), privkey.0.as_mut_ptr());
        return (pubkey, privkey);
    }
}

impl VrfPrivKey {
    /// Pubkey returns the public key that corresponds to the given private key.
    pub fn pubkey(&self) -> VrfPubKey {
        unsafe {
            let mut pubkey = VrfPubKey([0; VRF_PUBKEY_BYTE_LENGTH]);
            ffi::crypto_vrf_sk_to_pk(pubkey.0.as_mut_ptr(), self.0.as_ptr());
            return pubkey;
        }
    }

    /// Prove bytes
    pub fn prove_bytes(&self, msg: &[u8]) -> (VrfProof, bool) {
        unsafe {
            let m = msg; // FIXME: what if msg is empty slice
            let len = msg.len() as u64;
            let mut proof = VrfProof([0; 80]);
            let ret = ffi::crypto_vrf_prove(proof.0.as_mut_ptr(), self.0.as_ptr(), m.as_ptr(), len);
            return (proof, ret == 0);
        }
    }

    /// Prove constructs a VRF Proof for a given Hashable.
    /// ok will be false if the private key is malformed.
    pub fn prove<H: Hashable>(&self, msg: H) -> (VrfProof, bool) {
        self.prove_bytes(hash_rep(msg).as_slice())
    }
}

impl VrfProof {
    /// Hash converts a VRF proof to a VRF output without verifying the proof.
    /// TODO: Consider removing so that we don't accidentally hash an unverified proof
    /// ^^^^ ABOVE TODO IS FROM THE ALGORAND GO CODE
    pub fn hash(&self) -> (VrfOutput, bool) {
        unsafe {
            let mut hash = VrfOutput([0; 64]);
            let ret = ffi::crypto_vrf_proof_to_hash(hash.0.as_mut_ptr(), self.0.as_ptr());
            return (hash, ret == 0);
        }
    }
}

impl VrfPubKey {
    /// Verify bytes
    pub fn verify_bytes(&self, proof: VrfProof, msg: &[u8]) -> (bool, VrfOutput) {
        unsafe {
            let m = msg; //FIXME: what if msg is empty slice
            let len = msg.len() as u64;
            let mut out = VrfOutput([0; 64]);
            let ret = ffi::crypto_vrf_verify(
                out.0.as_mut_ptr(),
                self.0.as_ptr(),
                proof.0.as_ptr(),
                m.as_ptr(),
                len,
            );
            return (ret == 0, out); //FIXME: this is the opposite of the function return that we used so far
        }
    }

    /// Verify checks a VRF proof of a given Hashable. If the proof is valid the pseudorandom VrfOutput will be returned.
    /// For a given public key and message, there are potentially multiple valid proofs.
    /// However, given a public key and message, all valid proofs will yield the same output.
    /// Moreover, the output is indistinguishable from random to anyone without the proof or the secret key.
    pub fn verify<H: Hashable>(&self, proof: VrfProof, msg: H) -> (bool, VrfOutput) {
        self.verify_bytes(proof, hash_rep(msg).as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::convert::TryInto;

    fn must_decode(hex: String) -> Vec<u8> {
        match hex::decode(hex) {
            Ok(decoded) => decoded,
            Err(err) => panic!("ERROR while decoding: {:?}", err),
        }
    }

    fn test_vector(
        sk_hex: String,
        pk_hex: String,
        alpha_hex: String,
        pi_hex: String,
        beta_hex: String,
    ) {
        let seed: [u8; 32] = must_decode(sk_hex).try_into().expect("ERROR: seed size");

        let pk: VrfPubKey = VrfPubKey(must_decode(pk_hex).try_into().expect("ERROR: pk size"));
        let alpha_vec = must_decode(alpha_hex);
        let alpha: &[u8] = alpha_vec.as_slice();
        let pi: VrfProof = VrfProof(must_decode(pi_hex).try_into().expect("ERROR: pi size"));
        let beta: VrfOutput =
            VrfOutput(must_decode(beta_hex).try_into().expect("ERROR: beta size"));

        let (pk_test, sk) = vrf_keygen_from_seed(seed);
        assert_eq!(pk_test, pk);

        let (pi_test, ok) = sk.prove_bytes(alpha);
        assert!(ok);
        assert_eq!(pi_test, pi);

        let (ok, beta_test) = pk.verify_bytes(pi, alpha);
        assert!(ok);
        assert_eq!(beta_test, beta);
    }

    #[test]
    fn test_vrf_test_vectors() {
        ::init().unwrap();

        test_vector(
            String::from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), //sk
            String::from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"), //pk
            String::from(""), // alpha
            String::from("b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900"), // pi
            String::from("5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc"),                                 // beta
        );

        test_vector(
            String::from("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"), //sk
            String::from("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), //pk
            String::from("72"), // alpha
            String::from("ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07"), // pi
            String::from("94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8"),                                 // beta
        );
    }
}
