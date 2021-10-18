//! Libsodium Base64 encoding/decoding helper functions
use ffi;
#[cfg(not(feature = "std"))]
use prelude::*;
//use std::ptr;

/// defining public key length
pub const VRF_PUBKEY_BYTE_LENGTH: usize = ffi::crypto_vrf_PUBLICKEYBYTES as usize;

/// A VrfPrivkey is a private key used for producing VRF proofs.
/// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
#[derive(Copy, Clone)]
pub struct VrfPrivKey([u8; 64]);

/// A VrfPubkey is a public key that can be used to verify VRF proofs.
#[derive(Copy, Clone)]
pub struct VrfPubkey([u8; VRF_PUBKEY_BYTE_LENGTH]);

/// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
/// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
pub struct VrfProof([u8; 80]);

/// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
/// The VRF scheme guarantees that such output will be unique
pub struct VrfOutput([u8; 64]);
type HashID = [u8; 2]; // This is a bit oversimplified

/// Trait for types that can be encoded into byte slices
pub trait Hashable {
    /// Encode type into a hashID and byte slice
    fn to_be_hashed(&self) -> (HashID, &'static [u8]);
}

// FIXME: Hashable trait... or equivalent
fn hash_rep<H: Hashable>(h: H) -> Vec<u8> {
    let (hashid, data) = h.to_be_hashed();
    let mut r = vec![];
    r.extend_from_slice(&hashid);
    r.extend_from_slice(&data);
    r
}

/// VrfKeygenFromSeed deterministically generates a VRF keypair from 32 bytes of (secret) entropy.
pub fn vrf_keygen_from_seed(seed: [u8; 32]) -> (VrfPubkey, VrfPrivKey) {
    unsafe {
        let mut pubkey = VrfPubkey([0; VRF_PUBKEY_BYTE_LENGTH]);
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
pub fn vrf_keygen() -> (VrfPubkey, VrfPrivKey) {
    unsafe {
        let mut pubkey = VrfPubkey([0; VRF_PUBKEY_BYTE_LENGTH]);
        let mut privkey = VrfPrivKey([0; 64]);
        ffi::crypto_vrf_keypair(pubkey.0.as_mut_ptr(), privkey.0.as_mut_ptr());
        return (pubkey, privkey);
    }
}

impl VrfPrivKey {
    /// Pubkey returns the public key that corresponds to the given private key.
    pub fn pubkey(&self) -> VrfPubkey {
        unsafe {
            let mut pubkey = VrfPubkey([0; VRF_PUBKEY_BYTE_LENGTH]);
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

impl VrfPubkey {
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
