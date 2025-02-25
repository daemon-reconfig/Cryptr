use std::fs;
use std::path::Path;
use std::process::Command;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::{Aead, AeadCore}};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce, aead::Aead as ChaChaAead};
use clap::{Parser};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn encrypt_payload(payload: &[u8], encryption_type: &str, verbose: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = generate_random_bytes(32);
    let nonce = generate_random_bytes(12);

    let encrypted = match encryption_type {
        "AES-256" => {
            let aes_key = Key::<Aes256Gcm>::from_slice(&key);
            let cipher = Aes256Gcm::new(aes_key);
            cipher.encrypt(Nonce::from_slice(&nonce), payload).expect("Encryption failed")
        },
        "ChaCha20" => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&key));
            cipher.encrypt(ChaChaNonce::from_slice(&nonce), payload).expect("Encryption failed")
        },
        _ => panic!("Invalid encryption type"),
    };

    if verbose {
        println!("[Verbose] Encryption successful.");
    }

    (encrypted, key, nonce)
}

fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
