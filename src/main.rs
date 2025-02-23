use std::fs;
use std::io::{self, Write};
use std::process::Command;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce, aead::Aead as ChaChaAead};
use rand::rngs::OsRng;
use rand::RngCore;
use hex;

fn main() {
    println!("Crypter :: Choose or die!");

    let output_format = user_choice("Select output format (1: EXE, 2: DLL): ", &["1", "2"]);
    let enc_method = user_choice("Select encryption method (1: AES-256, 2: ChaCha20): ", &["1", "2"]);
    let verbose_method = user_choice("Enable verbose mode? (y/n): ", &["y", "n"]);
    let input_file = user_input("Enter the path to the file you want to encrypt: ");

    let output_type = if output_format == "1" { "exe" } else { "dll" };
    let encryption_type = if enc_method == "1" { "AES-256" } else { "ChaCha20" };
    let verbose = verbose_method == "y";

    println!("Generating {} with {} encryption", output_type, encryption_type);

    let payload = fs::read(&input_file).expect("Unable to read input file");
    let (encrypted_payload, key, nonce) = encrypt_payload(&payload, encryption_type, verbose);

    if verbose {
        println!("[Verbose] Encrypted payload size: {} bytes", encrypted_payload.len());
    }

    generate_stub(&encrypted_payload, &key, &nonce, encryption_type, output_type);
}

fn user_choice(prompt: &str, valid: &[&str]) -> String {
    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let choice = input.trim();
        if valid.contains(&choice) {
            return choice.to_string();
        } else {
            println!("Invalid Input");
        }
    }
}

fn user_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn encrypt_payload(payload: &[u8], encryption_type: &str, verbose: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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

fn generate_stub(encrypted_payload: &[u8], key: &[u8], nonce: &[u8], encryption_type: &str, output_type: &str) {
    let stub_code = format!(
        r#"
    use std::fs;

    const ENCRYPTED_PAYLOAD: &[u8] = &{encrypted_payload};
    const KEY: &[u8] = &{key};
    const NONCE: &[u8] = &{nonce};

    fn main() {{
        let output_path = format!("decrypted.{{}}", "{output_type}");
        println!("Decryption stub running...");
        fs::write(&output_path, ENCRYPTED_PAYLOAD).expect("Failed to write decrypted file");
        println!("[*] Decrypted file saved as {{}}", output_path);
    }}
    "#,
        encrypted_payload = format!("{:?}", encrypted_payload),
        key = format!("{:?}", key),
        nonce = format!("{:?}", nonce),
        output_type = output_type
    );

    fs::write("stub.rs", stub_code).expect("Failed to write stub code");
    println!("[*] Stub written to stub.rs");

    println!("[*] Compiling stub...");
    let status = Command::new("rustc")
        .args(&["stub.rs", "-o", &format!("decrypted.{}", output_type)])
        .status()
        .expect("Failed to execute rustc");

    if status.success() {
        println!("[*] Compilation successful: decrypted.{}", output_type);
    } else {
        println!("[!] Compilation failed.");
    }
}
