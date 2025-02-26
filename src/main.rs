use std::fs;
use std::path::Path;
use clap::{CommandFactory, Parser};
use colored::*;
mod encryption;
mod stub;
mod utils;

use encryption::encrypt_payload;
use stub::generate_stub;
use utils::ASCII_BANNER;


#[derive(Parser)]
#[command(name = "Crypter", version = "1.0", about = "Encrypts payloads and generates stub executables")]
struct Args {
    #[arg(short = 'i', long, help = "Input file path")]
    input_file: Option<String>,

    #[arg(short = 'o', long, help = "Output file path (optional)")]
    output_file: Option<String>,

    #[arg(short = 'e', long, value_parser = ["exe", "dll"], help = "Choose the output format (exe or dll)")]
    output_format: Option<String>,

    #[arg(short = 'm', long, value_parser = ["aes", "cha"], help = "Select encryption method: aes (AES-256) or cha (ChaCha20)")]
    encryption_method: Option<String>,

    #[arg(short = 'v', long, help = "Enable verbose output")]
    verbose: bool,
}

fn main() {
    println!("{}", ASCII_BANNER.red());

    let args = Args::parse();

    // Argument validation
    if args.input_file.is_none() || args.output_format.is_none() || args.encryption_method.is_none() {
        println!("{}", "[!] Missing required arguments. Use -h for help.".yellow());
        Args::command().print_help().unwrap();
        std::process::exit(1);
    }

    let input_file = args.input_file.as_deref().unwrap();
    let output_format = args.output_format.as_deref().unwrap();
    let encryption_method = args.encryption_method.as_deref().unwrap();

    // Validate input file exists
    if !Path::new(input_file).exists() {
        eprintln!("{}", "[!] Input file does not exist.".red());
        std::process::exit(1);
    }

    // Validate output file extension
    if let Some(output_path) = &args.output_file {
        if !output_path.ends_with(output_format) {
            eprintln!("{}", "[!] Output file extension must match the selected format.".red());
            std::process::exit(1);
        }
    }

    let encryption_display = match encryption_method {
        "aes" => "AES-256".cyan(),
        "cha" => "ChaCha20".cyan(),
        _ => unreachable!(),
    };

    println!(
        "{} {} with {} encryption",
        "[*] Generating".green(),
        output_format.blue(),
        encryption_display
    );

    let payload = fs::read(input_file).expect("Unable to read input file");
    let (encrypted_payload, key, nonce) = encrypt_payload(&payload, encryption_method, args.verbose);

    let output_path = args.output_file.unwrap_or_else(|| format!("stub.{}", output_format));
    generate_stub(&encrypted_payload, &key, &nonce, encryption_method, &output_path);

    println!("{}", "[✔] Stub successfully generated.".green().bold());
}
