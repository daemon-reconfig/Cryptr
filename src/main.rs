mod encryption;
mod stub;
mod utils;

use clap::{CommandFactory, Parser};
use colored::*;
use encryption::encrypt_payload;
use stub::generate_stub;
use utils::ASCII_BANNER;

/// Crypter CLI tool for encrypting and generating payloads
#[derive(Parser)]
#[command(name = "Crypter", version = "1.0", about = "Encrypts payloads and generates stub executables")]
struct Args {
    #[arg(short = 'i', long, help = "Input file path")]
    input_file: Option<String>,  // Changed to Option to check if missing

    #[arg(short = 'o', long, help = "Output file path (optional)")]
    output_file: Option<String>,

    #[arg(short = 'e', long, value_parser = ["exe", "dll"], help = "Choose the output format (exe or dll)")]
    output_format: Option<String>,  // Changed to Option

    #[arg(short = 'm', long, value_parser = ["aes", "cha"], help = "Select encryption method: aes (AES-256) or cha (ChaCha20)")]
    encryption_method: Option<String>,  // Changed to Option

    #[arg(short = 'v', long, help = "Enable verbose output")]
    verbose: bool,
}

fn main() {
    // Apply red color to ASCII banner
    println!("{}", ASCII_BANNER.red());

    let args = Args::parse();

    // Show help if required arguments are missing
    if args.input_file.is_none() || args.output_format.is_none() || args.encryption_method.is_none() {
        println!("{}", "[!] Missing required arguments. Use -h for help.".yellow());
        Args::command().print_help().unwrap();
        std::process::exit(1);
    }

    let encryption_type = match args.encryption_method.as_deref().unwrap() {
        "aes" => "AES-256".cyan(),
        "cha" => "ChaCha20".cyan(),
        _ => unreachable!(),
    };

    println!(
        "{} {} with {} encryption",
        "[*] Generating".green(),
        args.output_format.as_deref().unwrap().blue(),
        encryption_type
    );

    let payload = std::fs::read(args.input_file.as_deref().unwrap()).expect("Unable to read input file");
    let (encrypted_payload, key, nonce) = encrypt_payload(&payload, args.encryption_method.as_deref().unwrap(), args.verbose);

    let output_path = args.output_file.unwrap_or_else(|| format!("stub.{}", args.output_format.as_deref().unwrap()));
    generate_stub(&encrypted_payload, &key, &nonce, args.encryption_method.as_deref().unwrap(), &output_path);

    println!("{}", "[✔] Stub successfully generated.".green().bold());
}
