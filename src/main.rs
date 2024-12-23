use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::{distributions::Alphanumeric, Rng};
use anyhow::{anyhow, Context, Result};
use colored::*;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a secret key
    Generate,

    /// Encrypt files or directories
    Encrypt {
        /// Files or directories to encrypt
        targets: Vec<PathBuf>,
        /// Secret key for encryption
        #[arg(long, value_name = "KEY")]
        key: String,
    },

    /// Decrypt files or directories
    Decrypt {
        /// Files or directories to decrypt
        targets: Vec<PathBuf>,
        /// Secret key for decryption
        #[arg(long, value_name = "KEY")]
        key: String,
    },
}

fn generate_key() -> String {
    // Generate exactly 32 bytes of random data
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)  // Take exactly 32 characters
        .map(char::from)
        .collect();
    
    // Return the 32-byte key
    key
}

fn process_file(file_path: &Path, cipher: &Aes256Gcm, encrypt: bool) -> Result<()> {
    let mut file = File::open(file_path).context("Failed to open file")?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).context("Failed to read file")?;

    let processed_data = if encrypt {
        let nonce = rand::thread_rng().gen::<[u8; 12]>();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), data.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;
        [nonce.to_vec(), ciphertext].concat()
    } else {
        let (nonce, ciphertext) = data.split_at(12);
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?
    };

    let mut file = File::create(file_path).context("Failed to create file")?;
    file.write_all(&processed_data).context("Failed to write file")?;

    Ok(())
}


fn process_targets(targets: &[PathBuf], key: &[u8], encrypt: bool) -> Result<()> {
    if key.len() != 32 {
        return Err(anyhow!(
            "Key must be 32 bytes long. Provided key length: {} bytes.",
            key.len()
        ));
    }

    // Fix: Explicitly specify the key type for Aes256Gcm
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    for target in targets {
        if target.is_dir() {
            for entry in fs::read_dir(target).context("Failed to read directory")? {
                let path = entry.context("Failed to read directory entry")?.path();
                if path.is_dir() {
                    process_targets(&[path], key, encrypt)?;
                } else {
                    process_file(&path, &cipher, encrypt).with_context(|| {
                        format!("Failed to process file: {}", path.display())
                    })?;
                    println!(
                        "{}: {}",
                        if encrypt {
                            "Encrypted".green()
                        } else {
                            "Decrypted".green()
                        },
                        path.display()
                    );
                }
            }
        } else if target.is_file() {
            process_file(target, &cipher, encrypt).with_context(|| {
                format!("Failed to process file: {}", target.display())
            })?;
            println!(
                "{}: {}",
                if encrypt {
                    "Encrypted".green()
                } else {
                    "Decrypted".green()
                },
                target.display()
            );
        } else {
            eprintln!("{}: {}", "Skipping unknown target".yellow(), target.display());
        }
    }

    Ok(())
}


fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate => {
            let key = generate_key();
            println!("Generated secret key: {}", key);
        }
        Commands::Encrypt { targets, key } => {
            let key_bytes = key.as_bytes();
            process_targets(&targets, key_bytes, true)
                .context("Failed to encrypt targets")?;
        }
        Commands::Decrypt { targets, key } => {
            let key_bytes = key.as_bytes();
            process_targets(&targets, key_bytes, false)
                .context("Failed to decrypt targets")?;
        }                
    }

    Ok(())
}
