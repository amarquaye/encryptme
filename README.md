# Encryptme

Encryptme is a command-line tool written in Rust for securely encrypting and decrypting files and directories using AES-256-GCM encryption.

## Features

- Secure file encryption using AES-256-GCM.

- Support for both single files and entire directories.

- Random key generation.

- Colored terminal output for better visibility.

- Recursive directory processing.

- Built-in error handling and informative messages.

## Installation

To install the application, you'll need Rust and Cargo installed on your system. Then:

Clone the repository

```bash
git clone https://github.com/amarquaye/encryptme.git
cd encryptme
```

Build the project

```bash
cargo build --release
```

The binary will be available in `target/release/`

## Usage

The CLI provides three main commands:

1. **Generate** a Secret Key

```bash
# Generate a new 32-byte secret key
encryptme generate
```

2. **Encrypt** Files or Directories

```bash
# Encrypt a single file
encryptme encrypt path/to/file --key YOUR_SECRET_KEY

# Encrypt multiple files
encryptme encrypt file1.txt file2.txt --key YOUR_SECRET_KEY

# Encrypt an entire directory
encryptme encrypt path/to/directory --key YOUR_SECRET_KEY
```

3. **Decrypt** Files or Directories

```bash
# Decrypt a single file
encryptme decrypt path/to/encrypted-file --key YOUR_SECRET_KEY

# Decrypt multiple files
encryptme decrypt file1.txt file2.txt --key YOUR_SECRET_KEY

# Decrypt an entire directory
encryptme decrypt path/to/encrypted-directory --key YOUR_SECRET_KEY
```

## Security Notes

- Always keep your encryption key secure and never share it with others.

- The tool uses AES-256-GCM, which provides both confidentiality and authenticity.

- Each encryption operation uses a unique random nonce
  Keys must be exactly 32 bytes long.

## Dependencies

- `clap`: Command-line argument parsing.

- `aes-gcm`: AES-256-GCM encryption.

- `rand`: Secure random number generation.

- `anyhow`: Error handling.

- `colored`: Terminal coloring.

## Error Handling

The application includes comprehensive error handling for common scenarios:

- Invalid key length.

- File access issues.

- Encryption/decryption failures.

- Directory traversal problems.

All errors include contextual information to help diagnose the issue.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

The project is licensed under the [MIT](LICENSE-MIT) and [APACHE v2](LICENSE-APACHE) licenses.

## Development

To work on this project:

```bash
# Clone the repository
git clone https://github.com/amarquaye/encryptme.git
cd encryptme

# Run tests
cargo test

# Build in debug mode
cargo build

# Build in release mode
cargo build --release
```

### Minimum Rust Version

This project requires Rust 1.56.0 or higher due to the use of the 2021 edition and certain dependencies.
