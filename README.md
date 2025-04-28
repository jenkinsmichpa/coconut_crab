# Coconut Crab

![Coconut Crab Logo](coconut_crab_client/assets/img/favicon.ico "Coconut Crab Logo")

# Description

## Overview

This is client (coconut_crab_client) / server (coconut_crab_server) application built in Rust to simulate a ransomware attack.

**This software is indended for use in education only and should not be used for harm.**

The following additional applications are included:

- **coconut_crab_base_drop** - A basic dropper with a self-contained web client to download and execute coconut_crab_client 
- **group_docx_tool** - A tool to create and verify the authenticity of previously created DOCX files for groups
    - **group_docx_drop** - An accompanying bash script to copy DOCX files to the DC shares of their associated groups **(untested)**
- **coconut_crab_blue_drop** - A tool wrapping [AutoBlue](https://github.com/3ndG4me/AutoBlue-MS17-010/blob/master/zzz_exploit.py) to exploit MS-17-010 to download and execute coconut_crab_client **(untested)**

### Communication

The following HTTPS requests are sent in sequence:

1. **Download** - Client downloads the asymmetric public key
2. **Registration** - Client uploads ID and hostname
3. **Symmetric Key Upload** - Client uploads asymmetrically encrypted symmetric key
4. **Symmetric Key Recovery** - Client requests symmetric key due to premature end (if not completed and within accepted time period)
6. **Completion Announcement** - Client announces that it has completed the encryption process
7. **Symmetric Key Download** - Client provides a decryption code and downloads symmetric key

### Encryption Pipeline

The client performs the following steps to encrypt a file:

1. Walk the filesystem
2. Analyze files to avoid canaries (optional)
3. Create a new encrypted file
4. Overwrite and delete the existing plaintext file

## Features

- Does not run unless the server can be reached for sandboxing
- Analyze mode to list files without encrypting them
- Configurable victim GUI accepting code for decryption
- Configurable TLS encryption in transit
- Configurable and easily modified to be flawed or generate artifacts for detection
- Configurable allow and block lists
    - Filesystem paths
    - File extensions
- Configurable encryption delay time and jitter
- Configurable canary avoidance
    - Analyzes PDF and Office / Zip files
    - Avoids hidden directories and files
    - Identifies keywords
    - Identifies non-default URLs
    - Identifies broken images
- Configurable persistence through a registry entry
- Implements a logging crate with (maybe too) verbose output
    - Client output is automatically shown in debug mode and hidden in release mode
- Less sketchy output executable
    - Windows PE file complete with an icon and properties
    - All necessary certificates / assets are embedded within the EXE file
        - Including the client EXE served by the server
- All persistent application information is stored in a CSV for simple viewing and modification
- Configurable setting of desktop wallpaper
- Reaps benefits being written in Rust including
    - AV doesn't work on it as well
    - Speed
        - Compiled executables
        - Multithreaded pipeline for the client
        - Asynchronous design for the server
    - Memory safe / no garbage collection
    - Cross-platform-ish
    - Implements standard / reviewed cryptography crates (RSA and ChaCha20)

## Considerations

As this is an application for education and not real-world use, there were several shortcuts made to the design including the following:

- A baked in secret is used for request validation and is shared by every client
    - As a mitigation, the secret is obfuscated using litcrypt 
- Every request sent to the server is SHA265 hashed combined with the secret for validation
    - The server is easy to DoS as it does not implement a rate limit
    - The server is not resistant to replay attacks
- By default, the application is configured to use publicaly known RSA key pairs for encryption
    - These can be changed before compilation
- By default, the application is configured not to validate HTTPS certificates to allow the use of self-signed certificates
    - Validation can be enabled through the configuration
- The client must request a public key from the server before it can begin (to create artifacts for students)
    - By default, the public key is written to the victim hard drive. This can be disabled through the configuration.

**I am not a software engineer and this is my first time with Rust. Beware of data loss!**

# Usage

## Configuration

### Client Configuration

Client configuration variables are at the top of `coconut_crab_client/src/main.us`

Variable | Summary
--- | ---
server_port | remote web server port (must match server)
server_fqdn | remote web server hostname or IP address of server
allowlist_paths | paths to target
blocklist_paths | paths to avoid (optional)
allowlist_extensions | file extensions to target (optional)
blocklist_extensions | file extensions to avoid (optional)
encrypted_extension | file extension applied to encrypted files
save_public_key_to_disk | should client save public encryption key to disk
set_wallpaper | should the client set desktop wallpaper to the application icon
https | should the client use HTTP or HTTPS with TLS
verify_server | should the client validate HTTPS certificates
analyze_mode | should files be logged instead of encrypted
persist | should a registry startup entry be created
avoid_hidden | should the client avoid hidden directories and files
avoid_urls | should client avoid URLs that do not occur natively in Office files
avoid_keywords | should client avoid keywords associated with canary files
avoid_broken_images | should client avoid images that cannot be rendered correctly
analyze_office_zip | should client analyze office and zip files for caneries
analyze_pdf | should client analyze pdf files for caneries
random_order | should client randomize the order that files are encrypted
wait_time | time to wait between file encryptions (set to 0 for no delay)
jitter_time | time variance applied wait_time
preshared_secret | code used to validate web requests (must match server)

GUI text can be configured in `coconut_crab_client/ui/main.slint`

The application icon is placed in `coconut_crab_client/assets/img/favicon.ico`

EXE properties can be configured under `[package.metadata.winres]` in `coconut_crab_client/Cargo.toml`

Persistent client variables can be found in the `status.csv` generated by the executable

### Server Configuration

Client configuration variables are at the top of `coconut_crab_server/src/main.us`

Variable | Summary
--- | ---
PORT | web server port (must match client)
RECOVERY_WINDOW | time period that a symmetric key can be recovered if lost by client
PRESHARED_SECRET | code used to validate web requests (must match client)
BYPASS_CODE | code used to unlock decryption on any client

Decryption codes can be found in the `victims.csv` file generated by the executable

## Compilation

### Configure HTTPS Certificates

HTTPS certificates are placed in the following paths:

- `coconut_crab_lib/assets/cert/ca-cert.pem`
- `coconut_crab_lib/assets/cert/cert.pem`
- `coconut_crab_lib/assets/cert/key.pem`

Example HTTPS certificate generation:

```bash
openssl genpkey -algorithm RSA -out ca-key.pem
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 -subj "/C=US/ST=Indiana/L=West Lafayette/O=Purdue University/OU=CIT/OU=470/CN=CA"
openssl genpkey -algorithm RSA -out key.pem
openssl req -new -key key.pem -out server.csr -subj "/C=US/ST=Indiana/L=West Lafayette/O=Purdue University/OU=CIT/OU=470/CN=SERVER_FQDN"
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -days 3650 -sha256
```

### Configure Encryption Certificates

Encryption certificates are placed in the following paths:

- `coconut_crab_server/assets/public/asym-pub-key.pem`
- `coconut_crab_server/assets/private/asym-priv-key.pem`

Example encryption certificate generation:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl rsa -in private.pem -out private_pkcs1.pem -traditional
openssl rsa -pubin -in public.pem -RSAPublicKey_out -out public_pkcs1.pem -traditional
```

### Prepare Windows for Compilation

1. Download and install [rustup](https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe)

### Prepare Linux for Compilation

```bash
apt update
apt install build-essential pkg-config libssl-dev mingw-w64
curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup target add x86_64-pc-windows-gnu
```

### Compile Client on Windows for Windows

```powershell
cargo build --release --bin coconut_crab_client
```

Compiled executable will be output to `target/release/coconut_crab_client.exe`

### Compile Server on Windows for Windows

Copy compiled client executable to `coconut_crab_server/assets/public/coconut_crab_client.exe`

```powershell
cargo build --release --bin coconut_crab_server
```

Compiled executable will be output to `target/release/coconut_crab_server.exe`

### Compile Client on Linux for Windows

```bash
cargo build --release --target x86_64-pc-windows-gnu --bin coconut_crab_client
```

Compiled executable will be output to `target/x86_64-pc-windows-gnu/release/coconut_crab_client.exe`

### Compile Server on Linux for Linux

Copy compiled client executable to `coconut_crab_server/assets/public/coconut_crab_client.exe`

```bash
cargo build --release --bin coconut_crab_server
```

Compiled executable will be output to `target/release/coconut_crab_server`

# Support
If you have any issues with this application, feel free to reach out to [Michael Jenkins](https://jenkinsmichpa.com).

# Authors and Acknowledgement
This project was developed by [Michael Jenkins](https://jenkinsmichpa.com) with the help of [Samuel Ho](mailto:ho176@purdue.edu) for use in teaching Purdue CNIT 47000 - Incident Response Management.

# License
This project is licensed with the MIT License.
