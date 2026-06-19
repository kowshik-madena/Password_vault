# Secure Password Vault (C++)

A locally hosted, cryptographically secure, command-line password manager written entirely in C++. 

This project was built from the ground up with a strict focus on system-level security, memory safety, and zero-knowledge architecture. It completely avoids third-party cloud servers, ensuring that your cryptographic keys and plaintext data never leave your local machine.

## Key Engineering Features

* **AES-256-CBC Encryption:** Utilizes **AES-256-CBC** (Hardware-accelerated via OpenSSL) to secure the local database, ensuring it is mathematically impossible to brute-force without the Master Password.
* **Cryptographic Password Generation:** Uses OpenSSL's `RAND_bytes` to draw true, unpredictable entropy directly from the OS hardware noise pool.
* **RAM Safety:** Defends against memory-scraping malware. Utilizes the un-optimizable `OPENSSL_cleanse` C-instruction to explicitly overwrite sensitive variables (Master Password, AES keys, decrypted payloads, and OS entropy buffers) with zeros the exact millisecond their usage ends.
* **Zero-Knowledge Display:** Passwords can be auto-generated and injected directly into the AES encryption engine without ever printing to the terminal `stdout`, rendering screen-scraping malware useless.

## Prerequisites & Compilation

To compile and run this vault, you must have OpenSSL installed on your system.

**For Debian/Ubuntu Linux:**
sudo apt-get update
sudo apt-get install libssl-dev

**Compilation:**
Compile the architecture using `g++` and link the OpenSSL cryptography library (`-lcrypto`):
g++ main.cpp -o vault -lcrypto

## Usage Guide

On first run, the vault will prompt you to create a Master Password. This password is hashed via **SHA-256** and serves as the absolute lock for your database. If lost, the database cannot be recovered.

**Available Commands:**

# Manually save a password for a service
./vault add <service> <password>

# Auto-generate a high-entropy password and securely inject it
./vault add <service> --generate [length]

# Retrieve a password
./vault get <service>

# Delete a saved password
./vault delete <service>

# View all saved services
./vault list

## Security Disclaimer & Architecture Notes
* **Data Storage:** The database is serialized and saved locally as `vault.bin`. 
* **Hash Storage:** The Master Password verification hash is stored as `master.hash`. 

---
*Built with an emphasis on low-level C++ memory safety and OpenSSL cryptography.*