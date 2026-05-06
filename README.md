# AES Symmetric Encryption & Decryption (Python)

[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/library-PyCryptodome-green)](https://pycryptodome.readthedocs.io/)

This repository contains a robust implementation of the **Advanced Encryption Standard (AES)** using **Cipher Block Chaining (CBC)** mode. Developed as part of the **Cryptology and Coding Theory** coursework at **Victoria University, Kampala**.

## Features
- **Symmetric Encryption:** Uses the industry-standard AES algorithm.
- **Secure Key Management:** Supports 128-bit, 192-bit, and 256-bit keys.
- **CBC Mode with Random IV:** Implements Cipher Block Chaining with a unique, cryptographically secure Initialization Vector (IV) for every encryption cycle.
- **PKCS7 Padding:** Ensures plaintext is correctly padded to the 16-byte block size requirement.
- **Base64 Encoding:** Outputs are encoded in Base64 for easy transport and readability.

## How it Works
The program follows the standard cryptographic pipeline:
1. **Key Generation:** Generates a secure key or derives one from a user passphrase using SHA-256.
2. **Padding:** Plaintext is padded via PKCS7 to fit the 128-bit block structure.
3. **Encryption:** AES-CBC transformations are applied using the secret key and a random 16-byte IV.
4. **Decryption:** The process is reversed to recover the original message.



## Installation & Setup

### 1. Prerequisites
Ensure you have **Python 3.13+** installed. You can check your version by running:
```bash
python --version
```

### 2. Install Dependencies
This project requires the `pycryptodome` library. Install it using the command below (a global mirror is provided if you encounter connection timeouts):
```bash
python -m pip install pycryptodome -i https://pypi.tuna.tsinghua.edu.cn/simple
```

## Usage
Run the script directly from your terminal:
```bash
python aes_encrypt.py
```
Follow the interactive prompts to:
1. Enter your **plaintext message**.
2. Select or generate your **secret key**.
3. View the resulting **Ciphertext**, **IV**, and **Decrypted output**.

## Project Structure
```text
.
├── aes_encrypt.py      # Main implementation file
├── README.md           # Project documentation
└── .gitignore          # Files to exclude from Git
```


