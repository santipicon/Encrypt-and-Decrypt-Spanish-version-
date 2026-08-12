# Encrypt-and-Decrypt-Spanish-version-

# 🔐 SecureSend – Hybrid File Encryption with GUI

**SecureSend** is a cross-platform, user-friendly desktop application that lets you encrypt any file using a hybrid cryptosystem (**AES-256-GCM** + **RSA-2048**) before sending it over the internet.

Never worry about prying eyes again. The recipient only needs their private key to recover the original file with its **exact name and extension** (e.g., `invoice.pdf`).

<img width="642" height="606" alt="image" src="https://github.com/user-attachments/assets/7a075940-01c3-4c1f-89aa-0efa31a0051b" />

---

## ✨ Key Features

- **Hybrid Encryption**: Combines the speed of AES-256 (symmetric) with the security of RSA-2048 (asymmetric).
- **Original Filename Restore**: Automatically restores the file's original name and extension upon decryption (no more `.txt` issues!).
- **Intuitive GUI**: Built with `tkinter` – no command line or terminal knowledge required.
- **Password-Protected Private Keys**: Your private key is safely stored on disk using scrypt and AES-128-CBC (PKCS#8 standard).
- **Authenticated Encryption (GCM)**: Detects if the file has been tampered with during transit.
- **Portable & Open-Source**: 100% Python – you can inspect the code or modify it to suit your needs.

---

## 🛠️ How It Works (The Tech)

1.  **Symmetric Speed (AES-256-GCM)**: Your file is encrypted with a random 256-bit key. This is fast and secure.
2.  **Asymmetric Wrapping (RSA-2048-OAEP)**: The random AES key is encrypted using the *recipient's public key*.
3.  **Single Package**: The encrypted key, nonce, authentication tag, and original filename are bundled into a single `.enc` file.
4.  **Recovery**: The recipient uses their private key to unwrap the AES key and decrypt the file back to its original state.

---

## 📦 Requirements

- **Python 3.6+** – (https://www.python.org/downloads/)
- **pip** (Python package installer)

---

## 🚀 Installation & Setup

1.  **Clone or download** this repository to your local machine.
2.  Open a terminal/command prompt inside the project folder.
3.  Install the required cryptography library:

    ```bash
    pip install -r requirements.txt
