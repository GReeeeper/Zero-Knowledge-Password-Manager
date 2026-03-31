# Zero-Knowledge Password Manager

A secure, local, desktop-based password manager built with Python. It strictly adheres to a **Zero-Knowledge** architecture, meaning your master password is never stored or written to disk.

![Security](https://img.shields.io/badge/Security-AES--256--GCM-green)
![KDF](https://img.shields.io/badge/Key%20Derivation-Argon2id-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

## 🛡️ Security Architecture

- **Zero-Knowledge**: Master password is never stored. Keys are derived on-the-fly and kept in memory only while the vault is unlocked.
- **Key Derivation**: **Argon2id** (memory-hard function) is used to derive encryption keys, making it resistant to GPU/ASIC brute-force attacks.
- **Encryption**: **AES-256-GCM** (Galois/Counter Mode) provides both confidentiality and data integrity.
- **Unique Nonces**: Every entry uses a unique 12-byte nonce.
- **Memory Safety**: Clipboard is automatically cleared 10 seconds after copying a password.

## 🚀 Installation

1.  **Clone the repository** (if you haven't already):
    ```bash
    git clone <your-repo-url>
    cd secure-password-manager
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 🖥️ Usage

1.  **Run the application**:
    ```bash
    python secure_manager.py
    ```

2.  **First Time Setup**:
    - The app will ask you to create a **New Vault**.
    - Enter a strong **Master Password**.
    - **WARNING**: If you lose this password, your data is effectively lost forever. There is no recovery mechanism.

3.  **Features**:
    - **Add Entry**: Store Site, Username, and Password (password is hidden by default and requires the Master Password to un-hide).
    - **Show Password**: Securely displays a selected password in a read-only dialog, but only after re-verifying your Master Password.
    - **Copy Password**: Copies to clipboard and auto-clears after 10s.
    - **Lock Vault**: Instantly clears encryption keys from memory.

## 📂 Storage

- The encrypted vault is stored locally at: `~/.secure_vault.json`

## 🤝 Contributing

1.  Fork the repository.
2.  Create a feature branch.
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

## ⚠️ Disclaimer

This tool is provided for educational and personal use. While it uses industry-standard cryptography, always ensure you have backups of your critical data.
