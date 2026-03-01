# PYTHOMATOR
<p align="center">
  <img src="https://img.shields.io/badge/Cryptomator%20Format-388E3C?style=plastic&logo=cryptomator&logoColor=white" alt="Cryptomator Format">
  <img src="https://img.shields.io/badge/AES-GCM%20%2B%20SIV-C62828?style=plastic&logoColor=white" alt="AES-GCM + SIV">
  <img src="https://img.shields.io/badge/Python-1565C0?style=plastic&logo=python&logoColor=white" alt="Python">
</p>

For [Cryptomator Vault Format 8](https://docs.cryptomator.org/en/latest/security/architecture/).
Create, open and manage encrypted vaults directly from the terminal. Fully compatible with Cryptomator.

---

## Why

Easily use cryptomator when you can only use pure Python3.
Fully open source.
The cryptography is exactly the same as in Format 8 (1:1). What you create with Pythomator opens in desktop Cryptomator and vice versa.

---

## Installation

```bash
git clone https://github.com/tooter9/pythomator.git
cd pythomator
pip3 install -r requirements.txt
```

## Quick Start

### Interactive menu

```bash
python3 pythomator.py
```

You'll get an interactive menu where you can create a vault, open it, and manage it.

### Or create a vault directly

```bash
python3 pythomator.py create ./MyVault
```

**Important:** If you forget the password, there is absolutely nothing anyone can do to recover it (just like Cryptomator). Write it down, get a tattoo.

Once inside the vault, your prompt will look like this:

```
vault:MyVault / >
```

Enter `help` to see all the commands and know how to use.

## Vault Locations (Interactive Menu)

When using the interactive menu, your vaults are stored in:

```
~/pythomator/
```

Each vault is a separate subdirectory. The menu allows you to create, open, rename, delete vaults, and export backup zips.

---

## Cryptomator Compatibility

I repeat it, vaults created with pythomator:

- Open in Cryptomator desktop (Windows, macOS, Linux)
- Open in Cryptomator Android and iOS apps
- Are safe to store on any cloud provider (Dropbox, Google Drive, S3, Nextcloud, etc.)

---

## Support

If this tool protects your data, solves your problems, then it has fulfilled its mission.

---
