# Secure Password Manager

Python internship project: Password Manager.

## Features
- Master-password login
- Encrypted username/password storage
- SQLite database
- Strong random password generator
- Add, view and delete saved accounts
- Tkinter graphical user interface

## Requirements
- Python 3.10 or newer recommended

## Installation
Open Command Prompt in this folder and run:

    pip install -r requirements.txt

## Run

    python password_manager.py

On first run, create a master password. On later runs, use the same master password to unlock the manager.

## Files
- `password_manager.py` - main application
- `requirements.txt` - Python dependency
- `README.md` - project instructions

## Security note
This is an educational internship project. The master password is not stored directly. A salted PBKDF2-HMAC-SHA256 value is stored for verification, and the same master password is used to derive the encryption key for the stored credentials.
