import argparse, os
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 200000

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERS)
    return kdf.derive(password.encode())

def encrypt_file(in_path, out_path, password):
    with open(in_path, "rb") as f: plaintext = f.read()
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    with open(out_path, "wb") as f: f.write(salt + nonce + ciphertext)
    print("✅ File Encrypted:", out_path)

def decrypt_file(in_path, out_path, password):
    with open(in_path, "rb") as f: data = f.read()
    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    key = derive_key(password, salt)
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    with open(out_path, "wb") as f: f.write(plaintext)
    print("✅ File Decrypted:", out_path)

if __name__ == "__main__":
    mode = input("Enter mode (encrypt/decrypt): ").strip()
    infile = input("Enter input file name: ").strip()
    outfile = input("Enter output file name: ").strip()
    pwd = getpass("Password: ")

    if mode == "encrypt":
        encrypt_file(infile, outfile, pwd)
    else:
        decrypt_file(infile, outfile, pwd)
