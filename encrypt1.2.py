import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filename: str, password: str):
    with open(filename, "rb") as f:
        data = f.read()
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, data, None)
    with open(filename + ".encrypted", "wb") as f:
        f.write(salt + nonce + encrypted)
    print(f"File encrypted and saved as {filename}.encrypted")

def main():
    filename = input("Enter the path to the file to encrypt: ")
    password = getpass.getpass("Enter password: ")
    encrypt_file(filename, password)

if __name__ == "__main__":
    main()
