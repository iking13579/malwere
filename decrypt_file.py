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

def decrypt_file(filename: str, password: str):
    with open(filename, "rb") as f:
        raw = f.read()
    salt = raw[:16]
    nonce = raw[16:28]
    encrypted = raw[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        decrypted = aesgcm.decrypt(nonce, encrypted, None)
    except Exception as e:
        print("Decryption failed. Wrong password or corrupted file.")
        return
    output_file = filename.replace(".encrypted", "") + ".decrypted"
    with open(output_file, "wb") as f:
        f.write(decrypted)
    print(f"File decrypted and saved as {output_file}")

def main():
    filename = input("Enter the path to the encrypted file: ")
    password = getpass.getpass("Enter password: ")
    decrypt_file(filename, password)

if __name__ == "__main__":
    main()
