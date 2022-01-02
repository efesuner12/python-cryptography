from Crypto import Random
from Crypto.Cipher import AES
import os

key = os.urandom(32)

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def encrypt(data, key):
    data = pad(data)
    iv = Random.new().read(AES.block_size)
    enc = AES.new(key, AES.MODE_CBC, iv)

    return iv + enc.encrypt(data)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    dec = AES.new(key, AES.MODE_CBC, iv)
    plainText = dec.decrypt(ciphertext[AES.block_size:])

    return plainText.rstrip(b"\0")


if __name__ == "__main__":
    print(f"SYMMETRIC KEY: {key}\n")

    message = bytes(input("Please enter the message: ").encode("utf-8"))
    cipherText = encrypt(message, key)
    plainText = decrypt(cipherText, key)

    print(f"\nCipher Text: {cipherText}\nPlain Text: {plainText}")
