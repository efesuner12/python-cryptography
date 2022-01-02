from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os

key = os.urandom(32)

def validFilePath(path):
    if os.path.exists(path):
        return True
    
    return False

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def get_private_key(key):
    salt = Random.get_random_bytes(AES.block_size)
    kdf = PBKDF2(key, salt, 64, 1000)
    key = kdf[:32]

    return key

def encrypt(data, key):
    data = pad(data)
    iv = Random.new().read(AES.block_size)
    enc = AES.new(key, AES.MODE_CBC, iv)

    return iv + enc.encrypt(data)

def encrypt_file(fileName):
    with open(fileName, "rb") as f:
        data = f.read()

    cipherText = encrypt(data, privateKey)

    with open(fileName + ".enc", "wb") as f:
        f.write(cipherText)
    
    os.remove(fileName)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    dec = AES.new(key, AES.MODE_CBC, iv)
    plainText = dec.decrypt(ciphertext[AES.block_size:])

    return plainText.rstrip(b"\0")

def decrypt_file(fileName):
    with open(fileName, "rb") as f:
        data = f.read()
    
    plainText = decrypt(data, privateKey)

    with open(fileName[:-4], "wb") as f:
        f.write(plainText)

    os.remove(fileName)


if __name__ == "__main__":
    print(f"SYMMETRIC KEY: {key}\n")
    privateKey = get_private_key(key)
    print(f"HASHED SYMMETRIC KEY: {privateKey}\n")

    path = input("Please enter the file path: ")

    if validFilePath(path):
        encrypt_file(path)
        print("Encryption successful!")
    else:
        print("Please enter a valid file path!")

    path = input("\nPlease enter the file path of the encrypted file to decrypt: ")

    if validFilePath(path):
        decrypt_file(path)
        print("Decryption successful!")
    else:
        print("Please enter a valid file path!")
        