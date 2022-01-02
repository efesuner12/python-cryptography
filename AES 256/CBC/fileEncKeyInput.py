from Crypto import Random
from Crypto.Cipher import AES
import os

def validFilePath(path):
    if os.path.exists(path):
        return True
    
    return False

def validKey(key):
    if len(key) == 32:
        return True

    return False

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def encrypt(data, key):
    data = pad(data)
    iv = Random.new().read(AES.block_size)
    enc = AES.new(key, AES.MODE_CBC, iv)

    return iv + enc.encrypt(data)

def encrypt_file(fileName, key):
    with open(fileName, "rb") as f:
        data = f.read()

    cipherText = encrypt(data, key)

    with open(fileName + ".enc", "wb") as f:
        f.write(cipherText)
    
    os.remove(fileName)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    dec = AES.new(key, AES.MODE_CBC, iv)
    plainText = dec.decrypt(ciphertext[AES.block_size:])

    return plainText.rstrip(b"\0")

def decrypt_file(fileName, key):
    with open(fileName, "rb") as f:
        data = f.read()
    
    plainText = decrypt(data, key)

    with open(fileName[:-4], "wb") as f:
        f.write(plainText)

    os.remove(fileName)


if __name__ == "__main__":
    key = bytes(input("Please enter your 256-bit symmetric key: ").encode("utf-8"))

    if validKey(key):
        path = input("Please enter the file path: ")

        if validFilePath(path):
            encrypt_file(path, key)
            print("Encryption successful!")
        else:
            print("Please enter a valid file path!")

        path = input("\nPlease enter the file path of the encrypted file to decrypt: ")

        if validFilePath(path):
            decrypt_file(path, key)
            print("Decryption successful!")
        else:
            print("Please enter a valid file path!")
    else:
        print(f"\nPlease enter a valid key!\nYour key's length = {len(key)}")
