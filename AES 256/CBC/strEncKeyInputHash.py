from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def validKey(key):
    if len(key) == 32:
        return True

    return False

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

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    dec = AES.new(key, AES.MODE_CBC, iv)
    plainText = dec.decrypt(ciphertext[AES.block_size:])

    return plainText.rstrip(b"\0")


if __name__ == "__main__":
    key = bytes(input("Please enter your 256-bit symmetric key: ").encode("utf-8"))

    if validKey(key):
        privateKey = get_private_key(key)
        print(f"HASHED SYMMETRIC KEY: {privateKey}\n")

        message = bytes(input("Please enter the message: ").encode("utf-8"))
        cipherText = encrypt(message, privateKey)
        plainText = decrypt(cipherText, privateKey)

        print(f"\nCipher Text: {cipherText}\nPlain Text: {plainText}")
    else:
        print(f"\nPlease enter a valid key!\nYour key's length = {len(key)}")
        