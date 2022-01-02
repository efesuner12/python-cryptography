from Crypto import Random
from Crypto.Cipher import AES

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def validKey(key):
    if len(key) == 32:
        return True

    return False

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
        message = bytes(input("Please enter the message: ").encode("utf-8"))
        cipherText = encrypt(message, key)
        plainText = decrypt(cipherText, key)

        print(f"\nCipher Text: {cipherText}\nPlain Text: {plainText}")
    else:
        print(f"\nPlease enter a valid key!\nYour key's length = {len(key)}")
