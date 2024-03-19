from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from stegano import lsb
from Crypto.Hash import SHA256

def decrypt_text(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext),AES.block_size)
    return plaintext.decode()

def extract_text_from_image(image_path, key):
    extracted_text_hex = lsb.reveal(image_path)
    ciphertext = bytes.fromhex(extracted_text_hex)
    decrypted_text = decrypt_text(ciphertext, key)
    return decrypted_text

def get_user_key(key_size):
    user_key = input("Enter the encryption key: ")
    hash_object = SHA256.new(data=user_key.encode())
    key = hash_object.digest()
    return key[:key_size]


output_image_path = "stego_image.png"

key_size=32
key = get_user_key(key_size)

extracted_text = extract_text_from_image(output_image_path, key)
print("Extracted text:", extracted_text)