from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from stegano import lsb
from Crypto.Hash import SHA256

def encrypt_text(text,key):
    cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher object with the provided key in ECB mode
    ct_bytes = cipher.encrypt(pad(text.encode(),AES.block_size))  # Pad the plaintext to make its length a multiple of the AES block size
    return ct_bytes

def hide_text_in_image(text, input_image_path, output_image_path):
    encrypted_text = encrypt_text(text, key)  # Convert the encrypted text bytes to hexadecimal string for steganography
    secret = lsb.hide(input_image_path, encrypted_text.hex())  # Hide the encrypted text within the input image using LSB steganography
    secret.save(output_image_path)
    print("TEXT ENCRYPTED IN IMAGE SUCCESSFULLY")
    

def get_user_key(key_size):
    user_key = input("Enter the encryption key: ")
    hash_object = SHA256.new(data=user_key.encode()) # Hash the user-provided key using SHA-256
    key = hash_object.digest() # Truncate the hash to the desired key size
    return key[:key_size]

input_image_path = "quantumloom.png"
output_image_path = "stego_image.png"
key_size=32
key = get_user_key(key_size)
text_to_hide = "THIS IS A SECRET MESSAGE"

hide_text_in_image(text_to_hide,input_image_path,output_image_path)