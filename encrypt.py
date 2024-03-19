from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from stegano import lsb
from Crypto.Hash import SHA256

def encrypt_text(text,key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(text.encode(),AES.block_size))
    return ct_bytes

def hide_text_in_image(text, input_image_path, output_image_path):
    encrypted_text = encrypt_text(text, key)
    secret = lsb.hide(input_image_path, encrypted_text.hex())
    secret.save(output_image_path)
    print("TEXT ENCRYPTED IN IMAGE SUCCESSFULLY")
    

def get_user_key(key_size):
    user_key = input("Enter the encryption key: ")
    hash_object = SHA256.new(data=user_key.encode())
    key = hash_object.digest()
    return key[:key_size]

input_image_path = "quantUmloom.png"
output_image_path = "stego_image.png"
key_size=32
key = get_user_key(key_size)
text_to_hide = "THIS IS A SECRET MESSAGE"

hide_text_in_image(text_to_hide,input_image_path,output_image_path)