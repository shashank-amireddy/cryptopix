from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from stegano import lsb

def encrypt_text(text,key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(text.encode(),AES.block_size))
    return ct_bytes

def decrypt_text(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext),AES.block_size)
    return plaintext.decode()

def hide_text_in_image(text, input_image_path, output_image_path):
    encrypted_text = encrypt_text(text, key)
    secret = lsb.hide(input_image_path, encrypted_text.hex())
    secret.save(output_image_path)
    
def extract_text_from_image(image_path, key):
    extracted_text_hex = lsb.reveal(image_path)
    ciphertext = bytes.fromhex(extracted_text_hex)
    decrypted_text = decrypt_text(ciphertext, key)
    return decrypted_text

input_image_path = "quantoomloom_2.png"
output_image_path = "stego_image.png"
key = get_random_bytes(16)
text_to_hide = "THIS IS A SECRET MESSAGE"

hide_text_in_image(text_to_hide,input_image_path,output_image_path)

extracted_text = extract_text_from_image(output_image_path, key)
print("Extracted text:", extracted_text)