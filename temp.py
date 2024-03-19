from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from stegano import lsb
from PIL import Image

# Function to encrypt text
def encrypt_text(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return ct_bytes

# Function to decrypt text
def decrypt_text(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Function to hide text within an image
def hide_text_in_image(text, input_image_path, output_image_path):
    encrypted_text = encrypt_text(text, key)
    secret = lsb.hide(input_image_path, encrypted_text.hex())
    secret.save(output_image_path)

# Function to extract text from a steganographic image
def extract_text_from_image(image_path, key):
    extracted_text_hex = lsb.reveal(image_path)
    ciphertext = bytes.fromhex(extracted_text_hex)
    decrypted_text = decrypt_text(ciphertext, key)  # Decrypt the text
    return decrypted_text

# Example usage
input_image_path = "quantoomloom_2.png"
output_image_path = "stego_image.png"
key = get_random_bytes(16)  # 128-bit key for AES encryption
text_to_hide = "This is a secret message hidden within the image."

# Hide text within the image
hide_text_in_image(text_to_hide, input_image_path, output_image_path)

# Extract hidden text from the steganographic image
extracted_text = extract_text_from_image(output_image_path, key)
print("Extracted text:", extracted_text)
