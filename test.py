from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image

def encrypt_text(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return ct_bytes

def decrypt_text(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def encode_text_to_image(text, image_path):
    image = Image.new("RGB", (len(text), 1))
    pixels = image.load()
    for i, char in enumerate(text):
        pixels[i, 0] = ord(char), 0, 0  # Encode ASCII value as red color
    image.save(image_path)

def decode_text_from_image(image_path):
    image = Image.open(image_path)
    pixels = image.load()
    decoded_text = ""
    for i in range(image.width):
        char = chr(pixels[i, 0][0])  # Decode red channel as ASCII value
        decoded_text += char
    return decoded_text

# Example usage
key = get_random_bytes(16)  # 128-bit key for AES encryption
text = "Hello, World! This is a test message."
encrypted_text = encrypt_text(text, key)
encode_text_to_image(encrypted_text.hex(), "encrypted_image.png")  # Convert encrypted text to hex string and encode it into an image

# Now, if you want to decrypt the text from the image:
encoded_image_path = "encrypted_image.png"
encoded_text_hex = decode_text_from_image(encoded_image_path)
decoded_text = decrypt_text(bytes.fromhex(encoded_text_hex), key)
print("Decrypted text:", decoded_text)
