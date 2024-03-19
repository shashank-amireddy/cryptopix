# CryptoPix (Steganographic AES Encryption)


### Overview

CryptoPix is a Python project that combines AES encryption with steganography to hide encrypted text within an image. The project utilizes the AES encryption algorithm for secure text encryption and LSB steganography for hiding the encrypted text within an image without visibly altering its appearance.


### Features

- Encrypt text using the AES encryption algorithm. 
- Hide encrypted text within an image using LSB steganography. 
- Decrypt hidden text from a steganographic image using the AES encryption key.


## Requirements

- Python 3.x 
- [Crypto](https://pycryptodome.readthedocs.io/) library  
- [stegano](https://stegano.readthedocs.io/) library 
- [Pillow](https://pillow.readthedocs.io/) library


## Installation 
1. Clone the repository:
```command
git clone https://github.com/shashank-amireddy/cryptopix.git
```
2. Install the required Python libraries:

## Usage

1. Run the encryption script:
`python encrypt.py`
2. Enter the text to be encrypted and the encryption key when prompted.
3. The encrypted text will be hidden within the specified input image, and the steganographic image will be saved to the output path.
4. To decrypt the hidden text, run the decryption script:
`python decrypt.py`
5. Enter the path to the steganographic image and the encryption key when prompted.
6. The hidden text will be extracted and decrypted, and the original plaintext will be displayed.


## Author 
[Shashank Reddy](https://github.com/shashank-amireddy)
