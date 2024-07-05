# Simple Cryptography Example

This is a simple cryptography example using RSA encryption, hashing, and decryption, implemented in a Streamlit app. The app demonstrates how to generate RSA keys, encrypt and decrypt messages, and hash encrypted messages, with easy-to-understand explanations and fun facts.

## Features

- **Key Generation**: Generate public and private keys for RSA encryption.
- **Encryption**: Encrypt a message using the public key.
- **Hashing**: Hash the encrypted message using SHA-256.
- **Decryption**: Decrypt the message using the private key.
- **Fun Facts**: Learn interesting facts about cryptography, hashing, and secret codes.

## Requirements

- Python 3.6 or higher
- Streamlit
- hashlib

## Installation

1. **Clone the Repository**

    ```bash
    git clone https://github.com/mrpapawheelie/rsa-demo.git
    cd rsa-demo
    ```

2. **Create a Virtual Environment**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

## Running the App

1. **Run the Streamlit App**

    ```bash
    streamlit run app.py
    ```

2. **Open the App in Your Browser**

    Open your browser and go to `http://localhost:8501` to see the app in action.

## Usage

- **Generate Keys**: Click the "Generate Keys" button to generate public and private RSA keys.
- **Encrypt Message**: Enter a message in the text input and click "Encrypt" to encrypt the message using the public key.
- **Hash Encrypted Message**: Click "Hash Encrypted Message" to hash the encrypted message using SHA-256.
- **Decrypt Message**: Click "Decrypt" to decrypt the message using the private key.

## Fun Facts and Explanations

- **ASCII Art and Hashing**: Learn about the largest serving of hashbrowns and how hashing is like making hashbrowns.
- **Spy Movies and Decryption**: Discover fun facts about spy movies like "Cloak and Dagger" and how secret messages are unlocked.