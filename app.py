import streamlit as st
from hashlib import sha256

def generate_keys():
    """
    Generate public and private keys for RSA encryption.
    
    Uses two small prime numbers (p and q) to calculate the modulus (n),
    Euler's totient (phi), a public exponent (e), and a private exponent (d).
    
    Returns:
        tuple: (e, d, n) where e is the public exponent, d is the private exponent, and n is the modulus.
    """
    # Select two small prime numbers for simplicity
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17  # Public exponent (should be chosen such that 1 < e < phi and gcd(e, phi) = 1)
    
    # Calculate the private exponent d such that (d * e) % phi = 1
    def mod_inverse(a, m):
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1
    
    d = mod_inverse(e, phi)
    return e, d, n

def encrypt_message(message, e, n):
    """
    Encrypt a message using the RSA algorithm.
    
    Each character in the message is converted to its ASCII value,
    raised to the power of e, and then taken modulo n.
    
    Args:
        message (str): The message to encrypt.
        e (int): The public exponent.
        n (int): The modulus.
    
    Returns:
        list: The encrypted message as a list of integers.
    """
    return [pow(ord(char), e, n) for char in message]

def hash_message(message):
    """
    Hash a message using SHA-256.
    
    Args:
        message (str): The message to hash.
    
    Returns:
        str: The hashed message as a hexadecimal string.
    """
    return sha256(message.encode()).hexdigest()

def decrypt_message(encrypted_message, d, n):
    """
    Decrypt a message using the RSA algorithm.
    
    Each integer in the encrypted message is raised to the power of d,
    and then taken modulo n to retrieve the original character.
    
    Args:
        encrypted_message (list): The encrypted message as a list of integers.
        d (int): The private exponent.
        n (int): The modulus.
    
    Returns:
        str: The decrypted message.
    """
    return ''.join([chr(pow(char, d, n)) for char in encrypted_message])

# Set up the Streamlit app
st.title("Simple Cryptography Example")

# Check if keys are already generated, otherwise generate them
if 'e' not in st.session_state:
    st.session_state.e, st.session_state.d, st.session_state.n = generate_keys()

# Button to generate new keys
if st.button("Generate Keys"):
    # Generate the public and private keys
    st.session_state.e, st.session_state.d, st.session_state.n = generate_keys()
    
    # Display the generated keys with a detailed explanation
    st.write("### Keys Generated")
    
    st.write("#### Public Key (e, n): This is like a special lock and key that anyone can use to lock a message.")
    
    st.write("- **e (public exponent)**: Think of this as a special number that helps to lock the message. It works with another number (n) to create a lock. We use 17 because it's a small number that is easy to work with, but in real-life scenarios, a bigger number would be used to make the lock even stronger.")
    st.write(f"  - **Value of e**: {st.session_state.e}")
    
    st.write("- **n (modulus)**: This number is created by multiplying two secret numbers (p and q). In this case, n is 3233 because it is the product of 61 and 53, two prime numbers. This makes n a strong lock that is hard to break. The actual value isn't important; what's important is that it's made from multiplying two prime numbers.")
    st.write(f"  - **Value of n**: {st.session_state.n}")
    
    st.write("#### Private Key (d): This is like a special key that only you have, and it unlocks the message that was locked with the public key.")
    st.write("- **d (private exponent)**: This number works with the public lock (e, n) to unlock the message. It is very important to keep this number secret.")
    st.write(f"  - **Value of d**: {st.session_state.d}")
    
    st.write("### Why Use Special Numbers (Prime Numbers)?")
    st.write("Prime numbers are like special building blocks that are only divisible by themselves and one. They help make the lock (n) very strong and hard to break.")
    
    st.write("### Interesting Fact About Special Relationships (Relative Primes)")
    st.write("Two numbers are relatively prime if they don't share any common building blocks other than one. This is important because it makes sure the lock and key system works properly, so only the person with the private key can unlock the message.")

# Text input for the user to enter a word to encrypt
input_text = st.text_input("Enter a word to encrypt:")

# Button to encrypt the entered word
if st.button("Encrypt"):
    st.write("### Step-by-Step Encryption Process")
    st.write(f"Original message: {input_text}")
    
    # Step 1: Convert each character to its ASCII value
    ascii_values = [ord(char) for char in input_text]
    st.write("Step 1: Convert each character to a special number (ASCII value).")
    st.write(f"ASCII values: {ascii_values}")
    
    # Step 2: Encrypt each ASCII value
    encrypted_msg = encrypt_message(input_text, st.session_state.e, st.session_state.n)
    st.session_state.encrypted_msg = encrypted_msg
    st.write("Step 2: Use the public key to scramble each number so that only someone with the private key can unscramble it.")
    st.write(f"Encrypted message: {encrypted_msg}")
    
    # Display encrypted message
    st.write("### Encrypted Message")
    st.write(f"The encrypted message looks like this: {encrypted_msg}")

    # Fun fact about secret messages
    st.write("### Fun Fact")
    st.write("Did you know? In ancient times, people used secret codes to send messages. For example, Julius Caesar used a simple letter shift to keep his messages secret. Today, we use more advanced methods like RSA encryption to keep our messages safe!")

    
# Button to hash the encrypted message
if 'encrypted_msg' in st.session_state:
    if st.button("Hash Encrypted Message"):
        # Hash the encrypted message
        hashed_msg = hash_message(str(st.session_state.encrypted_msg))
        st.session_state.hashed_msg = hashed_msg
        
        st.write("### Hashing the Encrypted Message")
        
        # Fun explanation with a joke
        st.write("Hashing is like making hashbrowns out of potatoes!")
        st.write("Once you turn potatoes into hashbrowns, it's hard to get back to the original potatoes. Similarly, hashing turns data into a unique string of text that is hard to reverse.")
        
        st.write("Did you know? The world record for the largest serving of hashbrowns was set in 2018 in Oregon, USA, and weighed a whopping 1,488 pounds!")
        
        st.write(f"Hashed encrypted message (using SHA-256): {hashed_msg}")

    # Button to decrypt the encrypted message
if st.button("Decrypt"):
    st.write("### Step-by-Step Decryption Process")
    
    # Step 1: Decrypt each encrypted value
    decrypted_msg = decrypt_message(st.session_state.encrypted_msg, st.session_state.d, st.session_state.n)
    st.write("Step 1: Use the private key to unscramble each number back into the original message.")
    st.write(f"Decrypted message: {decrypted_msg}")
    
    # Step 2: Convert ASCII values back to characters
    decrypted_characters = [chr(pow(char, st.session_state.d, st.session_state.n)) for char in st.session_state.encrypted_msg]
    st.write("Step 2: Convert the numbers back into letters to reveal the original message.")
    st.write(f"Decrypted characters: {decrypted_characters}")
    
    # Display decrypted message
    st.write("### Decrypted Message")
    st.write(f"The decrypted message is: {decrypted_msg}")
    
    # Fun fact about spies
    st.write("### Fun Fact")
    st.write("Did you know? In spy movies like 'Cloak and Dagger,' secret messages are often hidden using codes and gadgets. Just like in those movies, we used a secret key to unlock and reveal our hidden message!")