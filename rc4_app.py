import streamlit as st
from Crypto.Cipher import ARC4
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
from io import BytesIO
import streamlit as st
import hashlib
import io
import random

def rc4_encrypt(message, key):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def rc4_decrypt(ciphertext, key):
    cipher = ARC4.new(key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

def main():
    st.title("RC4 Encryption App")

    mode = st.sidebar.radio("Mode", ("Encrypt Text", "Decrypt Text", "Encrypt File", "Decrypt File"))

    key = st.sidebar.text_input("Enter Key", type="password")
    iv = st.sidebar.text_input("Enter IV (Initialization Vector)", type="password")
    salt = st.sidebar.text_input("Enter Salt", type="password")

    if mode in ["Encrypt Text", "Decrypt Text"]:
        text = st.text_area("Enter Text to Process")
        if st.button(mode):
            if not key:
                st.error("Please enter a key")
            else:
                derived_key = PBKDF2(key, salt.encode(), dkLen=16, count=1000000)
                if mode == "Encrypt Text":
                    if not text:
                        st.error("Please enter text to encrypt")
                    else:
                        encrypted_text = rc4_encrypt(text.encode(), derived_key)
                        encrypted_text_base64 = base64.b64encode(encrypted_text).decode('utf-8')
                        st.text_area("Processed Text", value=encrypted_text_base64, height=200)
                else:
                    if not text:
                        st.error("Please enter text to decrypt")
                    else:
                        try:
                            encrypted_text_bytes = base64.b64decode(text)
                        except base64.binascii.Error as e:
                            st.error("Invalid base64 encoded string. Please check the input and try again.")
                        else:
                            decrypted_text = rc4_decrypt(encrypted_text_bytes, derived_key)
                            st.text_area("Processed Text", value=decrypted_text.decode(), height=200)
    
    elif mode in ["Encrypt File"]:
        file = st.file_uploader("Upload File", type=["txt", "pdf"])
        if st.button(mode):
            if not key:
                st.error("Please enter a key")
            elif not file:
                st.error("Please upload a file")
            else:
                file_contents = file.read()
                derived_key = PBKDF2(key, salt.encode(), dkLen=16, count=1000000)
                if mode == "Encrypt File":
                    encrypted_file_contents = rc4_encrypt(file_contents, derived_key)
                    encrypted_file_contents_base64 = base64.b64encode(encrypted_file_contents).decode('utf-8')
                    st.download_button(
                        label="Download Encrypted File",
                        data=BytesIO(encrypted_file_contents_base64.encode()),
                        file_name="encrypted_file.txt",
                        mime="text/plain"
                    )
    elif mode == "Decrypt File":
        file = st.file_uploader("Upload File", type=["txt", "pdf"])
        if st.button(mode):
            if not key:
                st.error("Please enter a key")
            elif not file:
                st.error("Please upload a file")
            else:
                file_contents = file.read()
                derived_key = PBKDF2(key, salt.encode(), dkLen=16, count=1000000)
                try:
                    decrypted_file_contents_bytes = base64.b64decode(file_contents)
                except base64.binascii.Error as e:
                    st.error("Invalid base64 encoded file. Please check the input and try again.")
                else:
                    decrypted_file_contents = rc4_decrypt(decrypted_file_contents_bytes, derived_key)
                    st.text_area("Decrypted File", value=decrypted_file_contents.decode(), height=200)

def hash_text(text, hash_type):
    # Hash the input text using the specified hash function
    if hash_type == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif hash_type == "SHA-1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif hash_type == "SHA-256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif hash_type == "SHA-512":
        return hashlib.sha512(text.encode()).hexdigest()

def hash_file(file, hash_type):
    # Hash the contents of the input file using the specified hash function
    if hash_type == "MD5":
        hasher = hashlib.md5()
    elif hash_type == "SHA-1":
        hasher = hashlib.sha1()
    elif hash_type == "SHA-256":
        hasher = hashlib.sha256()
    elif hash_type == "SHA-512":
        hasher = hashlib.sha512()

    # Read the file contents
    file_contents = file.read()

    # Calculate the hash
    hasher.update(file_contents)

    return hasher.hexdigest()

# Streamlit app
st.title("Hashing Functions")

# Ask the user to input text or upload a file
option = st.radio("Choose input method:", ("Text", "File"))

if option == "Text":
    # Ask the user to input text
    text = st.text_input("Enter text to hash:")
    if text:
        # Ask the user to select the hash function
        hash_type = st.selectbox("Choose a hash function:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))

        # Hash the text using the selected hash function
        hashed_text = hash_text(text, hash_type)

        # Display the hash value
        st.write("Hash value:", hashed_text)
elif option == "File":
    # Ask the user to upload a file
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        # Ask the user to select the hash function
        hash_type = st.selectbox("Choose a hash function:", ("MD5", "SHA-1", "SHA-256", "SHA-512"))

        # Hash the file contents using the selected hash function
        hashed_file = hash_file(io.BytesIO(file.read()), hash_type)

        # Display the hash value
        st.write("Hash value:", hashed_file)

def generate_prime(bits):
    # Generate a random prime number of specified bit length
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

def is_prime(n, k=5):
    # Miller-Rabin primality test
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as 2^r * d + 1
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Test primality k times
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gcd(a, b):
    # Euclidean algorithm for finding greatest common divisor
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    # Extended Euclidean algorithm for finding multiplicative inverse
    d = 0
    x1, x2 = 0, 1
    y1, y2 = 1, 0
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2 - temp1 * x1
        y = y2 - temp1 * y1

        x2 = x1
        x1 = x
        y2 = y1
        y1 = y

    if temp_phi == 1:
        return y2 + phi

def generate_keypair(bits):
    # Generate RSA key pair
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randrange(2, phi)
        if gcd(e, phi) == 1:
            break

    d = multiplicative_inverse(e, phi)
    return (e, n), (d, n)

def encrypt(public_key, plaintext):
    # Encrypt plaintext using RSA public key
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext

def decrypt(private_key, ciphertext):
    # Decrypt ciphertext using RSA private key
    d, n = private_key
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext

# Streamlit app
st.title("RSA Encryption and Decryption")

# Ask the user for the bit length of primes
bits = st.slider("Select the bit length for primes", min_value=32, max_value=1024, step=32, value=512)

# Generate RSA key pair
public_key, private_key = generate_keypair(bits)

# Ask the user for the plaintext message
plaintext = st.text_input("Enter the message to encrypt", "Hello, RSA!")

# Encrypt the message using the public key
encrypted_message = encrypt(public_key, plaintext)

# Display the encrypted message
st.write("Encrypted message:", encrypted_message)

# Decrypt the message using the private key
decrypted_message = decrypt(private_key, encrypted_message)

# Display the decrypted message
st.write("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
