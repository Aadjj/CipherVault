import streamlit as st
import os
import base64
import string
import smtplib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from email.mime.text import MIMEText


# Utility functions for the Caesar Cipher
def caesar_encrypt(plain_text, key):
    result = []
    for char in plain_text:
        if char.isupper():
            result.append(chr((ord(char) + key - 65) % 26 + 65))
        elif char.islower():
            result.append(chr((ord(char) + key - 97) % 26 + 97))
        elif char.isdigit():
            result.append(chr((ord(char) + key - 48) % 10 + 48))
        else:
            result.append(char)
    return ''.join(result)


def caesar_decrypt(cipher_text, key):
    return caesar_encrypt(cipher_text, -key)


# Utility functions for the Vigenère Cipher
def vigenere_encrypt(plain_text, key):
    key = ''.join([k for k in key if k.isalpha()]).upper()
    if not key:
        raise ValueError("Key must contain at least one alphabetical character.")

    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plain_text_int = [ord(i) for i in plain_text.upper()]
    cipher_text = ''

    for i in range(len(plain_text_int)):
        if chr(plain_text_int[i]).isalpha():
            value = (plain_text_int[i] + key_as_int[i % key_length]) % 26
            cipher_text += chr(value + 65)
        else:
            cipher_text += chr(plain_text_int[i])

    return cipher_text


def vigenere_decrypt(cipher_text, key):
    key = ''.join([k for k in key if k.isalpha()]).upper()
    if not key:
        raise ValueError("Key must contain at least one alphabetical character.")

    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    cipher_text_int = [ord(i) for i in cipher_text.upper()]
    plain_text = ''

    for i in range(len(cipher_text_int)):
        if chr(cipher_text_int[i]).isalpha():
            value = (cipher_text_int[i] - key_as_int[i % key_length]) % 26
            plain_text += chr(value + 65)
        else:
            plain_text += chr(cipher_text_int[i])

    return plain_text


# Utility functions for a substitution cipher
def create_substitution_cipher(key):
    alphabet = string.ascii_lowercase
    if len(key) != len(alphabet) or set(key) != set(alphabet):
        raise ValueError("Substitution key must be a permutation of the alphabet.")
    return str.maketrans(alphabet, key), str.maketrans(key, alphabet)


def substitution_encrypt(plain_text, key):
    enc_trans, _ = create_substitution_cipher(key)
    return plain_text.translate(enc_trans)


def substitution_decrypt(cipher_text, key):
    _, dec_trans = create_substitution_cipher(key)
    return cipher_text.translate(dec_trans)


# Utility functions for AES encryption
def aes_encrypt(plain_text, key):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(key.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + cipher_text).decode('utf-8')


def aes_decrypt(cipher_text, key):
    backend = default_backend()
    cipher_text = base64.b64decode(cipher_text)
    salt, iv, cipher_text = cipher_text[:16], cipher_text[16:32], cipher_text[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(key.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    return plain_text.decode('utf-8')


# Utility functions for RSA encryption
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # Increased key size for higher security
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(plain_text, public_key):
    cipher_text = public_key.encrypt(
        plain_text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(cipher_text).decode('utf-8')


def rsa_decrypt(cipher_text, private_key):
    cipher_text = base64.b64decode(cipher_text)
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text.decode('utf-8')


# Utility functions for ECC encryption
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())  # Increased curve size for higher security
    public_key = private_key.public_key()
    return private_key, public_key


def ecc_encrypt(plain_text, public_key):
    shared_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    shared_key_bytes = shared_key.exchange(ec.ECDH(), public_key)
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_key_bytes)
    aes_key = derived_key.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return base64.b64encode(iv + cipher_text).decode('utf-8'), shared_key.public_key()


def ecc_decrypt(cipher_text, private_key, public_key):
    shared_key_bytes = private_key.exchange(ec.ECDH(), public_key)
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_key_bytes)
    aes_key = derived_key.finalize()
    cipher_text = base64.b64decode(cipher_text)
    iv, cipher_text = cipher_text[:16], cipher_text[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(cipher_text) + decryptor.finalize()
    return plain_text.decode('utf-8')


# Custom CSS
st.markdown("""
    <style>
        body {
            background-color: #000000;
            color: #FFFFFF;
            font-family: Arial, sans-serif;
        }
        .css-1lcbmhc {
            color: #FFFFFF;
        }
        .css-1lcbmhc .stTextInput input, .css-1lcbmhc .stTextArea textarea {
            background-color: #333333;
            color: #FFFFFF;
            border: 1px solid #FFFFFF;
        }
        .css-1lcbmhc .stButton button {
            background-color: #444444;
            color: #FFFFFF;
            border: 1px solid #FFFFFF;
        }
        .css-1lcbmhc .stButton button:hover {
            background-color: #555555;
        }
        .css-1lcbmhc .stSelectbox div, .css-1lcbmhc .stSelectbox label {
            color: #FFFFFF;
        }
        .css-1lcbmhc .stSelectbox div[role="listbox"] {
            background-color: #333333;
        }
        .css-1lcbmhc .stSelectbox div[role="listbox"] div {
            border-bottom: 1px solid #444444;
        }
        .owner-info {
            position: fixed;
            bottom: 0;
            width: 100%;
            background-color: #222222;
            color: #FFFFFF;
            text-align: center;
            padding: 10px 0;
        }
        .result-section {
            margin-top: 20px;
        }
        .result-title {
            font-size: 18px;
            font-weight: bold;
        }
        .result-content {
            margin-top: 10px;
            font-size: 16px;
            white-space: pre-wrap;
        }
        .css-1lcbmhc h1 {
            color: #FFFFFF;
        }
    </style>
""", unsafe_allow_html=True)


def main():
    st.title("CipherVault")
    st.markdown(
        "Secure your text using various encryption methods. Choose a cipher method, enter your text, and provide a "
        "key to encrypt or decrypt your text.")

    st.sidebar.title("About the Developer")
    st.sidebar.info("""
        **Name:** Syed Adnan Ahmed  
        **Email:** aadjj41@example.com  
        **GitHub:** [github.com/aadjj](https://github.com/aadjj)

        **Note:** Ensure the security of your keys and do not share sensitive information.
    """)

    st.sidebar.title("About the Website")
    st.sidebar.info("""
        This website provides various encryption methods to secure your text. 
        You can choose from Caesar, Vigenère, Substitution, AES, RSA, and ECC ciphers. 
        Encrypt or decrypt your text easily using this intuitive interface.
    """)

    st.sidebar.title("Feedback")
    st.sidebar.write("We value your feedback! Please provide your comments and suggestions below:")
    feedback = st.sidebar.text_area("Feedback", height=150)
    if st.sidebar.button("Submit Feedback"):
        send_feedback(feedback)
        st.sidebar.success("Thank you for your feedback!")

    # Main application interface
    text_input = st.text_area("Enter Text (up to 3000 characters):", height=150)
    cipher_method = st.selectbox("Select Cipher Method:", ["Caesar", "Vigenère", "Substitution", "AES", "RSA", "ECC", ])
    key_input = st.text_input("Enter Key:")
    encrypt = st.button("Encrypt")
    decrypt = st.button("Decrypt")

    result_output = st.empty()

    if "private_key_rsa" not in st.session_state:
        st.session_state["private_key_rsa"] = None
    if "public_key_rsa" not in st.session_state:
        st.session_state["public_key_rsa"] = None
    if "private_key_ecc" not in st.session_state:
        st.session_state["private_key_ecc"] = None
    if "public_key_ecc" not in st.session_state:
        st.session_state["public_key_ecc"] = None

    private_key_rsa = st.session_state["private_key_rsa"]
    public_key_rsa = st.session_state["public_key_rsa"]
    private_key_ecc = st.session_state["private_key_ecc"]
    public_key_ecc = st.session_state["public_key_ecc"]

    if encrypt:
        try:
            if len(text_input) > 3000:
                st.error("Text exceeds 3000 characters!")
                return

            if cipher_method == "Caesar":
                key = int(key_input)
                result = caesar_encrypt(text_input, key)
            elif cipher_method == "Vigenère":
                result = vigenere_encrypt(text_input, key_input)
            elif cipher_method == "Substitution":
                result = substitution_encrypt(text_input, key_input)
            elif cipher_method == "AES":
                result = aes_encrypt(text_input, key_input)
            elif cipher_method == "RSA":
                if not public_key_rsa:
                    private_key_rsa, public_key_rsa = generate_rsa_keys()
                    st.session_state["private_key_rsa"] = private_key_rsa
                    st.session_state["public_key_rsa"] = public_key_rsa
                result = rsa_encrypt(text_input, public_key_rsa)
            elif cipher_method == "ECC":
                if not public_key_ecc:
                    private_key_ecc, public_key_ecc = generate_ecc_keys()
                    st.session_state["private_key_ecc"] = private_key_ecc
                    st.session_state["public_key_ecc"] = public_key_ecc
                result, public_key_ecc = ecc_encrypt(text_input, public_key_ecc)
                st.session_state["public_key_ecc"] = public_key_ecc

            result_output.markdown(f"""
                <div class="result-section">
                    <div class="result-title">Encryption Result:</div>
                    <div class="result-content">{result}</div>
                </div>
            """, unsafe_allow_html=True)
        except Exception as e:
            st.error(str(e))

    if decrypt:
        try:
            if len(text_input) > 3000:
                st.error("Text exceeds 3000 characters!")
                return

            if cipher_method == "Caesar":
                key = int(key_input)
                result = caesar_decrypt(text_input, key)
            elif cipher_method == "Vigenère":
                result = vigenere_decrypt(text_input, key_input)
            elif cipher_method == "Substitution":
                result = substitution_decrypt(text_input, key_input)
            elif cipher_method == "AES":
                result = aes_decrypt(text_input, key_input)
            elif cipher_method == "RSA":
                if not private_key_rsa:
                    st.error("No RSA private key available for decryption!")
                    return
                result = rsa_decrypt(text_input, private_key_rsa)
            elif cipher_method == "ECC":
                if not private_key_ecc:
                    st.error("No ECC private key available for decryption!")
                    return
                result = ecc_decrypt(text_input, private_key_ecc, public_key_ecc)

            result_output.markdown(f"""
                <div class="result-section">
                    <div class="result-title">Decryption Result:</div>
                    <div class="result-content">{result}</div>
                </div>
            """, unsafe_allow_html=True)
        except Exception as e:
            st.error(str(e))


def send_feedback(feedback):
    sender_email = "aadjj41@example.com"
    receiver_email = "aadjj4321@example.com"
    msg = MIMEText(feedback)
    msg["Subject"] = "Feedback from CipherVault"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP("smtp.example.com") as server:
            server.login("yourusername", "yourpassword")
            server.sendmail(sender_email, receiver_email, msg.as_string())
    except Exception as e:
        st.error(f"Failed to send feedback: {str(e)}")


if __name__ == "__main__":
    main()
