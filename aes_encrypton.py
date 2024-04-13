from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
from flask import Flask, render_template, request, session, redirect, url_for

app = Flask(__name__)
# set secret key for encryption and decryption
app.config["SECRET_KEY"] = "hjhjsdahhds"

def pad_message(message):
    """
    :param message: og message
    :return: padded message
    """
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    return padded_data

def unpad_message(padded_message):
    """
    :param padded_message: padded message
    :return: unpadded message
    """
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_message) + unpadder.finalize()
    return data.decode()

def encrypt_message(key, message):
    """
    :param key: session key
    :param message: og message
    :return: encrypted message
    """
    iv = b'\x01' * 16  # same for decryption

    # create cipher obj using aes and cfb
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    # create encryptor
    encryptor = cipher.encryptor()
    # pad message
    padded_message = pad_message(message)
    # encrypt message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return b64encode(encrypted_message)

def decrypt_message(key, encrypted_message):
    """
    :param key: session key
    :param encrypted_message:
    :return: decrypted message
    """
    iv = b'\x01' * 16  # same as used for encryption
    # create cipher obj using aes and cfb
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    # create decryptor obj
    decryptor = cipher.decryptor()
    # decode and decrypt encrypted message
    decrypted_message = decryptor.update(b64decode(encrypted_message)) + decryptor.finalize()
    return unpad_message(decrypted_message)
