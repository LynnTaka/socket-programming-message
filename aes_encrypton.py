import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

def pad_message(message):
    """
    pads message to required length using pkcs7 padding
    :param message: og message
    :return: padded message that is ready to be encrypted
    """
    padded = padding.PKCS7(128).padder()
    padded_data = padded.update(message.encode()) + padded.finalize()
    return padded_data

def unpad_message(padded_message):
    """
    removes pkcs7 padding from padded message
    unpads message
    :param padded_message: padded message
    :return: unpadded message
    """
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_message) + unpadder.finalize()
    return data.decode()

def encrypt_message(key, message):
    """
    encrypts message using aes-256
    :param key: room
    :param message: og message
    :return: encrypted message
    """
    # initialization vector
    iv = generate_iv(key)
    # aes key
    key = generate_aes_key(key)

    print('encrypt')
    print(iv)
    print(key)
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
    decrypts the message using aes-256 algorithm in CFB mode
    :param key: session key
    :param encrypted_message:
    :return: decrypted message
    """
    # initialization vector
    iv = generate_iv(key)
    # aes key
    key = generate_aes_key(key)

    # print('decrypt')
    # print(iv)
    # print(key)

    # create cipher obj using aes and cfb
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    # create decryptor obj
    decryptor = cipher.decryptor()
    # decode and decrypt encrypted message
    decrypted_message = decryptor.update(b64decode(encrypted_message)) + decryptor.finalize()
    return unpad_message(decrypted_message)


def generate_aes_key(letters):
    """
    generate a 256 aes key based on the room code
    :param letters: 4 letters
    :return: aes-256 key
    """
    # convert letters to bytes
    bytes_sequence = bytes(letters, 'utf-8')

    # expand bytes to reach right length (256)
    # the hash is the same, as the letters will be the same
    while len(bytes_sequence) < 32:
        bytes_sequence += hashlib.sha256(bytes_sequence).digest()

    # trim to the required key length
    # print(bytes_sequence)
    aes_key = bytes_sequence[:32]

    return aes_key

def generate_iv(letters):
    """
    generates or regenerates iv based on room code
    :param letters: room code
    :return:initiailization vector of 16 bytes
    """
    # convert letters to bytes
    bytes_sequence = bytes(letters, 'utf-8')

    # required IV length
    while len(bytes_sequence) < 16:
        bytes_sequence += hashlib.sha256(bytes_sequence).digest()

    # trim
    iv = bytes_sequence[:16]

    return iv
