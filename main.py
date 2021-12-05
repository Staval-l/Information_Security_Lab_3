import json
import argparse
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import os
import pickle

with open('settings.json') as json_file:
    json_data = json.load(json_file)

path_initial_file = json_data["initial_file"]
path_encrypted_file = json_data["encrypted_file"]
path_decrypted_file = json_data["decrypted_file"]
path_symmetric_key = json_data["symmetric_key"]
path_public_key = json_data["public_key"]
path_secret_key = json_data["secret_key"]


def key_generation(path_to_symmetric_key: str, path_to_public_key: str, path_to_secret_key: str) -> None:
    symmetric_key = ChaCha20Poly1305.generate_key()

    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privat_k = keys

    privat_pem = privat_k.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption())
    with open(path_to_secret_key, 'wb') as file:
        file.write(privat_pem)

    public_k = keys.public_key()
    public_pem = public_k.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(path_to_public_key, 'wb') as file:
        file.write(public_pem)

    enc_symmetrical_key = public_k.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                       algorithm=hashes.SHA256(), label=None))
    with open(path_to_symmetric_key, 'wb') as file:
        file.write(enc_symmetrical_key)


def decrypt_symmetric_key(path_to_symmetric_key: str, path_to_secret_key: str):
    with open(path_to_symmetric_key, 'rb') as file:
        enc_symmetrical_key = file.read()
    with open(path_to_secret_key, 'rb') as file:
        privat_k = serialization.load_pem_private_key(file.read(), password=None)
    symmetrical_key = privat_k.decrypt(enc_symmetrical_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                         algorithm=hashes.SHA256(), label=None))
    return symmetrical_key


def encrypt_file(path_to_initial_file: str, path_to_secret_key: str, path_to_symmetric_key: str,
                 path_to_encrypt_file: str) -> None:
    return True


def decrypt_file(path_to_encrypt_file: str, path_to_secret_key: str, path_to_symmetric_key: str,
                 path_to_decrypted_file: str) -> None:
    return True


parser = argparse.ArgumentParser(description='main.py')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
args = parser.parse_args()
