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

# Загрузка настроек из файла
with open('settings.json') as json_file:
    json_data = json.load(json_file)

path_initial_file = json_data["initial_file"]
path_encrypted_file = json_data["encrypted_file"]
path_decrypted_file = json_data["decrypted_file"]
path_symmetric_key = json_data["symmetric_key"]
path_public_key = json_data["public_key"]
path_secret_key = json_data["secret_key"]


def key_generation(path_to_symmetric_key: str, path_to_public_key: str, path_to_secret_key: str) -> None:
    """
    :param path_to_symmetric_key: Путь к файлу, где лежит зашифрованный симметричный ключ
    :param path_to_public_key: Путь к файлу с публичным ключом
    :param path_to_secret_key: Путь к файлу с секретным ключом
    """
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
    """
    :param path_to_symmetric_key: Путь к файлу, где лежит зашифрованный симметричный ключ
    :param path_to_secret_key: Путь к файлу с секретным ключом
    """
    with open(path_to_symmetric_key, 'rb') as file:
        enc_symmetrical_key = file.read()
    with open(path_to_secret_key, 'rb') as file:
        privat_k = serialization.load_pem_private_key(file.read(), password=None)
    symmetrical_key = privat_k.decrypt(enc_symmetrical_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                         algorithm=hashes.SHA256(), label=None))
    return symmetrical_key


def encrypt_file(path_to_initial_file: str, path_to_secret_key: str, path_to_symmetric_key: str,
                 path_to_encrypt_file: str) -> None:
    """
    :param path_to_initial_file: Путь к файлу, в котором находится исходный текст
    :param path_to_secret_key: Путь к файлу с секретным ключом
    :param path_to_symmetric_key: Путь к файлу, где лежит зашифрованный симметричный ключ
    :param path_to_encrypt_file: Путь к файлу, куда будет сохранен зашифрованный текст
    """
    symmetrical_key = decrypt_symmetric_key(path_to_symmetric_key, path_to_secret_key)
    with open(path_to_initial_file, 'r', encoding='utf-8') as file:
        txt = file.read()
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(symmetrical_key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encrypt = cipher.encryptor()
    cipher_txt = encrypt.update(bytes(txt, 'utf-8'))
    res = {'ciphertxt': cipher_txt, 'nonce': nonce}
    with open(path_to_encrypt_file, 'wb') as file:
        pickle.dump(res, file)


def decrypt_file(path_to_encrypt_file: str, path_to_secret_key: str, path_to_symmetric_key: str,
                 path_to_decrypted_file: str) -> None:
    """
    :param path_to_encrypt_file: Путь к файлу, где находится зашифрованный текст
    :param path_to_secret_key: Путь к файлу с секретным ключом
    :param path_to_symmetric_key: Путь к файлу, где лежит зашифрованный симметричный ключ
    :param path_to_decrypted_file: Путь к файлу, куда будет сохранен расшифрованный текст
    """
    symmetrical_key = decrypt_symmetric_key(path_to_symmetric_key, path_to_secret_key)
    with open(path_to_encrypt_file, 'rb') as file:
        cipher_tmp = pickle.load(file)
    cipher_txt = cipher_tmp['ciphertxt']
    nonce = cipher_tmp['nonce']
    algorithm = algorithms.ChaCha20(symmetrical_key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decrypt = cipher.decryptor()
    dec_txt = decrypt.update(cipher_txt) + decrypt.finalize()
    with open(path_to_decrypted_file, 'w', encoding='utf-8') as file:
        file.write(dec_txt.decode('utf-8'))


parser = argparse.ArgumentParser(description='main.py')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', type=str, help='Запускает режим генерации ключей', dest='generation')
group.add_argument('-enc', '--encryption', type=str, help='Запускает режим шифрования', dest='encryption')
group.add_argument('-dec', '--decryption', type=str, help='Запускает режим дешифрования', dest='decryption')
args = parser.parse_args()

if args.generation is not None:
    key_generation(path_symmetric_key, path_public_key, path_secret_key)
    print('Ключи созданы')
if args.encryption is not None:
    encrypt_file(path_initial_file, path_secret_key, path_symmetric_key, path_encrypted_file)
    print('Файл зашифрован')
if args.decryption is not None:
    decrypt_file(path_encrypted_file, path_secret_key, path_symmetric_key, path_decrypted_file)
    print('Файл расшифрован')
