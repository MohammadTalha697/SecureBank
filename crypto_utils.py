from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii

class AESCipher:
    @staticmethod
    def encrypt(plaintext, key):
        if isinstance(key, str):
            if len(key) == 32:
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = key.encode('utf-8')
                key_bytes = key_bytes.ljust(16, b'\0')[:16]
        else:
            key_bytes = key
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        return binascii.hexlify(ct).decode(), binascii.hexlify(cipher.iv).decode()

    @staticmethod
    def decrypt(ciphertext_hex, key, iv_hex):
        if isinstance(key, str):
            if len(key) == 32:
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = key.encode('utf-8')
                key_bytes = key_bytes.ljust(16, b'\0')[:16]
        else:
            key_bytes = key
        cipher = AES.new(key_bytes, AES.MODE_CBC, bytes.fromhex(iv_hex))
        return unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), AES.block_size).decode('utf-8')

    @staticmethod
    def generate_key():
        return binascii.hexlify(get_random_bytes(16)).decode()


class DESCipher:
    @staticmethod
    def encrypt(plaintext, key):
        if isinstance(key, str):
            key_bytes = key.encode('utf-8')
            key_bytes = key_bytes.ljust(8, b'\0')[:8]
        else:
            key_bytes = key
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = DES.new(key_bytes, DES.MODE_CBC)
        ct = cipher.encrypt(pad(plaintext, DES.block_size))
        return binascii.hexlify(ct).decode(), binascii.hexlify(cipher.iv).decode()

    @staticmethod
    def decrypt(ciphertext_hex, key, iv_hex):
        if isinstance(key, str):
            key_bytes = key.encode('utf-8')
            key_bytes = key_bytes.ljust(8, b'\0')[:8]
        else:
            key_bytes = key
        cipher = DES.new(key_bytes, DES.MODE_CBC, bytes.fromhex(iv_hex))
        return unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), DES.block_size).decode('utf-8')
