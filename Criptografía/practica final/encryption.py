import os
import base64
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes


# =====================
# FUNCIONES DE CIFRADO Y DESCIFRADO AES-GCM
# =====================

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')

def derivar_clave_cifrado(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Longitud de la clave AES de 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    clave = kdf.derive(password.encode())
    logging.debug(f"Clave derivada con KDF. Algoritmo: SHA256, Longitud de clave: {len(clave)*8} bits")
    return clave

def cifrar_aes_gcm(mensaje: str, clave: bytes, aad: bytes = None) -> dict:
    nonce = os.urandom(12)  # Genera un nonce de 12 bytes para AES-GCM
    cipher = Cipher(algorithms.AES(clave), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)

    cifrado = encryptor.update(mensaje.encode()) + encryptor.finalize()
    tag = encryptor.tag  # El tag de autenticación de GCM

    logging.debug(f"Cifrado AES realizado. Algoritmo: AES, Longitud de clave: {len(clave)*8} bits")
    logging.debug(f"Nonce utilizado: {base64.urlsafe_b64encode(nonce).decode('utf-8')}")
    logging.debug(f"Etiqueta de autenticación (tag): {base64.urlsafe_b64encode(tag).decode('utf-8')}")

    return {
        'nonce': nonce,
        'cifrado': cifrado,
        'tag': tag
    }

def descifrar_aes_gcm(cifrado: bytes, clave: bytes, nonce: bytes, tag: bytes, aad: bytes = None) -> str:
    cipher = Cipher(algorithms.AES(clave), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    if aad:
        decryptor.authenticate_additional_data(aad)

    mensaje_descifrado = decryptor.update(cifrado) + decryptor.finalize()
    logging.debug(f"Descifrado AES realizado. Algoritmo: AES, Longitud de clave: {len(clave)*8} bits")
    return mensaje_descifrado.decode()
