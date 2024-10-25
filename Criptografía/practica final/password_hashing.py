import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# =====================
# FUNCIONES PARA HASHING Y VERIFICACIÓN DE CONTRASEÑAS
# =====================

def generar_salt():
    return os.urandom(16)

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_password = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return hashed_password

def verificar_password(password, salt, hashed_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), base64.urlsafe_b64decode(hashed_password))
        return True
    except:
        return False
