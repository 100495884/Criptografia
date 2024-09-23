import os
import hashlib
import hmac
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate, Certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509.oid import NameOID
import cryptography.x509 as x509
from datetime import datetime, timedelta


# =====================
# REGISTRO Y AUTENTICACIÓN DE USUARIOS
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
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


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


# =====================
# CIFRADO/DESCIFRADO SIMÉTRICO (AES-GCM)
# =====================
def cifrar_aes_gcm(mensaje, clave):
    nonce = os.urandom(12)  # Nonce de 12 bytes
    aesgcm = Cipher(algorithms.AES(clave), modes.GCM(nonce), backend=default_backend()).encryptor()
    cifrado = aesgcm.update(mensaje.encode()) + aesgcm.finalize()
    return (nonce, cifrado, aesgcm.tag)


def descifrar_aes_gcm(nonce, cifrado, tag, clave):
    aesgcm = Cipher(algorithms.AES(clave), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return aesgcm.update(cifrado) + aesgcm.finalize()


# =====================
# HMAC PARA AUTENTICACIÓN DE MENSAJES
# =====================
def generar_hmac(mensaje, clave):
    h = crypto_hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h.update(mensaje.encode())
    return h.finalize()


def verificar_hmac(mensaje, clave, etiqueta):
    h = crypto_hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h.update(mensaje.encode())
    try:
        h.verify(etiqueta)
        return True
    except:
        return False


# =====================
# FIRMA DIGITAL (RSA)
# =====================
def generar_claves_rsa():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def firmar_mensaje_rsa(mensaje, private_key):
    return private_key.sign(
        mensaje.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()  # Hash automático en vez de Prehashed
    )



def verificar_firma_rsa(mensaje, firma, public_key):
    try:
        public_key.verify(
            firma,
            mensaje.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except:
        return False


# =====================
# CERTIFICADOS Y PKI
# =====================
def crear_certificado(private_key, public_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Provincia"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Ciudad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Organización"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"nombrecomun.com"),
    ])
    certificado = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    return certificado


def guardar_certificado(certificado, filename):
    with open(filename, "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))


# =====================
# USO DEL SISTEMA
# =====================
if __name__ == "__main__":
    # Registro de usuario
    password = "password_seguro"
    salt = generar_salt()
    hashed_password = hash_password(password, salt)

    # Autenticación de usuario
    autenticado = verificar_password("password_seguro", salt, hashed_password)
    print("Autenticado:", autenticado)

    # Cifrado y Descifrado con AES-GCM
    clave_aes = os.urandom(32)
    nonce, cifrado, tag = cifrar_aes_gcm("Mensaje secreto", clave_aes)
    mensaje_descifrado = descifrar_aes_gcm(nonce, cifrado, tag, clave_aes)
    print("Mensaje descifrado:", mensaje_descifrado.decode())

    # HMAC
    clave_hmac = os.urandom(32)
    etiqueta = generar_hmac("Mensaje autenticado", clave_hmac)
    es_valido = verificar_hmac("Mensaje autenticado", clave_hmac, etiqueta)
    print("Etiqueta HMAC válida:", es_valido)

    # Firma y verificación RSA
    private_key, public_key = generar_claves_rsa()
    firma = firmar_mensaje_rsa("Mensaje firmado", private_key)
    es_firma_valida = verificar_firma_rsa("Mensaje firmado", firma, public_key)
    print("Firma válida:", es_firma_valida)

    # Creación de certificado
    certificado = crear_certificado(private_key, public_key)
    guardar_certificado(certificado, "certificado.pem")
    print("Certificado creado y guardado.")
