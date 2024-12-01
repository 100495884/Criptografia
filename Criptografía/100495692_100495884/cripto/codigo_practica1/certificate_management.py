from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import CertificateBuilder, NameOID, load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

# =====================
# Funciones de Certificados
# =====================

def generar_ca():
    """
    Genera un certificado autofirmado para la CA.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    builder = CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mi CA")]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mi CA")]))
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    ca_cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    cert_pem = ca_cert.public_bytes(Encoding.PEM)

    return private_key_pem, cert_pem


def emitir_certificado(user_public_key_pem, ca_private_key, ca_cert_pem):
    """
    Emite un certificado para un usuario firmado por la CA.
    """
    # Cargar la clave pública del usuario
    user_public_key = load_pem_public_key(user_public_key_pem)

    # Cargar el certificado de la CA
    ca_cert = load_pem_x509_certificate(ca_cert_pem)

    builder = CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Usuario")]))
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(user_public_key)

    user_cert = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    return user_cert.public_bytes(Encoding.PEM)


def validar_certificado(user_cert_pem, ca_cert_pem):
    """
    Valida un certificado de usuario contra el certificado de la CA.
    """
    user_cert = load_pem_x509_certificate(user_cert_pem)
    ca_cert = load_pem_x509_certificate(ca_cert_pem)

    try:
        ca_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Certificado inválido: {e}")
        return False
