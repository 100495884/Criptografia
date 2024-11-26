from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def firmar_contenido(private_key_pem, password, contenido):
    if isinstance(contenido, str):
        contenido = contenido.encode('utf-8')

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=password,
        backend=default_backend()
    )
    firma = private_key.sign(
        contenido,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma

def verificar_firma(public_key_pem, contenido, firma):
    if isinstance(contenido, str):
        contenido = contenido.encode('utf-8')

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    try:
        public_key.verify(
            firma,
            contenido,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False