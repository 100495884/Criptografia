import base64
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)


def generar_firma_digital(datos, private_key_pem):
    """
    Genera una firma digital para un conjunto de datos.
    :param datos: Datos a firmar (deben ser un diccionario serializable a JSON).
    :param private_key_pem: Clave privada en formato PEM para firmar.
    :return: La firma digital en formato base64.
    """
    # Serializa los datos en formato JSON ordenado
    datos_serializados = json.dumps(datos, sort_keys=True).encode()

    # Verificar y convertir la clave privada a bytes si es necesario
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode()  # Convierte de str a bytes

    # Cargar la clave privada
    private_key = load_pem_private_key(
        private_key_pem,
        password=None  # Si la clave está protegida, incluye la contraseña
    )

    # Generar la firma
    firma = private_key.sign(
        datos_serializados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Retornar la firma en formato base64
    print(firma)  # Debug: Verifica la firma generada
    return base64.urlsafe_b64encode(firma).decode('utf-8')


def verificar_firma_digital(datos, firma, public_key_pem):
    """
    Verifica una firma digital.

    :param datos: Datos firmados (deben ser un diccionario serializable a JSON).
    :param firma: Firma digital en formato base64.
    :param public_key_pem: Clave pública en formato PEM para verificar.
    :return: True si la firma es válida, False si no lo es.
    """
    # Serializa los datos en formato JSON ordenado
    datos_serializados = json.dumps(datos, sort_keys=True).encode()

    # Cargar la clave pública
    public_key = load_pem_public_key(public_key_pem)

    try:
        # Verificar la firma
        public_key.verify(
            base64.urlsafe_b64decode(firma),  # Decodificar la firma desde base64
            datos_serializados,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Error al verificar la firma: {e}")  # Debug
        return False
