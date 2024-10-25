import json_management
import password_hashing
import data_validation
import encryption
import base64
from exceptions import ValidationError


# =====================
# FUNCIONES DE REGISTRO Y AUTENTICACIÓN
# =====================

def registrar_usuario(nombre_usuario, password, email, telefono):
    usuarios = json_management.cargar_usuarios()

    # Comprobaciones para asegurarse de que todos los campos están completos
    if not nombre_usuario:
        raise ValidationError("Error: Debes proporcionar un nombre de usuario.")
    if not password:
        raise ValidationError("Error: Debes proporcionar una contraseña.")
    if not email:
        raise ValidationError("Error: Debes proporcionar un correo electrónico.")
    if not telefono:
        raise ValidationError("Error: Debes proporcionar un número de teléfono.")

    if nombre_usuario in usuarios:
        raise ValidationError(f"Error: El usuario '{nombre_usuario}' ya existe.")

    try:
        data_validation.validar_nombre_usuario(nombre_usuario)
        data_validation.validar_contraseña(password)
        data_validation.validar_email(email)
        data_validation.validar_telefono(telefono)
    except ValidationError as e:
        raise e

    salt_password = password_hashing.generar_salt()
    salt_cifrado = password_hashing.generar_salt()
    hashed_password = password_hashing.hash_password(password, salt_password)
    clave = encryption.derivar_clave_cifrado(password, salt_cifrado)

    email_cifrado = encryption.cifrar_aes_gcm(email, clave)
    telefono_cifrado = encryption.cifrar_aes_gcm(telefono, clave)

    usuarios[nombre_usuario] = {
        'salt_password': base64.urlsafe_b64encode(salt_password).decode('utf-8'),
        'salt_cifrado': base64.urlsafe_b64encode(salt_cifrado).decode('utf-8'),
        'hashed_password': hashed_password.decode('utf-8'),
        'email': {
            'cifrado': base64.urlsafe_b64encode(email_cifrado['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(email_cifrado['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(email_cifrado['tag']).decode('utf-8')
        },
        'telefono': {
            'cifrado': base64.urlsafe_b64encode(telefono_cifrado['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(telefono_cifrado['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(telefono_cifrado['tag']).decode('utf-8')
        }
    }
    json_management.guardar_usuarios(usuarios)
    return True


def autenticar_usuario(nombre_usuario, password):
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError(f"Error: El usuario '{nombre_usuario}' no está registrado.")

    user_data = usuarios[nombre_usuario]
    salt_password = base64.urlsafe_b64decode(user_data['salt_password'])
    salt_cifrado = base64.urlsafe_b64decode(user_data['salt_cifrado'])
    hashed_password = user_data['hashed_password']

    if password_hashing.verificar_password(password, salt_password, hashed_password):
        clave = encryption.derivar_clave_cifrado(password, salt_cifrado)
        return {
            'nombre_usuario': nombre_usuario,
            'clave': clave
        }
    else:
        raise ValidationError("Error: Contraseña incorrecta.")