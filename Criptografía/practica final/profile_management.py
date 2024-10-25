import base64
import json_management
import encryption
from exceptions import ValidationError


# =====================
# FUNCIONES DE PERFIL DE USUARIO
# =====================

def consultar_usuario(nombre_usuario, clave):
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError("Usuario no encontrado.")

    user_data = usuarios[nombre_usuario]

    # Derivar la clave del email y descifrar el email con ella
    clave_email = encryption.derivar_clave_cifrado(nombre_usuario)
    email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
    email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
    email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])
    email = encryption.descifrar_aes_gcm(email_cifrado, clave_email, email_nonce, email_tag)

    # Descifrar el teléfono usando la clave de sesión
    telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono']['cifrado'])
    telefono_nonce = base64.urlsafe_b64decode(user_data['telefono']['nonce'])
    telefono_tag = base64.urlsafe_b64decode(user_data['telefono']['tag'])
    telefono = encryption.descifrar_aes_gcm(telefono_cifrado, clave, telefono_nonce, telefono_tag)

    return {
        'nombre_usuario': nombre_usuario,
        'email': email,
        'telefono': telefono
    }


def guardar_contraseña(nombre_usuario, asunto, contraseña, clave_sesion):
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError("Usuario no encontrado.")

    user_data = usuarios[nombre_usuario]

    # Cifrado de la contraseña usando la clave de sesión
    contraseña_cifrada = encryption.cifrar_aes_gcm(contraseña, clave_sesion)

    # Almacenamos la contraseña cifrada y sus metadatos (nonce y tag) en el JSON
    if 'contraseñas' not in user_data:
        user_data['contraseñas'] = []

    user_data['contraseñas'].append({
        'asunto': asunto,
        'contraseña': base64.urlsafe_b64encode(contraseña_cifrada['cifrado']).decode('utf-8'),
        'nonce': base64.urlsafe_b64encode(contraseña_cifrada['nonce']).decode('utf-8'),
        'tag': base64.urlsafe_b64encode(contraseña_cifrada['tag']).decode('utf-8')
    })

    json_management.guardar_usuarios(usuarios)


def obtener_contraseñas(nombre_usuario, clave):
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios or 'contraseñas' not in usuarios[nombre_usuario]:
        return []

    user_data = usuarios[nombre_usuario]
    contraseñas_descifradas = []

    # Iterar sobre cada contraseña cifrada y descifrar usando la clave derivada
    for item in user_data['contraseñas']:
        # Decodificar los elementos de la contraseña (contraseña, nonce, y tag)
        contraseña_cifrada = base64.urlsafe_b64decode(item['contraseña'])
        nonce = base64.urlsafe_b64decode(item['nonce'])
        tag = base64.urlsafe_b64decode(item['tag'])

        # Descifrar la contraseña usando la clave, nonce y tag
        contraseña = encryption.descifrar_aes_gcm(contraseña_cifrada, clave, nonce, tag)
        contraseñas_descifradas.append({
            'asunto': item['asunto'],
            'contraseña': contraseña
        })

    return contraseñas_descifradas



def eliminar_contraseña(nombre_usuario, asunto):
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios or 'contraseñas' not in usuarios[nombre_usuario]:
        raise ValidationError("Usuario o contraseñas no encontrados.")

    # Filtrar las contraseñas, excluyendo la que coincide con el asunto dado
    contraseñas = usuarios[nombre_usuario]['contraseñas']
    usuarios[nombre_usuario]['contraseñas'] = [c for c in contraseñas if c['asunto'] != asunto]

    # Guardar la lista actualizada en el JSON
    json_management.guardar_usuarios(usuarios)