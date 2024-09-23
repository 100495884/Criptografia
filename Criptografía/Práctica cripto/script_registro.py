import os
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Archivo donde se almacenarán los datos de los usuarios
ARCHIVO_USUARIOS = "usuarios.json"


# =====================
# FUNCIONES PARA HASHING Y VERIFICACIÓN DE CONTRASEÑAS
# =====================
def generar_salt():
    """
    Genera una sal aleatoria de 16 bytes.
    """
    return os.urandom(16)


def hash_password(password, salt):
    """
    Genera un hash seguro de la contraseña usando PBKDF2 con SHA-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_password = base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Convertimos a base64 para almacenarlo
    return hashed_password


def verificar_password(password, salt, hashed_password):
    """
    Verifica si la contraseña proporcionada coincide con la contraseña hasheada.
    """
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
# FUNCIONES PARA GESTIONAR EL ARCHIVO JSON
# =====================
def cargar_usuarios():
    """
    Carga los usuarios desde el archivo JSON. Si no existe, retorna un diccionario vacío.
    """
    if os.path.exists(ARCHIVO_USUARIOS):
        with open(ARCHIVO_USUARIOS, "r") as file:
            return json.load(file)
    return {}


def guardar_usuarios(usuarios):
    """
    Guarda el diccionario de usuarios en el archivo JSON.
    """
    with open(ARCHIVO_USUARIOS, "w") as file:
        json.dump(usuarios, file, indent=4)


# =====================
# FUNCIONES DE REGISTRO Y AUTENTICACIÓN
# =====================
def registrar_usuario(nombre_usuario, password):
    """
    Registra un nuevo usuario almacenando su nombre de usuario, su sal y la contraseña hasheada en un archivo JSON.
    """
    usuarios = cargar_usuarios()

    if nombre_usuario in usuarios:
        print(f"Error: El usuario '{nombre_usuario}' ya existe.")
        return False

    # Generamos una sal única para este usuario
    salt = generar_salt()

    # Hasheamos la contraseña con la sal
    hashed_password = hash_password(password, salt)

    # Guardamos el usuario en el diccionario de usuarios
    usuarios[nombre_usuario] = {
        'salt': base64.urlsafe_b64encode(salt).decode('utf-8'),  # Convertimos la sal a formato legible
        'hashed_password': hashed_password.decode('utf-8')  # Convertimos el hash a formato legible
    }

    # Guardamos los cambios en el archivo JSON
    guardar_usuarios(usuarios)
    print(f"Usuario '{nombre_usuario}' registrado con éxito.")
    return True


def autenticar_usuario(nombre_usuario, password):
    """
    Autentica a un usuario verificando si su contraseña es correcta.
    """
    usuarios = cargar_usuarios()

    # Comprobamos si el usuario está registrado
    if nombre_usuario not in usuarios:
        print(f"Error: El usuario '{nombre_usuario}' no está registrado.")
        return False

    # Recuperamos la sal y la contraseña hasheada del usuario
    user_data = usuarios[nombre_usuario]
    salt = base64.urlsafe_b64decode(user_data['salt'])  # Convertimos la sal a bytes
    hashed_password = user_data['hashed_password']  # Contraseña hasheada

    # Verificamos si la contraseña es correcta
    if verificar_password(password, salt, hashed_password):
        print(f"Usuario '{nombre_usuario}' autenticado correctamente.")
        return True
    else:
        print(f"Error: Contraseña incorrecta para el usuario '{nombre_usuario}'.")
        return False


# =====================
# MENÚ DINÁMICO PARA REGISTRO E INICIO DE SESIÓN
# =====================
def menu():
    """
    Menú interactivo para que el usuario elija entre registrarse o iniciar sesión.
    """
    while True:
        print("\n--- Menú ---")
        print("1. Registrarse")
        print("2. Iniciar sesión")
        print("3. Salir")

        opcion = input("Selecciona una opción (1/2/3): ")

        if opcion == '1':
            # Registro de un nuevo usuario
            nombre_usuario = input("Introduce el nombre de usuario: ")
            password = input("Introduce la contraseña: ")
            registrar_usuario(nombre_usuario, password)

        elif opcion == '2':
            # Autenticación de un usuario registrado
            nombre_usuario = input("Introduce el nombre de usuario: ")
            password = input("Introduce la contraseña: ")
            autenticar_usuario(nombre_usuario, password)

        elif opcion == '3':
            # Salir del programa
            print("Saliendo del sistema...")
            break

        else:
            print("Opción no válida, por favor selecciona 1, 2 o 3.")


# =====================
# EJECUCIÓN DEL MENÚ
# =====================
if __name__ == "__main__":
    menu()
