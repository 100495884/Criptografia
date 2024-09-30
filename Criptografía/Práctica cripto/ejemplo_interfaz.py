import os
import base64
import hashlib
import json
import smtplib
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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
class ValidationError(Exception):
    pass

def validar_nombre_usuario(nombre_usuario):
    """
    Verifica si el nombre de usuario cumple con los requisitos:
    - Solo contiene letras y números
    - No contiene caracteres especiales
    - No tiene una longitud superior a 15 caracteres
    """
    if re.search("[\W]", nombre_usuario):
        raise ValidationError("El nombre de usuario no debe contener caracteres especiales.")
    if len(nombre_usuario) > 15:
        raise ValidationError("El nombre de usuario no debe tener más de 15 caracteres.")
    if len(nombre_usuario) < 5:
        raise ValidationError("El nombre de usuario no debe tener menos de 5 caracteres.")
    return True

def validar_contraseña(password):
    """
    Verifica si la contraseña cumple con los requisitos para hacer una contraseña robusta:
    - Al menos 8 caracteres
    - Contiene letras, números y caracteres especiales
    """
    if len(password) < 8:
        raise ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if len(password) > 30:
        raise ValidationError("La contraseña no debe tener más de 30 caracteres.")
    if not re.search("^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[\W]).{8,30}$", password):
        raise ValidationError("La contraseña debe contener al menos una letra, un número y un carácter especial.")

    return True

def validar_contraseña_única(password, usuarios):
    """
    Verifica si la contraseña ya existe en el sistema.
    """
    for usuario in usuarios.values():
        salt = base64.urlsafe_b64decode(usuario['salt'])
        hashed_password = usuario['hashed_password']
        if hash_password(password, salt).decode('utf-8') == hashed_password:
            raise ValidationError("No puede haber 2 usuarios con la misma contraseña.")

def registrar_usuario(nombre_usuario, password):
    """
    Registra un nuevo usuario almacenando su nombre de usuario, su sal y la contraseña hasheada en un archivo JSON.
    """
    usuarios = cargar_usuarios()

    if nombre_usuario in usuarios:
        print(f"Error: El usuario '{nombre_usuario}' ya existe.")
        return False

    try:
        validar_nombre_usuario(nombre_usuario)
    except ValidationError as e:
        print(f"Error: {e}")
        return False

    while True:
        try:
            validar_contraseña(password)
            validar_contraseña_única(password, usuarios)
            break  # Si la contraseña es válida, salimos del bucle
        except ValidationError as e:
            print(f"Error: {e}")
            password = input("Introduce la contraseña: ")

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

def autenticar_usuario():
    """
    Autentica a un usuario verificando si su contraseña es correcta.
    """
    usuarios = cargar_usuarios()

    while True:
        print("1. Introducir nombre de usuario")
        print("2. Salir al menú principal")
        opcion = input("Seleccione una opción (1/2): ")

        if opcion == '1':
            nombre_usuario = input("Introduce el nombre de usuario: ")
            if nombre_usuario not in usuarios:
                print(f"Error: El usuario '{nombre_usuario}' no está registrado.")
                continue
        elif opcion == '2':
            return False
        else:
            print("Opción no válida, por favor selecciona 1 o 2.")
            continue

        intentos = 3
        while intentos > 0:
            print("1. Introducir contraseña")
            print("2. ¿Olvidó la contraseña?")
            print("3. Salir")
            opcion = input("Seleccione una opción (1/2/3): ")

            if opcion == '1':
                password = input("Introduce la contraseña: ")
                # Recuperamos la sal y la contraseña hasheada del usuario
                user_data = usuarios[nombre_usuario]
                salt = base64.urlsafe_b64decode(user_data['salt'])  # Convertimos la sal a bytes
                hashed_password = user_data['hashed_password']  # Contraseña hasheada

                # Verificamos si la contraseña es correcta
                if verificar_password(password, salt, hashed_password):
                    print(f"Usuario '{nombre_usuario}' autenticado correctamente.")
                    return True
                else:
                    intentos -= 1
                    print(f"Error: Contraseña incorrecta para el usuario '{nombre_usuario}'. Te quedan {intentos} intentos.")
            elif opcion == '2':
                return restaurar_contraseña(nombre_usuario)
            elif opcion == '3':
                break

        if intentos == 0:
            print("Se han gastado los intentos, intentelo más tarde.")
            return False

def validar_email(email):
    """
    Verifica si el correo electrónico cumple con el formato correcto.
    """
    restricciones = '^[a-z0-9]+[\._]?[a-z0-9]+[@]gmail[.]com$|^[a-z0-9]+[\._]?[a-z0-9]+[@]gmail[.]es$'
    if re.search(restricciones, email):
        return True
    else:
        return False
def restaurar_contraseña(nombre_usuario):
    intentos = 0
    while True:
        if intentos == 3:
            print("1. Introducir nuevo correo")
            print("2. Salir")
            opcion = input("Seleccione una opción (1/2): ")
            if opcion == '1':
                intentos = 0
                continue
            elif opcion == '2':
                return False
            else:
                print("Opción no válida, por favor selecciona 1 o 2.")
                continue

        email = input("Por favor, ingresa tu correo electrónico: ")
        if not validar_email(email):
            print("El correo electrónico debe tener una forma válida.")
            intentos += 1
            continue

        # Configuración del servidor de correo
        servidor_correo = "smtp.gmail.com"
        puerto = 587
        correo_envio = "100495692@alumnos.uc3m.es"
        contraseña_correo = "miep iewr zlmc ycfp"

        # Creación del mensaje
        mensaje = MIMEMultipart()
        mensaje['From'] = correo_envio
        mensaje['To'] = email
        mensaje['Subject'] = "Restauración de contraseña"
        cuerpo_mensaje = f"Hola {nombre_usuario},\n\nPara restablecer tu contraseña, por favor sigue este enlace: http://tu_sitio_web.com/restablecer_contraseña/{nombre_usuario}\n\nSi no has solicitado un restablecimiento de contraseña, por favor ignora este correo."
        mensaje.attach(MIMEText(cuerpo_mensaje, 'plain'))

        # Conexión al servidor de correo y envío del mensaje
        try:
            servidor = smtplib.SMTP(servidor_correo, puerto)
            servidor.starttls()
            servidor.login(correo_envio, contraseña_correo)
            servidor.send_message(mensaje)
            servidor.quit()
            print(f"Se ha enviado un correo electrónico a {email} con instrucciones para restablecer la contraseña.")
            return True
        except smtplib.SMTPRecipientsRefused:
            print("El correo electrónico que has introducido no existe. Por favor, introduce otro correo electrónico válido.")
            intentos += 1
        except smtplib.SMTPException as e:
            print(f"Error al enviar el correo electrónico: {e}")
            intentos += 1



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
            try:
                registrar_usuario(nombre_usuario, password)
            except ValidationError as e:
                print(f"Error: {e}")

        elif opcion == '2':
            # Autenticación de un usuario registrado
            autenticar_usuario()  # No necesitamos la contraseña aquí, ya que la función autenticar_usuario la manejará

        elif opcion == '3':
            # Salir del programa
            print("Saliendo del sistema...")
            break

        else:
            print("Opción no válida, por favor selecciona 1, 2 o 3.")

# =====================
# EJECUCIÓN DEL MENÚ
# =====================
import tkinter as tk
from tkinter import messagebox

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Autenticación")

        self.menú_frame = tk.Frame(self.root)
        self.menú_frame.pack(padx=10, pady=10)

        self.boton_registrar = tk.Button(self.menú_frame, text="Registrarse", command=self.mostrar_formulario_registro)
        self.boton_registrar.pack(fill='x')

        self.boton_iniciar_sesion = tk.Button(self.menú_frame, text="Iniciar sesión", command=self.mostrar_formulario_login)
        self.boton_iniciar_sesion.pack(fill='x')

        self.boton_salir = tk.Button(self.menú_frame, text="Salir", command=self.root.quit)
        self.boton_salir.pack(fill='x')

        self.formulario_frame = None

    def mostrar_formulario_registro(self):
        self.limpiar_pantalla()
        self.formulario_frame = tk.Frame(self.root)
        self.formulario_frame.pack(padx=10, pady=10)

        tk.Label(self.formulario_frame, text="Nombre de usuario").grid(row=0, column=0)
        self.entry_usuario = tk.Entry(self.formulario_frame)
        self.entry_usuario.grid(row=0, column=1)

        tk.Label(self.formulario_frame, text="Contraseña").grid(row=1, column=0)
        self.entry_password = tk.Entry(self.formulario_frame, show='*')
        self.entry_password.grid(row=1, column=1)

        self.boton_registrar = tk.Button(self.formulario_frame, text="Registrarse", command=self.registrar_usuario_gui)
        self.boton_registrar.grid(row=2, columnspan=2)

        self.boton_volver = tk.Button(self.formulario_frame, text="Volver", command=self.volver_al_menu)
        self.boton_volver.grid(row=3, columnspan=2)

    def mostrar_formulario_login(self):
        self.limpiar_pantalla()
        self.formulario_frame = tk.Frame(self.root)
        self.formulario_frame.pack(padx=10, pady=10)

        tk.Label(self.formulario_frame, text="Nombre de usuario").grid(row=0, column=0)
        self.entry_usuario = tk.Entry(self.formulario_frame)
        self.entry_usuario.grid(row=0, column=1)

        tk.Label(self.formulario_frame, text="Contraseña").grid(row=1, column=0)
        self.entry_password = tk.Entry(self.formulario_frame, show='*')
        self.entry_password.grid(row=1, column=1)

        self.boton_iniciar_sesion = tk.Button(self.formulario_frame, text="Iniciar sesión", command=self.iniciar_sesion_gui)
        self.boton_iniciar_sesion.grid(row=2, columnspan=2)

        self.boton_volver = tk.Button(self.formulario_frame, text="Volver", command=self.volver_al_menu)
        self.boton_volver.grid(row=3, columnspan=2)

    def limpiar_pantalla(self):
        if self.formulario_frame is not None:
            self.formulario_frame.pack_forget()

    def volver_al_menu(self):
        self.limpiar_pantalla()
        self.menú_frame.pack(padx=10, pady=10)

    def registrar_usuario_gui(self):
        nombre_usuario = self.entry_usuario.get()
        password = self.entry_password.get()
        resultado = registrar_usuario(nombre_usuario, password)
        messagebox.showinfo("Registro", resultado)

    def iniciar_sesion_gui(self):
        nombre_usuario = self.entry_usuario.get()
        password = self.entry_password.get()
        resultado = autenticar_usuario(nombre_usuario, password)
        messagebox.showinfo("Inicio de sesión", resultado)

# Crear la ventana principal y ejecutar la aplicación
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()