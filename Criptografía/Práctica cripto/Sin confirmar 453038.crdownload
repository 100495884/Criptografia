import os
import base64
import json
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import messagebox

# Archivo donde se almacenarán los datos de los usuarios
ARCHIVO_USUARIOS = "usuarios.json"

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

# =====================
# FUNCIONES PARA GESTIONAR EL ARCHIVO JSON
# =====================
def cargar_usuarios():
    if os.path.exists(ARCHIVO_USUARIOS):
        with open(ARCHIVO_USUARIOS, "r") as file:
            return json.load(file)
    return {}

def guardar_usuarios(usuarios):
    with open(ARCHIVO_USUARIOS, "w") as file:
        json.dump(usuarios, file, indent=4)

# =====================
# FUNCIONES DE REGISTRO Y AUTENTICACIÓN
# =====================
class ValidationError(Exception):
    pass

def validar_nombre_usuario(nombre_usuario):
    if re.search("[\W]", nombre_usuario):
        raise ValidationError("El nombre de usuario no debe contener caracteres especiales.")
    if len(nombre_usuario) > 15:
        raise ValidationError("El nombre de usuario no debe tener más de 15 caracteres.")
    return True

def validar_contraseña(password):
    if len(password) < 8:
        raise ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if not re.search("[a-zA-Z]", password):
        raise ValidationError("La contraseña debe contener al menos una letra.")
    if not re.search("[0-9]", password):
        raise ValidationError("La contraseña debe contener al menos un número.")
    if not re.search("[\W]", password):
        raise ValidationError("La contraseña debe contener al menos un carácter especial.")
    return True

def registrar_usuario(nombre_usuario, password):
    usuarios = cargar_usuarios()

    if nombre_usuario in usuarios:
        raise ValidationError(f"El usuario '{nombre_usuario}' ya existe.")

    try:
        validar_nombre_usuario(nombre_usuario)
        validar_contraseña(password)
    except ValidationError as e:
        return str(e)

    salt = generar_salt()
    hashed_password = hash_password(password, salt)

    usuarios[nombre_usuario] = {
        'salt': base64.urlsafe_b64encode(salt).decode('utf-8'),
        'hashed_password': hashed_password.decode('utf-8')
    }

    guardar_usuarios(usuarios)
    return f"Usuario '{nombre_usuario}' registrado con éxito."

def autenticar_usuario(nombre_usuario, password):
    usuarios = cargar_usuarios()

    if nombre_usuario not in usuarios:
        return f"Error: El usuario '{nombre_usuario}' no está registrado."

    user_data = usuarios[nombre_usuario]
    salt = base64.urlsafe_b64decode(user_data['salt'])
    hashed_password = user_data['hashed_password']

    if verificar_password(password, salt, hashed_password):
        return f"Usuario '{nombre_usuario}' autenticado correctamente."
    else:
        return f"Error: Contraseña incorrecta para el usuario '{nombre_usuario}'."

# =====================
# INTERFAZ GRÁFICA
# =====================
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
