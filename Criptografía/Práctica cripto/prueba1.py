import os
import base64
import hashlib
import random
import json
import re
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

# Archivo donde se almacenarán los datos de los usuarios
ARCHIVO_USUARIOS = "usuarios.json"

# =====================
# FUNCIONES PARA HASHING Y VERIFICACIÓN DE CONTRASEÑAS
# =====================

#Funciones de Cifrado simétrico
def generar_clave_aes(longitud=32):
    """
    Genera una clave AES de la longitud especificada.
    Longitud por defecto: 32 bytes (256 bits).
    """
    return os.urandom(longitud)

def actualizar_usuarios_con_clave():
    usuarios = cargar_usuarios()
    for nombre_usuario, datos in usuarios.items():
        if 'clave' not in datos:
            clave = generar_clave_aes()
            datos['clave'] = base64.urlsafe_b64encode(clave).decode('utf-8')
    guardar_usuarios(usuarios)

# Configuración del log
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')

def cifrar_aes(mensaje: str, clave: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(mensaje.encode()) + padder.finalize()
    cifrado = encryptor.update(padded_data) + encryptor.finalize()

    # Registro de la operación
    logging.debug(f"Cifrado AES realizado. Algoritmo: AES, Longitud de clave: {len(clave)*8} bits")

    return iv + cifrado

def descifrar_aes(cifrado: bytes, clave: bytes) -> str:
    iv = cifrado[:16]
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(cifrado[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Registro de la operación
    logging.debug(f"Descifrado AES realizado. Algoritmo: AES, Longitud de clave: {len(clave)*8} bits")

    return data.decode()

#Funciones de Hashing
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
# FUNCIONES DE RESTAURACIÓN DE CONTRASEÑA
# =====================
def validar_email(email):
    """
    Verifica si el correo electrónico es válido y pertenece al dominio de Gmail (.com o .es).
    """
    patron = r'^[a-zA-Z0-9._%+-]+@gmail\.(com|es)$'
    if not bool(re.fullmatch(patron, email)):
        raise ValidationError("El correo electrónico debe tener una forma válida y pertenecer al dominio de Gmail (.com o .es).")
    return True

def validar_telefono(telefono):
    """
    Verifica si el número de teléfono es válido.
    """
    # Este patrón verifica si el número de teléfono tiene 9 dígitos y comienza con 6 o 7.
    patron = r'^[6-7]\d{8}$'
    if not bool(re.fullmatch(patron, telefono)):
        raise ValidationError("El número de teléfono debe tener 9 dígitos y comenzar con 6 o 7.")
    return True

def generar_pin():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def restaurar_contraseña(nombre_usuario, email_proporcionado):
    usuarios = cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError("Usuario no encontrado.")

    user_data = usuarios[nombre_usuario]
    clave = base64.urlsafe_b64decode(user_data['clave'])  # Decodificar la clave desde base64
    email_descifrado = descifrar_aes(base64.urlsafe_b64decode(user_data['email']), clave)  # Descifrar el email almacenado

    if email_descifrado != email_proporcionado:
        raise ValidationError("El correo electrónico no coincide con el registrado.")

    intentos = 0
    pin = generar_pin()

    # Configuración del servidor de correo
    servidor_correo = "smtp.gmail.com"
    puerto = 587
    correo_envio = "100495692@alumnos.uc3m.es"
    contraseña_correo = "miep iewr zlmc ycfp"

    # Creación del mensaje
    mensaje = MIMEMultipart()
    mensaje['From'] = correo_envio
    mensaje['To'] = email_descifrado
    mensaje['Subject'] = "Restauración de contraseña"
    cuerpo_mensaje = f"Hola {nombre_usuario},\n\nTu PIN de restauración de contraseña es: {pin}\n\nSi no has solicitado un restablecimiento de contraseña, por favor ignora este correo."
    mensaje.attach(MIMEText(cuerpo_mensaje, 'plain'))

    # Conexión al servidor de correo y envío del mensaje
    try:
        servidor = smtplib.SMTP(servidor_correo, puerto)
        servidor.starttls()
        servidor.login(correo_envio, contraseña_correo)
        servidor.send_message(mensaje)
        servidor.quit()
    except smtplib.SMTPException as e:
        raise ValidationError(f"Error al enviar el correo electrónico: {e}")

    return pin

def enviar_correo_aviso_cambio_contraseña(email, nombre_usuario):
    usuarios = cargar_usuarios()
    user_data = usuarios[nombre_usuario]
    clave = base64.urlsafe_b64decode(user_data['clave'])  # Decodificar la clave desde base64
    email = descifrar_aes(base64.urlsafe_b64decode(email), clave)  # Descifrar el email

    # Configuración del servidor de correo
    servidor_correo = "smtp.gmail.com"
    puerto = 587
    correo_envio = "100495692@alumnos.uc3m.es"
    contraseña_correo = "miep iewr zlmc ycfp"

    # Creación del mensaje
    mensaje = MIMEMultipart()
    mensaje['From'] = correo_envio
    mensaje['To'] = email
    mensaje['Subject'] = "Cambio de contraseña"
    cuerpo_mensaje = f"Hola {nombre_usuario},\n\nTu contraseña ha sido cambiada exitosamente. Si no has sido tú, por favor contacta con el personal de mantenimiento escribiendo a este mismo email."
    mensaje.attach(MIMEText(cuerpo_mensaje, 'plain'))

    # Conexión al servidor de correo y envío del mensaje
    try:
        servidor = smtplib.SMTP(servidor_correo, puerto)
        servidor.starttls()
        servidor.login(correo_envio, contraseña_correo)
        servidor.send_message(mensaje)
        servidor.quit()
    except smtplib.SMTPException as e:
        raise ValidationError(f"Error al enviar el correo electrónico: {e}")

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
    if re.search(r"[\W]", nombre_usuario):
        raise ValidationError("El nombre de usuario no debe contener caracteres especiales.")
    if len(nombre_usuario) > 15:
        raise ValidationError("El nombre de usuario no debe tener más de 15 caracteres.")
    if len(nombre_usuario) < 5:
        raise ValidationError("El nombre de usuario no debe tener menos de 5 caracteres.")
    return True

def validar_contraseña(password):
    if len(password) < 8:
        raise ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if len(password) > 30:
        raise ValidationError("La contraseña no debe tener más de 30 caracteres.")
    if not re.search(r"^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[\W]).{8,30}$", password):
        raise ValidationError("La contraseña debe contener al menos una letra, un número y un carácter especial.")
    return True

def registrar_usuario(nombre_usuario, password, email, telefono):
    usuarios = cargar_usuarios()

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
        validar_nombre_usuario(nombre_usuario)
        validar_contraseña(password)
        validar_email(email)
        validar_telefono(telefono)
    except ValidationError as e:
        raise e

    salt = generar_salt()
    hashed_password = hash_password(password, salt)
    clave = generar_clave_aes()

    email_cifrado = cifrar_aes(email, clave)
    telefono_cifrado = cifrar_aes(telefono, clave)

    usuarios[nombre_usuario] = {
        'salt': base64.urlsafe_b64encode(salt).decode('utf-8'),
        'hashed_password': hashed_password.decode('utf-8'),
        'email': base64.urlsafe_b64encode(email_cifrado).decode('utf-8'),
        'telefono': base64.urlsafe_b64encode(telefono_cifrado).decode('utf-8'),
        'clave': base64.urlsafe_b64encode(clave).decode('utf-8')
    }

    guardar_usuarios(usuarios)
    return True
def autenticar_usuario(nombre_usuario, password):
    usuarios = cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError(f"Error: El usuario '{nombre_usuario}' no está registrado.")

    user_data = usuarios[nombre_usuario]
    salt = base64.urlsafe_b64decode(user_data['salt'])
    hashed_password = user_data['hashed_password']

    if verificar_password(password, salt, hashed_password):
        return {
            'nombre_usuario': nombre_usuario,
            'clave': base64.urlsafe_b64decode(user_data['clave'])
        }
    else:
        raise ValidationError("Error: Contraseña incorrecta.")


def consultar_usuario(nombre_usuario):
    usuarios = cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError("Usuario no encontrado.")

    user_data = usuarios[nombre_usuario]
    clave = base64.urlsafe_b64decode(user_data['clave'])

    email_cifrado = base64.urlsafe_b64decode(user_data['email'])
    telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono'])

    email = descifrar_aes(email_cifrado, clave)
    telefono = descifrar_aes(telefono_cifrado, clave)

    return {
        'nombre_usuario': nombre_usuario,
        'email': email,
        'telefono': telefono
    }

def guardar_contraseña(nombre_usuario, asunto, contraseña):
    usuarios = cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError("Usuario no encontrado.")

    user_data = usuarios[nombre_usuario]
    clave = base64.urlsafe_b64decode(user_data['clave'])  # Decodificar la clave desde base64

    contraseña_cifrada = cifrar_aes(contraseña, clave)

    if 'contraseñas' not in usuarios[nombre_usuario]:
        usuarios[nombre_usuario]['contraseñas'] = []

    usuarios[nombre_usuario]['contraseñas'].append({
        'asunto': asunto,
        'contraseña': base64.urlsafe_b64encode(contraseña_cifrada).decode('utf-8')
    })
    guardar_usuarios(usuarios)

def obtener_contraseñas(nombre_usuario):
    usuarios = cargar_usuarios()
    if nombre_usuario not in usuarios or 'contraseñas' not in usuarios[nombre_usuario]:
        return []

    user_data = usuarios[nombre_usuario]
    clave = base64.urlsafe_b64decode(user_data['clave'])  # Decodificar la clave desde base64

    contraseñas_descifradas = []
    for item in usuarios[nombre_usuario]['contraseñas']:
        contraseña_cifrada = base64.urlsafe_b64decode(item['contraseña'])
        contraseña = descifrar_aes(contraseña_cifrada, clave)
        contraseñas_descifradas.append({
            'asunto': item['asunto'],
            'contraseña': contraseña
        })

    return contraseñas_descifradas

def eliminar_contraseña(nombre_usuario, asunto):
    usuarios = cargar_usuarios()
    if nombre_usuario not in usuarios or 'contraseñas' not in usuarios[nombre_usuario]:
        raise ValidationError("Usuario o contraseñas no encontrados.")

    contraseñas = usuarios[nombre_usuario]['contraseñas']
    usuarios[nombre_usuario]['contraseñas'] = [c for c in contraseñas if c['asunto'] != asunto]
    guardar_usuarios(usuarios)


# =====================
# INTERFAZ GRÁFICA
# =====================
class App:
    def __init__(self, master):
        self.master = master
        master.title("Sistema de Registro y Autenticación")
        master.geometry("400x300")

        # Cambiar el color de fondo de la ventana
        master.configure(bg="white")

        # Estilo para botones
        self.style = ttk.Style()
        self.style.configure("TButton", padding=8, relief="flat", background="white", foreground="Black",
                             font=("Helvetica", 12))

        # Estilo para botones activos
        self.style.map("TButton", background=[("active", "black")], foreground=[("active", "black")])


        # Estilo para etiquetas
        self.style.configure("TLabel", background="white", foreground="black", font=("Helvetica", 12))

        # Frame principal


        self.menu_frame = ttk.Frame(master)
        self.menu_frame.pack(pady=20)

        self.label = ttk.Label(self.menu_frame, text="Bienvenido al sistema")
        self.label.pack(pady=(0, 20))

        self.boton_registrar = ttk.Button(self.menu_frame, text="Registrarse", command=self.mostrar_registro)
        self.boton_registrar.pack(pady=5)

        self.boton_autenticar = ttk.Button(self.menu_frame, text="Iniciar sesión", command=self.mostrar_login_usuario)
        self.boton_autenticar.pack(pady=5)

        self.boton_salir = ttk.Button(self.menu_frame, text="Salir", command=master.quit)
        self.boton_salir.pack(pady=5)

        # Inicializamos variables para mantener el estado
        self.usuario_actual = None

        # Frames para las diferentes pantallas
        self.frame_registro = None
        self.frame_login = None
        self.frame_contraseña = None
        self.frame_opciones = None
        self.frame_cambiar_contraseña = None
        self.frame_nueva_contraseña = None
        self.frame_restaurar_contraseña = None
        self.frame_introducir_pin = None
        self.frame_introducir_pin = None

    def limpiar_frame(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def limpiar_login(self):
        if self.frame_registro is not None:
            self.frame_registro.pack_forget()
        if self.frame_login is not None:
            self.frame_login.pack_forget()
        if self.frame_contraseña is not None:
            self.frame_contraseña.pack_forget()
        if self.frame_opciones is not None:
            self.frame_opciones.pack_forget()
        if self.frame_cambiar_contraseña is not None:
            self.frame_cambiar_contraseña.pack_forget()
        if self.frame_nueva_contraseña is not None:
            self.frame_nueva_contraseña.pack_forget()
        if self.frame_restaurar_contraseña is not None:
            self.frame_restaurar_contraseña.pack_forget()


    def volver_menu(self):
        self.limpiar_frame()
        self.menu_frame = ttk.Frame(self.master)
        self.menu_frame.pack(pady=20)

        self.label = ttk.Label(self.menu_frame, text="Bienvenido al sistema")
        self.label.pack()

        self.boton_registrar = ttk.Button(self.menu_frame, text="Registrarse", command=self.mostrar_registro)
        self.boton_registrar.pack(pady=5)

        self.boton_autenticar = ttk.Button(self.menu_frame, text="Iniciar sesión",
                                           command=self.mostrar_login_usuario)
        self.boton_autenticar.pack(pady=5)

        self.boton_salir = ttk.Button(self.menu_frame, text="Salir", command=self.master.quit)
        self.boton_salir.pack(pady=5)


    def mostrar_registro(self):
        self.limpiar_frame()
        self.frame_registro = ttk.Frame(self.master)
        self.frame_registro.pack(pady=20)

        self.label_usuario = ttk.Label(self.frame_registro, text="Nombre de usuario:")
        self.label_usuario.pack()
        self.entry_usuario = ttk.Entry(self.frame_registro)
        self.entry_usuario.pack()

        self.label_password = ttk.Label(self.frame_registro, text="Contraseña:")
        self.label_password.pack()
        self.entry_password = ttk.Entry(self.frame_registro, show='*')
        self.entry_password.pack()

        self.label_email = ttk.Label(self.frame_registro, text="Correo electrónico:")
        self.label_email.pack()
        self.entry_email = ttk.Entry(self.frame_registro)
        self.entry_email.pack()

        self.label_telefono = ttk.Label(self.frame_registro, text="Número de teléfono:")
        self.label_telefono.pack()
        self.entry_telefono = ttk.Entry(self.frame_registro)
        self.entry_telefono.pack()

        self.boton_registrar = ttk.Button(self.frame_registro, text="Registrar", command=self.registrar_usuario)
        self.boton_registrar.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_registro, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

    def registrar_usuario(self):
        nombre_usuario = self.entry_usuario.get()
        password = self.entry_password.get()
        email = self.entry_email.get()
        telefono = self.entry_telefono.get()

        try:
            if registrar_usuario(nombre_usuario, password, email, telefono):
                messagebox.showinfo("Éxito", "Usuario registrado exitosamente.")
                self.volver_menu()
        except ValidationError as e:
            messagebox.showerror("Error", str(e))

    def mostrar_login_usuario(self):
        self.limpiar_frame()
        self.frame_login = ttk.Frame(self.master)
        self.frame_login.pack(pady=20)

        self.label_usuario = ttk.Label(self.frame_login, text="Nombre de usuario:")
        self.label_usuario.pack()
        self.entry_usuario_login = ttk.Entry(self.frame_login)
        self.entry_usuario_login.pack()

        self.boton_confirmar = ttk.Button(self.frame_login, text="Continuar", command=self.mostrar_contraseña)
        self.boton_confirmar.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_login, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

    def mostrar_contraseña(self):
        self.usuario_actual = self.entry_usuario_login.get()

        usuarios = cargar_usuarios()
        if self.usuario_actual not in usuarios:
            messagebox.showerror("Error", "El usuario no está registrado.")
            return

        self.limpiar_login()
        self.frame_contraseña = ttk.Frame(self.master)
        self.frame_contraseña.pack(pady=20)

        self.label_password = ttk.Label(self.frame_contraseña, text="Contraseña:")
        self.label_password.pack()
        self.entry_password_login = ttk.Entry(self.frame_contraseña, show='*')
        self.entry_password_login.pack()

        self.boton_autenticar = ttk.Button(self.frame_contraseña, text="Iniciar sesión", command=self.autenticar_usuario)
        self.boton_autenticar.pack(pady=5)

        self.boton_olvidar = ttk.Button(self.frame_contraseña, text="Olvidé mi contraseña", command=lambda: self.olvide_contraseña(self.usuario_actual))
        self.boton_olvidar.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_contraseña, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

    def autenticar_usuario(self):
        nombre_usuario = self.usuario_actual
        password = self.entry_password_login.get()

        try:
            if autenticar_usuario(nombre_usuario, password):
                self.usuario_actual = nombre_usuario
                messagebox.showinfo("Éxito", f"Ingreso exitoso como {nombre_usuario}.")
                self.mostrar_opciones()
        except ValidationError as e:
            messagebox.showerror("Error", str(e))

        # Función para mostrar la pantalla de recuperación de contraseña

    def olvide_contraseña(self, nombre_usuario):
        usuarios = cargar_usuarios()
        if nombre_usuario not in usuarios:
            messagebox.showerror("Error", "Usuario no encontrado.")
            return

        user_data = usuarios[nombre_usuario]
        clave = base64.urlsafe_b64decode(user_data['clave'])  # Decodificar la clave desde base64
        email_cifrado = base64.urlsafe_b64decode(user_data['email'])  # Decodificar el email cifrado desde base64
        email_descifrado = descifrar_aes(email_cifrado, clave)  # Descifrar el email almacenado

        # Guardar el email descifrado temporalmente
        self.email_descifrado = email_descifrado

        self.limpiar_login()
        self.frame_restaurar_contraseña = ttk.Frame(self.master)
        self.frame_restaurar_contraseña.pack(pady=20)

        self.label_email = ttk.Label(self.frame_restaurar_contraseña, text="Ingresa tu correo electrónico:")
        self.label_email.pack()
        self.entry_email = ttk.Entry(self.frame_restaurar_contraseña)
        self.entry_email.pack()

        self.boton_enviar = ttk.Button(self.frame_restaurar_contraseña, text="Enviar",
                                       command=lambda: self.enviar_correo_restauracion(nombre_usuario))
        self.boton_enviar.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_restaurar_contraseña, text="Volver", command=self.mostrar_contraseña)
        self.boton_volver.pack(pady=5)

    def enviar_correo_restauracion(self, nombre_usuario):
        email_proporcionado = self.entry_email.get()
        if email_proporcionado != self.email_descifrado:
            messagebox.showerror("Error", "El correo electrónico proporcionado no coincide con el registrado.")
            return

        try:
            self.pin = restaurar_contraseña(nombre_usuario, email_proporcionado)
            self.mostrar_pantalla_introducir_pin(nombre_usuario)
        except ValidationError as e:
            messagebox.showerror("Error", str(e))


    def mostrar_opciones(self):
        self.limpiar_frame()
        self.opciones_frame = ttk.Frame(self.master)
        self.opciones_frame.pack(pady=20)

        self.label = ttk.Label(self.opciones_frame, text=f"Bienvenido, {self.usuario_actual}")
        self.label.pack()

        self.boton_consultar_perfil = ttk.Button(self.opciones_frame, text="Consultar Perfil", command=self.consultar_perfil)
        self.boton_consultar_perfil.pack(pady=5)

        self.boton_cambiar_contraseña = ttk.Button(self.opciones_frame, text="Cambiar Contraseña", command=self.mostrar_cambiar_contraseña)
        self.boton_cambiar_contraseña.pack(pady=5)

        self.boton_administrar_contraseñas = ttk.Button(self.opciones_frame, text="Administrar Contraseñas", command=self.administrar_contraseñas)
        self.boton_administrar_contraseñas.pack(pady=5)

        self.boton_cerrar_sesion = ttk.Button(self.opciones_frame, text="Cerrar Sesión", command=self.master.quit)
        self.boton_cerrar_sesion.pack(pady=5)

    def consultar_perfil(self):
        usuarios = cargar_usuarios()
        nombre_usuario = self.usuario_actual


        if nombre_usuario not in usuarios:
            messagebox.showerror("Error", "Usuario no encontrado.")
            return

        user_data = usuarios[nombre_usuario]
        clave = base64.urlsafe_b64decode(user_data['clave'])  # Decodificar la clave desde base64
        email_cifrado = base64.urlsafe_b64decode(user_data['email'])
        telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono'])

        email = descifrar_aes(email_cifrado, clave)
        telefono = descifrar_aes(telefono_cifrado, clave)

        # Limpiar el frame actual
        self.limpiar_frame()
        self.frame_consultar_perfil = ttk.Frame(self.master)
        self.frame_consultar_perfil.pack(pady=20)

        # Mostrar la información del perfil
        ttk.Label(self.frame_consultar_perfil, text="Correo Electrónico:").pack(pady=5)
        ttk.Label(self.frame_consultar_perfil, text=email).pack(pady=5)

        ttk.Label(self.frame_consultar_perfil, text="Teléfono:").pack(pady=5)
        ttk.Label(self.frame_consultar_perfil, text=telefono).pack(pady=5)

        # Contar el número de claves almacenadas
        num_claves = len(usuarios)  # Cambiar por la función que cuente las claves almacenadas
        ttk.Label(self.frame_consultar_perfil, text="Número de Claves Almacenadas:").pack(pady=5)
        ttk.Label(self.frame_consultar_perfil, text=num_claves).pack(pady=5)

        # Botón para cerrar (volver al menú anterior)
        self.boton_cerrar = ttk.Button(self.frame_consultar_perfil, text="Cerrar",
                                       command=self.mostrar_opciones)  # Cambia esto por el método que desees para cerrar
        self.boton_cerrar.pack(pady=20)

    def mostrar_cambiar_contraseña(self):
        self.limpiar_frame()
        self.frame_cambiar_contraseña = ttk.Frame(self.master)
        self.frame_cambiar_contraseña.pack(pady=20)

        self.label_actual = ttk.Label(self.frame_cambiar_contraseña, text="Contraseña actual:")
        self.label_actual.pack()
        self.entry_actual = ttk.Entry(self.frame_cambiar_contraseña, show='*')
        self.entry_actual.pack()

        self.boton_confirmar = ttk.Button(self.frame_cambiar_contraseña, text="Continuar", command=self.verificar_contraseña_actual)
        self.boton_confirmar.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_cambiar_contraseña, text="Volver", command=self.mostrar_opciones)
        self.boton_volver.pack(pady=5)

    def verificar_contraseña_actual(self):
        usuarios = cargar_usuarios()
        nombre_usuario = self.usuario_actual
        password_actual = self.entry_actual.get()

        salt = base64.urlsafe_b64decode(usuarios[nombre_usuario]['salt'])
        hashed_password = usuarios[nombre_usuario]['hashed_password']

        if verificar_password(password_actual, salt, hashed_password):
            self.mostrar_nueva_contraseña()
        else:
            messagebox.showerror("Error", "La contraseña actual es incorrecta.")

    def mostrar_nueva_contraseña(self):
        self.limpiar_frame()
        self.frame_nueva_contraseña = ttk.Frame(self.master)
        self.frame_nueva_contraseña.pack(pady=20)

        self.label_nueva = ttk.Label(self.frame_nueva_contraseña, text="Nueva contraseña:")
        self.label_nueva.pack()
        self.entry_nueva = ttk.Entry(self.frame_nueva_contraseña, show='*')
        self.entry_nueva.pack()

        self.label_confirmar = ttk.Label(self.frame_nueva_contraseña, text="Confirmar nueva contraseña:")
        self.label_confirmar.pack()
        self.entry_confirmar = ttk.Entry(self.frame_nueva_contraseña, show='*')
        self.entry_confirmar.pack()

        self.boton_confirmar_nueva = ttk.Button(self.frame_nueva_contraseña, text="Cambiar contraseña", command=self.cambiar_contraseña)
        self.boton_confirmar_nueva.pack(pady=5)

        self.boton_volver_nueva = ttk.Button(self.frame_nueva_contraseña, text="Volver", command=self.mostrar_opciones)
        self.boton_volver_nueva.pack(pady=5)

    def cambiar_contraseña(self):
        usuarios = cargar_usuarios()
        nombre_usuario = self.usuario_actual
        nueva_password = self.entry_nueva.get()
        confirmar_password = self.entry_confirmar.get()

        if nueva_password != confirmar_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden.")
            return
        try:
            validar_contraseña(nueva_password)
        except ValidationError as e:
            messagebox.showerror("Error", str(e))
            return

        salt = generar_salt()
        hashed_password = hash_password(nueva_password, salt)
        usuarios[nombre_usuario]['hashed_password'] = hashed_password.decode('utf-8')
        usuarios[nombre_usuario]['salt'] = base64.urlsafe_b64encode(salt).decode('utf-8')

        guardar_usuarios(usuarios)

        messagebox.showinfo("Éxito", "Contraseña cambiada exitosamente.")
        self.mostrar_opciones()
        enviar_correo_aviso_cambio_contraseña(usuarios[nombre_usuario]['email'], nombre_usuario)

    def mostrar_pantalla_introducir_pin(self, nombre_usuario):
        self.limpiar_login()
        self.frame_introducir_pin = ttk.Frame(self.master)
        self.frame_introducir_pin.pack(pady=20)

        self.label_pin = ttk.Label(self.frame_introducir_pin, text="Ingresa el PIN enviado a tu correo:")
        self.label_pin.pack()
        self.entry_pin = ttk.Entry(self.frame_introducir_pin)
        self.entry_pin.pack()

        self.boton_verificar_pin = ttk.Button(self.frame_introducir_pin, text="Verificar PIN",
                                              command=lambda: self.verificar_pin())
        self.boton_verificar_pin.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_introducir_pin, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

    def verificar_pin(self):
        pin_introducido = self.entry_pin.get()
        intentos = 0

        if pin_introducido == self.pin:
            self.mostrar_nueva_contraseña()
        else:
            intentos += 1
            if intentos >= 3:
                messagebox.showerror("Error",
                                     "Se han acabado los intentos y se ha bloqueado la opción de restaurar por cuestiones de seguridad.")
                self.volver_menu()
            else:
                messagebox.showerror("Error", "PIN incorrecto. Inténtalo de nuevo.")

    def administrar_contraseñas(self):
        self.limpiar_frame()
        self.frame_administrar_contraseñas = ttk.Frame(self.master)
        self.frame_administrar_contraseñas.pack(pady=20)

        # Botón para añadir una nueva contraseña
        self.boton_añadir_contraseña = ttk.Button(self.frame_administrar_contraseñas, text="Añadir Nueva Contraseña",
                                                  command=self.añadir_nueva_contraseña)
        self.boton_añadir_contraseña.pack(pady=5)

        # Botón para gestionar contraseñas
        self.boton_gestionar_contraseñas = ttk.Button(self.frame_administrar_contraseñas, text="Gestionar Contraseñas",
                                                      command=self.gestionar_contraseñas)
        self.boton_gestionar_contraseñas.pack(pady=5)

        # Botón para eliminar contraseñas
        self.boton_eliminar_contraseña = ttk.Button(self.frame_administrar_contraseñas, text="Eliminar Contraseñas",
                                                    command=self.eliminar_contraseñas)
        self.boton_eliminar_contraseña.pack(pady=5)

        # Botón para salir o volver
        self.boton_volver = ttk.Button(self.frame_administrar_contraseñas, text="Volver", command=self.mostrar_opciones)
        self.boton_volver.pack(pady=5)

        # Pantalla para añadir una nueva contraseña

    def añadir_nueva_contraseña(self):
        self.limpiar_frame()
        self.frame_añadir_contraseña = ttk.Frame(self.master)
        self.frame_añadir_contraseña.pack(pady=20)

        self.label_asunto = ttk.Label(self.frame_añadir_contraseña, text="Asunto:")
        self.label_asunto.pack()
        self.entry_asunto = ttk.Entry(self.frame_añadir_contraseña)
        self.entry_asunto.pack()

        self.label_contraseña = ttk.Label(self.frame_añadir_contraseña, text="Contraseña:")
        self.label_contraseña.pack()
        self.entry_contraseña = ttk.Entry(self.frame_añadir_contraseña, show='*')
        self.entry_contraseña.pack()

        self.boton_guardar_contraseña = ttk.Button(self.frame_añadir_contraseña, text="Guardar Contraseña",
                                                   command=self.guardar_contraseña)
        self.boton_guardar_contraseña.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_añadir_contraseña, text="Volver",
                                       command=self.administrar_contraseñas)
        self.boton_volver.pack(pady=5)

        # Pantalla para gestionar contraseñas (ver todas)

    # Pantalla para gestionar contraseñas (ver todas)
    def gestionar_contraseñas(self):
        contraseñas = obtener_contraseñas(self.usuario_actual)  # Llamar a la función que obtiene contraseñas

        self.limpiar_frame()
        self.frame_gestionar_contraseñas = ttk.Frame(self.master)
        self.frame_gestionar_contraseñas.pack(pady=20)

        if contraseñas:
            self.contraseñas_visibles = {}  # Diccionario para almacenar el estado de visibilidad de cada contraseña

            for idx, contraseña in enumerate(contraseñas):
                # Mostrar el asunto
                ttk.Label(self.frame_gestionar_contraseñas, text=f"Asunto: {contraseña['asunto']}").pack()

                # Crear una variable que controla la visibilidad
                self.contraseñas_visibles[idx] = False

                # Frame para la contraseña y botón de mostrar/ocultar
                frame_contraseña = ttk.Frame(self.frame_gestionar_contraseñas)
                frame_contraseña.pack(pady=5)

                # Etiqueta para la contraseña, inicialmente oculta
                label_contraseña = ttk.Label(frame_contraseña, text="********")
                label_contraseña.pack(side="left")

                # Botón para mostrar/ocultar contraseña
                boton_mostrar = ttk.Button(frame_contraseña, text="Mostrar")
                boton_mostrar.pack(side="left")

                # Corregir la lambda para que las variables estén correctamente referenciadas
                boton_mostrar.config(
                    command=lambda i=idx, lbl=label_contraseña, btn=boton_mostrar, contra=contraseña['contraseña']:
                    self.mostrar_ocultar_contraseña(i, lbl, btn, contra))
        else:
            ttk.Label(self.frame_gestionar_contraseñas, text="No hay contraseñas guardadas.").pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_gestionar_contraseñas, text="Volver",
                                       command=self.administrar_contraseñas)
        self.boton_volver.pack(pady=5)

    # Función para mostrar/ocultar la contraseña
    def mostrar_ocultar_contraseña(self, idx, label_contraseña, boton_mostrar, contraseña):
        if self.contraseñas_visibles[idx]:
            # Si la contraseña está visible, ocultarla
            label_contraseña.config(text="********")
            boton_mostrar.config(text="Mostrar")
        else:
            # Si la contraseña está oculta, mostrarla
            label_contraseña.config(text=contraseña)
            boton_mostrar.config(text="Ocultar")

        # Cambiar el estado de visibilidad
        self.contraseñas_visibles[idx] = not self.contraseñas_visibles[idx]

    # Pantalla para eliminar contraseñas
    def eliminar_contraseñas(self):
        contraseñas = obtener_contraseñas(self.usuario_actual)  # Llamar a la función que obtiene contraseñas

        self.limpiar_frame()
        self.frame_eliminar_contraseñas = ttk.Frame(self.master)
        self.frame_eliminar_contraseñas.pack(pady=20)

        if contraseñas:
            for contraseña in contraseñas:
                frame_contraseña = ttk.Frame(self.frame_eliminar_contraseñas)
                frame_contraseña.pack(pady=5)

                ttk.Label(frame_contraseña, text=f"Asunto: {contraseña['asunto']}").pack(side="left")
                ttk.Button(frame_contraseña, text="Eliminar",
                           command=lambda a=contraseña['asunto']: self.eliminar_contraseña(a)).pack(side="left")
        else:
            ttk.Label(self.frame_eliminar_contraseñas, text="No hay contraseñas guardadas.").pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_eliminar_contraseñas, text="Volver",
                                       command=self.administrar_contraseñas)
        self.boton_volver.pack(pady=5)

        # Función para guardar contraseña

    def guardar_contraseña(self):
        asunto = self.entry_asunto.get()
        contraseña = self.entry_contraseña.get()

        if not asunto or not contraseña:
            messagebox.showerror("Error", "Debes proporcionar un asunto y una contraseña.")
            return

        try:
            guardar_contraseña(self.usuario_actual, asunto, contraseña)  # Llamar a la función para guardar
            messagebox.showinfo("Éxito", "Contraseña guardada exitosamente.")
            self.administrar_contraseñas()

        except Exception as e:
            messagebox.showerror("Error", str(e))

        # Función para eliminar contraseña

    def eliminar_contraseña(self, asunto):
        try:
            eliminar_contraseña(self.usuario_actual, asunto)  # Llamar a la función para eliminar
            messagebox.showinfo("Éxito", "Contraseña eliminada exitosamente.")
            self.eliminar_contraseñas()  # Actualizar la lista tras eliminar
        except Exception as e:
            messagebox.showerror("Error", str(e))

# =====================
# EJECUCIÓN DE LA APLICACIÓN
# =====================
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()