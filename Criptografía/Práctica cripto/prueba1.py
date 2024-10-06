import os
import base64
import hashlib
import random
import json
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

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

def restaurar_contraseña(nombre_usuario, email):
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
    mensaje['To'] = email
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

    usuarios[nombre_usuario] = {
        'salt': base64.urlsafe_b64encode(salt).decode('utf-8'),
        'hashed_password': hashed_password.decode('utf-8'),
        'email': email,
        'telefono': telefono
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
        return True
    else:
        raise ValidationError("Error: Contraseña incorrecta.")




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

        self.boton_olvidar = ttk.Button(self.frame_contraseña, text="Olvidé mi contraseña", command=lambda: self.mostrar_pantalla_restaurar_contraseña(self.usuario_actual))
        self.boton_olvidar.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_contraseña, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

    def autenticar_usuario(self):
        nombre_usuario = self.usuario_actual
        password = self.entry_password_login.get()

        try:
            if autenticar_usuario(nombre_usuario, password):
                messagebox.showinfo("Éxito", f"Ingreso exitoso como {nombre_usuario}.")
                self.mostrar_opciones()
        except ValidationError as e:
            messagebox.showerror("Error", str(e))

        # Función para mostrar la pantalla de recuperación de contraseña

    def mostrar_pantalla_restaurar_contraseña(self, nombre_usuario):
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

        self.boton_volver = ttk.Button(self.frame_restaurar_contraseña, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

        # Función para enviar el correo de restauración

    def enviar_correo_restauracion(self, nombre_usuario):
        email = self.entry_email.get()
        usuarios = cargar_usuarios()

        # Comprobar si el usuario existe
        if nombre_usuario not in usuarios:
            messagebox.showerror("Error", "El usuario no está registrado.")
            return

        # Comprobar si el correo electrónico proporcionado coincide con el almacenado
        if email != usuarios[nombre_usuario]['email']:
            messagebox.showerror("Error", "El correo electrónico proporcionado no coincide con el registrado.")
            return

        try:
            if restaurar_contraseña(nombre_usuario, email):
                messagebox.showinfo("Éxito", "Correo de restauración enviado exitosamente.")
                self.volver_menu()
        except ValidationError as e:
            messagebox.showerror("Error", str(e))


    def mostrar_opciones(self):
        self.limpiar_login()
        self.frame_opciones = ttk.Frame(self.master)
        self.frame_opciones.pack(pady=20)

        self.label_opciones = ttk.Label(self.frame_opciones, text="Opciones:")
        self.label_opciones.pack()

        self.boton_cambiar_contraseña = ttk.Button(self.frame_opciones, text="Cambiar contraseña", command=self.mostrar_cambiar_contraseña)
        self.boton_cambiar_contraseña.pack(pady=5)

        self.boton_salir = ttk.Button(self.frame_opciones, text="Salir", command=self.master.quit)
        self.boton_salir.pack(pady=5)

    def mostrar_cambiar_contraseña(self):
        self.limpiar_login()

        self.frame_cambiar_contraseña = ttk.Frame(self.master)
        self.frame_cambiar_contraseña.pack(pady=20)

        self.label_actual = ttk.Label(self.frame_cambiar_contraseña, text="Contraseña actual:")
        self.label_actual.pack()
        self.entry_actual = ttk.Entry(self.frame_cambiar_contraseña, show='*')
        self.entry_actual.pack()

        self.boton_confirmar_cambio = ttk.Button(self.frame_cambiar_contraseña, text="Continuar", command=self.verificar_contraseña_actual)
        self.boton_confirmar_cambio.pack(pady=5)

        self.boton_volver_cambiar = ttk.Button(self.frame_cambiar_contraseña, text="Volver", command=self.mostrar_opciones)
        self.boton_volver_cambiar.pack(pady=5)

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
        self.limpiar_login()
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

        try:
            # Validar que las nuevas contraseñas coincidan
            if nueva_password != confirmar_password:
                messagebox.showerror("Error", "Las nuevas contraseñas no coinciden.")
                return

            # Validar la nueva contraseña usando la misma lógica de registro
            validar_contraseña(nueva_password)

            # Si la validación es exitosa, continuar con el cambio de contraseña
            salt = base64.urlsafe_b64decode(usuarios[nombre_usuario]['salt'])
            hashed_nueva_password = hash_password(nueva_password, salt)

            usuarios[nombre_usuario]['hashed_password'] = hashed_nueva_password.decode('utf-8')
            guardar_usuarios(usuarios)
            enviar_correo_aviso_cambio_contraseña(usuarios[nombre_usuario]['email'], nombre_usuario)
            messagebox.showinfo("Éxito", "Contraseña cambiada exitosamente.")
            self.mostrar_opciones()  # Volver al menú de opciones después de cambiar la contraseña
        except ValidationError as e:
            messagebox.showerror("Error", str(e))


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

    def mostrar_pantalla_restaurar_contraseña(self, nombre_usuario):
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

        self.boton_volver = ttk.Button(self.frame_restaurar_contraseña, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

    def enviar_correo_restauracion(self, nombre_usuario):
        email = self.entry_email.get()
        usuarios = cargar_usuarios()

        # Comprobar si el usuario existe
        if nombre_usuario not in usuarios:
            messagebox.showerror("Error", "El usuario no está registrado.")
            return

        # Comprobar si el correo electrónico proporcionado coincide con el almacenado
        if email != usuarios[nombre_usuario]['email']:
            messagebox.showerror("Error", "El correo electrónico proporcionado no coincide con el registrado.")
            return

        try:
            self.pin = restaurar_contraseña(nombre_usuario, email)
            self.mostrar_pantalla_introducir_pin(nombre_usuario)
        except ValidationError as e:
            messagebox.showerror("Error", str(e))

    def mostrar_pantalla_introducir_pin(self, nombre_usuario):
        self.limpiar_login()
        self.frame_introducir_pin = ttk.Frame(self.master)
        self.frame_introducir_pin.pack(pady=20)

        self.label_pin = ttk.Label(self.frame_introducir_pin, text="Ingresa el PIN enviado a tu correo:")
        self.label_pin.pack()
        self.entry_pin = ttk.Entry(self.frame_introducir_pin)
        self.entry_pin.pack()

        self.boton_verificar_pin = ttk.Button(self.frame_introducir_pin, text="Verificar PIN",
                                              command=lambda: self.verificar_pin(nombre_usuario))
        self.boton_verificar_pin.pack(pady=5)

        self.boton_volver = ttk.Button(self.frame_introducir_pin, text="Volver", command=self.volver_menu)
        self.boton_volver.pack(pady=5)

    def verificar_pin(self, nombre_usuario):
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

    def mostrar_nueva_contraseña(self):
        self.limpiar_login()
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

        self.boton_confirmar_nueva = ttk.Button(self.frame_nueva_contraseña, text="Cambiar contraseña",
                                                command=self.cambiar_contraseña)
        self.boton_confirmar_nueva.pack(pady=5)

        self.boton_volver_nueva = ttk.Button(self.frame_nueva_contraseña, text="Volver", command=self.volver_menu)
        self.boton_volver_nueva.pack(pady=5)

    def cambiar_contraseña(self):
        usuarios = cargar_usuarios()
        nombre_usuario = self.usuario_actual
        nueva_password = self.entry_nueva.get()
        confirmar_password = self.entry_confirmar.get()

        try:
            # Validar que las nuevas contraseñas coincidan
            if nueva_password != confirmar_password:
                messagebox.showerror("Error", "Las nuevas contraseñas no coinciden.")
                return

            # Validar la nueva contraseña usando la misma lógica de registro
            validar_contraseña(nueva_password)

            # Si la validación es exitosa, continuar con el cambio de contraseña
            salt = base64.urlsafe_b64decode(usuarios[nombre_usuario]['salt'])
            hashed_nueva_password = hash_password(nueva_password, salt)

            usuarios[nombre_usuario]['hashed_password'] = hashed_nueva_password.decode('utf-8')
            guardar_usuarios(usuarios)
            enviar_correo_aviso_cambio_contraseña(usuarios[nombre_usuario]['email'], nombre_usuario)
            messagebox.showinfo("Éxito", "Contraseña cambiada exitosamente.")
            self.mostrar_opciones()  # Volver al menú de opciones después de cambiar la contraseña
        except ValidationError as e:
            messagebox.showerror("Error", str(e))


# =====================
# EJECUCIÓN DE LA APLICACIÓN
# =====================
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()