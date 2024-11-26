import base64
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

import password_hashing
import password_restoration
import encryption
import json_management
import data_validation
import register_login
import profile_management
from exceptions import ValidationError
import os
import logging


# =====================
# INTERFAZ GRÁFICA
# =====================

class App:
    def __init__(self, master):
        """
        Constructor de la clase App.
        Inicializa la ventana principal de la aplicación, configurando los estilos,
        creando botones y etiquetas iniciales, y configurando los diferentes frames.
        """
        self.master = master
        self.master.title("Sistema de Registro y Autenticación")
        self.master.geometry("700x600")
        self.master.configure(bg="white")

        # Configuración del estilo visual usando `ttk.Style`
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="white")
        self.style.configure(
            "TLabel",
            padding=10,
            relief="flat",
            background="white",
            foreground="black",
            font=("Helvetica", 12, "bold")
        )
        self.style.configure(
            "TButton",
            relief="flat",
            background="#1330ED",
            foreground="white",
            font=("Helvetica", 12, "bold"),
            width=20,
            padding=(0, 10),
        )
        self.style.map(
            "TButton",
            background=[("active", "#1029C9")],
            foreground=[("active", "white")]
        )

        # Configuración de botones secundarios
        self.style.configure(
            "Secondary.TButton",
            relief="flat",
            background="#1A237E",
            foreground="white",
            font=("Helvetica", 12, "bold"),
            width=20,
        )
        self.style.map(
            "Secondary.TButton",
            background=[("active", "#0D1B55")],
            foreground=[("active", "white")]
        )

        # Configuración de botones secundarios
        self.style.configure(
            "Delete.TButton",
            relief="flat",
            background="red",
            foreground="white",
            font=("Helvetica", 12, "bold"),
            width=15,
        )
        self.style.map(
            "Delete.TButton",
            background=[("active", "darkred")],
            foreground=[("active", "white")]
        )

        # Configuración de las entradas de texto
        self.style.configure(
            "TEntry",
            padding=(0, 5),
            foreground="Black",
        )
        self.master.option_add("*TEntry.Font", ("Helvetica", 12))
        self.master.option_add("*TEntry.Width", 20)
        self.master.option_add("*TEntry.Justify", "center")

        # Creación del frame del menú principal con opciones iniciales
        self.menu_frame = ttk.Frame(self.master)
        self.menu_frame.pack()

        self.label = ttk.Label(self.menu_frame, text="Bienvenido al sistema")
        self.label.pack()

        self.boton_registrar = ttk.Button(self.menu_frame, text="Registrarse", command=self.mostrar_registro)
        self.boton_registrar.pack(pady=15)

        self.boton_autenticar = ttk.Button(self.menu_frame, text="Iniciar sesión", command=self.mostrar_login_usuario)
        self.boton_autenticar.pack(pady=15)

        self.boton_salir = ttk.Button(self.menu_frame, text="Salir", command=master.quit, style="Secondary.TButton")
        self.boton_salir.pack(pady=15)

        # Inicialización de variables de sesión y frames
        self.usuario_actual = None
        self.clave_sesion = None
        self.private_key_pem = None
        self.public_key_pem = None
        self.frame_registro = None
        self.frame_login = None
        self.frame_contraseña = None
        self.frame_opciones = None
        self.frame_cambiar_contraseña = None
        self.frame_nueva_contraseña = None
        self.frame_restaurar_contraseña = None
        self.frame_añadir_contraseña = None
        self.frame_consultar_perfil = None
        self.frame_consultar_contraseñas = None
        self.frame_eliminar_contraseña = None
        self.frame_mostrar_contraseña = None
        self.frame_administrar_contraseña = None

    def limpiar_frame(self):
        """
        Limpia todos los elementos visibles en la ventana principal.
        Utilizado para cambiar entre diferentes pantallas (frames).
        """
        for widget in self.master.winfo_children():
            widget.destroy()

    def volver_menu(self):
        """
        Regresa al menú principal después de haber navegado a otra pantalla.
        """
        self.limpiar_frame()
        self.menu_frame = ttk.Frame(self.master)
        self.menu_frame.pack()

        self.label = ttk.Label(self.menu_frame, text="Bienvenido al sistema")
        self.label.pack()

        self.boton_registrar = ttk.Button(self.menu_frame, text="Registrarse", command=self.mostrar_registro)
        self.boton_registrar.pack(pady=15)

        self.boton_autenticar = ttk.Button(self.menu_frame, text="Iniciar sesión",
                                           command=self.mostrar_login_usuario)
        self.boton_autenticar.pack(pady=15)

        self.boton_salir = ttk.Button(self.menu_frame, text="Salir", command=self.master.quit, style="Secondary.TButton")
        self.boton_salir.pack(pady=15)

    def mostrar_registro(self):
        """
        Muestra la pantalla de registro de usuario.
        Contiene campos para ingresar nombre de usuario, contraseña, email y teléfono.
        """
        self.limpiar_frame()
        self.frame_registro = ttk.Frame(self.master)
        self.frame_registro.pack()

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
        self.boton_registrar.pack(pady=15)

        self.boton_volver = ttk.Button(self.frame_registro, text="Volver", command=self.volver_menu, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

    def registrar_usuario(self):
        """
        Registra a un nuevo usuario validando los datos ingresados.
        Si el registro es exitoso, regresa al menú principal.
        En caso de error muestra un mensaje informativo.
        """
        nombre_usuario = self.entry_usuario.get()
        password = self.entry_password.get()
        email = self.entry_email.get()
        telefono = self.entry_telefono.get()

        try:
            if register_login.registrar_usuario(nombre_usuario, password, email, telefono):
                messagebox.showinfo("Éxito", "Usuario registrado exitosamente.")
                self.volver_menu()
        except ValidationError as e:
            messagebox.showerror("Error", str(e))

    def mostrar_login_usuario(self):
        """
        Muestra la pantalla para iniciar sesión ingresando el nombre de usuario.
        """
        self.limpiar_frame()
        self.frame_login = ttk.Frame(self.master)
        self.frame_login.pack()

        self.label_usuario = ttk.Label(self.frame_login, text="Nombre de usuario:")
        self.label_usuario.pack()
        self.entry_usuario_login = ttk.Entry(self.frame_login)
        self.entry_usuario_login.pack()

        self.boton_confirmar = ttk.Button(self.frame_login, text="Continuar", command=self.mostrar_contraseña)
        self.boton_confirmar.pack(pady=15)

        self.boton_volver = ttk.Button(self.frame_login, text="Volver", command=self.volver_menu, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

    def mostrar_contraseña(self):
        """
        Muestra la pantalla para ingresar la contraseña del usuario después de ingresar el nombre.
        Si el usuario no está registrado, muestra un mensaje de error.
        """
        self.usuario_actual = self.entry_usuario_login.get()

        usuarios = json_management.cargar_usuarios()
        if self.usuario_actual not in usuarios:
            messagebox.showerror("Error", "El usuario no está registrado.")
            return

        self.limpiar_frame()
        self.frame_contraseña = ttk.Frame(self.master)
        self.frame_contraseña.pack()

        self.label_password = ttk.Label(self.frame_contraseña, text="Contraseña:")
        self.label_password.pack()
        self.entry_password_login = ttk.Entry(self.frame_contraseña, show='*')
        self.entry_password_login.pack()

        self.boton_autenticar = ttk.Button(self.frame_contraseña, text="Iniciar sesión", command=self.autenticar_usuario)
        self.boton_autenticar.pack(pady=15)

        self.boton_volver = ttk.Button(self.frame_contraseña, text="Volver", command=self.volver_menu, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

    def autenticar_usuario(self):
        """
        Autentica al usuario utilizando el nombre de usuario y contraseña proporcionados.
        Si la autenticación es exitosa, se deriva una clave de sesión para cifrar y descifrar datos.
        """
        usuarios = json_management.cargar_usuarios()
        nombre_usuario = self.usuario_actual
        password = self.entry_password_login.get()

        try:
            if register_login.autenticar_usuario(nombre_usuario, password):
                self.usuario_actual = nombre_usuario
                user_data = usuarios[nombre_usuario]
                salt_cifrado = base64.urlsafe_b64decode(user_data['salt_cifrado'])
                self.clave_sesion = encryption.derivar_clave_cifrado(password, salt_cifrado)

                self.private_key_pem = encryption.descifrar_clave_privada(user_data['clave_privada_cifrada'],
                                                                                 self.clave_sesion)
                self.public_key_pem = base64.urlsafe_b64decode(user_data['clave_publica'])


                messagebox.showinfo("Éxito", f"Ingreso exitoso como {nombre_usuario}.")
                self.mostrar_opciones()
        except ValidationError as e:
            messagebox.showerror("Error", str(e))

    def cifrar_dato(self, mensaje: str) -> dict:
        """
        Cifra un mensaje utilizando la clave de sesión activa.
        """
        return encryption.cifrar_aes_gcm(mensaje, self.clave_sesion)

    def descifrar_dato(self, cifrado: bytes, nonce: bytes, tag: bytes) -> str:
        """
        Descifra un mensaje cifrado utilizando la clave de sesión activa.
        """
        if self.clave_sesion is None:
            raise ValueError("Clave de sesión no está inicializada.")
        return encryption.descifrar_aes_gcm(cifrado, self.clave_sesion, nonce, tag)

    def mostrar_opciones(self):
        """
        Muestra las opciones disponibles para el usuario autenticado, incluyendo consultar perfil,
        cambiar contraseña, administrar contraseñas y cerrar sesión.
        """
        self.limpiar_frame()
        self.opciones_frame = ttk.Frame(self.master)
        self.opciones_frame.pack()

        self.label = ttk.Label(self.opciones_frame, text=f"Bienvenido, {self.usuario_actual}")
        self.label.pack()

        self.boton_consultar_perfil = ttk.Button(self.opciones_frame, text="Consultar Perfil", command=self.consultar_perfil)
        self.boton_consultar_perfil.pack(pady=15)

        self.boton_cambiar_contraseña = ttk.Button(self.opciones_frame, text="Cambiar Contraseña", command=self.mostrar_cambiar_contraseña)
        self.boton_cambiar_contraseña.pack(pady=15)

        self.boton_administrar_contraseñas = ttk.Button(self.opciones_frame, text="Administrar Contraseñas", command=self.administrar_contraseñas)
        self.boton_administrar_contraseñas.pack(pady=15)

        self.boton_cerrar_sesion = ttk.Button(self.opciones_frame, text="Cerrar Sesión", command=self.cerrar_sesion, style="Secondary.TButton")
        self.boton_cerrar_sesion.pack(pady=15)

    def cerrar_sesion(self):
        """
        Cierra la sesión del usuario actual y limpia la clave de sesión.
        """
        self.clave_sesion = None
        self.private_key_pem = None
        self.master.quit()

    def consultar_perfil(self):
        """
        Muestra el perfil del usuario autenticado.
        Descifra y muestra la información cifrada, incluyendo el email, el teléfono y el número de contraseñas almacenadas.
        """
        usuarios = json_management.cargar_usuarios()
        user_data = usuarios[self.usuario_actual]

        # Descifrado de email y teléfono
        email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
        email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
        email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])

        telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono']['cifrado'])
        telefono_nonce = base64.urlsafe_b64decode(user_data['telefono']['nonce'])
        telefono_tag = base64.urlsafe_b64decode(user_data['telefono']['tag'])

        email = self.descifrar_dato(email_cifrado, email_nonce, email_tag)
        telefono = self.descifrar_dato(telefono_cifrado, telefono_nonce, telefono_tag)

        # Creación del frame para mostrar la información del perfil
        self.limpiar_frame()
        self.frame_consultar_perfil = ttk.Frame(self.master)
        self.frame_consultar_perfil.pack(pady=10)

        # Mostrar información descifrada en etiquetas
        ttk.Label(self.frame_consultar_perfil, text=f"Correo Electrónico: {email}").pack(pady=5)
        ttk.Label(self.frame_consultar_perfil, text=f"Teléfono: {telefono}").pack(pady=5)

        # Mostrar el número de contraseñas almacenadas
        num_claves = len(user_data.get("contraseñas", []))
        ttk.Label(self.frame_consultar_perfil, text=f"Número de Claves Almacenadas: {num_claves}").pack(pady=5)

        # Botón para cerrar la visualización del perfil
        self.boton_cerrar = ttk.Button(self.frame_consultar_perfil, text="Cerrar", command=self.mostrar_opciones,
                                       style="Secondary.TButton")
        self.boton_cerrar.pack(pady=15)

    def mostrar_cambiar_contraseña(self):
        """
        Muestra la pantalla para cambiar la contraseña.
        Pide la contraseña actual antes de permitir el cambio.
        """
        self.limpiar_frame()
        self.frame_cambiar_contraseña = ttk.Frame(self.master)
        self.frame_cambiar_contraseña.pack()

        # Campos de entrada para la contraseña actual
        self.label_actual = ttk.Label(self.frame_cambiar_contraseña, text="Contraseña actual:")
        self.label_actual.pack()
        self.entry_actual = ttk.Entry(self.frame_cambiar_contraseña, show='*')
        self.entry_actual.pack()

        # Botón para confirmar la contraseña actual
        self.boton_confirmar = ttk.Button(self.frame_cambiar_contraseña, text="Continuar",
                                          command=self.verificar_contraseña_actual)
        self.boton_confirmar.pack(pady=15)

        # Botón para volver a la pantalla de opciones
        self.boton_volver = ttk.Button(self.frame_cambiar_contraseña, text="Volver", command=self.mostrar_opciones,
                                       style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

    def verificar_contraseña_actual(self):
        """
        Verifica que la contraseña actual ingresada sea correcta.
        Si es correcta, permite continuar con el cambio de contraseña.
        """
        usuarios = json_management.cargar_usuarios()
        nombre_usuario = self.usuario_actual
        password_actual = self.entry_actual.get()

        # Verificación de la contraseña actual con los datos almacenados
        salt_password = base64.urlsafe_b64decode(usuarios[nombre_usuario]['salt_password'])
        hashed_password = usuarios[nombre_usuario]['hashed_password']

        if password_hashing.verificar_password(password_actual, salt_password, hashed_password):
            self.mostrar_nueva_contraseña()
        else:
            messagebox.showerror("Error", "La contraseña actual es incorrecta.")

    def mostrar_nueva_contraseña(self):
        """
        Muestra la pantalla para ingresar una nueva contraseña y confirmarla.
        """
        self.limpiar_frame()
        self.frame_nueva_contraseña = ttk.Frame(self.master)
        self.frame_nueva_contraseña.pack()

        # Campos de entrada para la nueva contraseña
        self.label_nueva = ttk.Label(self.frame_nueva_contraseña, text="Nueva contraseña:")
        self.label_nueva.pack()
        self.entry_nueva = ttk.Entry(self.frame_nueva_contraseña, show='*')
        self.entry_nueva.pack()

        self.label_confirmar = ttk.Label(self.frame_nueva_contraseña, text="Confirmar nueva contraseña:")
        self.label_confirmar.pack()
        self.entry_confirmar = ttk.Entry(self.frame_nueva_contraseña, show='*')
        self.entry_confirmar.pack()

        # Botón para confirmar el cambio de contraseña
        self.boton_confirmar_nueva = ttk.Button(self.frame_nueva_contraseña, text="Cambiar contraseña",
                                                command=self.cambiar_contraseña)
        self.boton_confirmar_nueva.pack(pady=15)

        # Botón para volver a la pantalla de opciones
        self.boton_volver_nueva = ttk.Button(self.frame_nueva_contraseña, text="Volver", command=self.mostrar_opciones,
                                             style="Secondary.TButton")
        self.boton_volver_nueva.pack(pady=15)

    def cambiar_contraseña(self):
        """
        Cambia la contraseña del usuario después de validar la nueva contraseña.
        Realiza el recifrado de la información con la nueva clave derivada.
        """
        usuarios = json_management.cargar_usuarios()
        nombre_usuario = self.usuario_actual
        nueva_password = self.entry_nueva.get()
        confirmar_password = self.entry_confirmar.get()

        # Validación de que la nueva contraseña coincide con la confirmación
        if nueva_password != confirmar_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden.")
            return

        # Validación de la seguridad de la nueva contraseña
        try:
            data_validation.validar_contraseña(nueva_password)
        except ValidationError as e:
            messagebox.showerror("Error", str(e))
            return

        user_data = usuarios[nombre_usuario]

        # Descifrado de los datos actuales con la clave antigua
        clave_antigua = self.clave_sesion
        telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono']['cifrado'])
        telefono_nonce = base64.urlsafe_b64decode(user_data['telefono']['nonce'])
        telefono_tag = base64.urlsafe_b64decode(user_data['telefono']['tag'])
        telefono_descifrado = self.descifrar_dato(telefono_cifrado, telefono_nonce, telefono_tag)

        email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
        email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
        email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])
        email_descifrado = self.descifrar_dato(email_cifrado, email_nonce, email_tag)

        # Descifrar la clave privada
        clave_privada_cifrada = user_data['clave_privada_cifrada']
        clave_privada_pem = encryption.descifrar_clave_privada(clave_privada_cifrada, clave_antigua)

        contraseñas_descifradas = []
        for contraseña in user_data.get('contraseñas', []):
            contraseña_cifrada = base64.urlsafe_b64decode(contraseña['contraseña'])
            nonce = base64.urlsafe_b64decode(contraseña['nonce'])
            tag = base64.urlsafe_b64decode(contraseña['tag'])
            contrasena_descifrada = self.descifrar_dato(contraseña_cifrada, nonce, tag)
            contraseñas_descifradas.append((contraseña['asunto'], contrasena_descifrada))

        # Generar nueva clave y salts
        salt_password = password_hashing.generar_salt()
        salt_cifrado = password_hashing.generar_salt()
        hashed_password = password_hashing.hash_password(nueva_password, salt_password)
        nueva_clave = encryption.derivar_clave_cifrado(nueva_password, salt_cifrado)

        # Recifrar los datos con la nueva clave
        email_cifrado_nuevo = encryption.cifrar_aes_gcm(email_descifrado, nueva_clave)
        telefono_cifrado_nuevo = encryption.cifrar_aes_gcm(telefono_descifrado, nueva_clave)

        contraseñas_cifradas_nuevas = []
        for asunto, contrasena_descifrada in contraseñas_descifradas:
            contrasena_cifrada = encryption.cifrar_aes_gcm(contrasena_descifrada, nueva_clave)
            contraseñas_cifradas_nuevas.append({
                'asunto': asunto,
                'contraseña': base64.urlsafe_b64encode(contrasena_cifrada['cifrado']).decode('utf-8'),
                'nonce': base64.urlsafe_b64encode(contrasena_cifrada['nonce']).decode('utf-8'),
                'tag': base64.urlsafe_b64encode(contrasena_cifrada['tag']).decode('utf-8')
            })

        # Recifrar la clave privada con la nueva clave
        clave_privada_cifrada_nueva = encryption.cifrar_aes_gcm(clave_privada_pem, nueva_clave)

        # Guardar los nuevos datos del usuario
        usuarios[nombre_usuario]['hashed_password'] = hashed_password.decode('utf-8')
        usuarios[nombre_usuario]['salt_password'] = base64.urlsafe_b64encode(salt_password).decode('utf-8')
        usuarios[nombre_usuario]['salt_cifrado'] = base64.urlsafe_b64encode(salt_cifrado).decode('utf-8')
        usuarios[nombre_usuario]['email'] = {
            'cifrado': base64.urlsafe_b64encode(email_cifrado_nuevo['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(email_cifrado_nuevo['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(email_cifrado_nuevo['tag']).decode('utf-8')
        }
        usuarios[nombre_usuario]['telefono'] = {
            'cifrado': base64.urlsafe_b64encode(telefono_cifrado_nuevo['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(telefono_cifrado_nuevo['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(telefono_cifrado_nuevo['tag']).decode('utf-8')
        }
        usuarios[nombre_usuario]['contraseñas'] = contraseñas_cifradas_nuevas
        usuarios[nombre_usuario]['clave_privada_cifrada'] = {
            'cifrado': base64.urlsafe_b64encode(clave_privada_cifrada_nueva['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(clave_privada_cifrada_nueva['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(clave_privada_cifrada_nueva['tag']).decode('utf-8')
        }

        # Guardar los cambios en el archivo JSON
        json_management.guardar_usuarios(usuarios)

        # Actualizar la clave de sesión y mostrar mensaje de éxito
        self.clave_sesion = nueva_clave
        password_restoration.enviar_correo_aviso_cambio_contraseña(nombre_usuario, nueva_clave)
        messagebox.showinfo("Éxito", "Contraseña cambiada exitosamente.")
        self.mostrar_opciones()

    def administrar_contraseñas(self):
        """
        Muestra la pantalla para administrar las contraseñas almacenadas.
        Permite al usuario añadir, gestionar o eliminar contraseñas.
        """
        self.limpiar_frame()
        self.frame_administrar_contraseñas = ttk.Frame(self.master)
        self.frame_administrar_contraseñas.pack()

        # Botón para añadir una nueva contraseña
        self.boton_añadir_contraseña = ttk.Button(
            self.frame_administrar_contraseñas,
            text="Nueva Contraseña",
            command=self.añadir_nueva_contraseña
        )
        self.boton_añadir_contraseña.pack(pady=15)

        # Botón para gestionar las contraseñas existentes
        self.boton_gestionar_contraseñas = ttk.Button(
            self.frame_administrar_contraseñas,
            text="Gestionar Contraseñas",
            command=self.gestionar_contraseñas
        )
        self.boton_gestionar_contraseñas.pack(pady=15)

        # Botón para eliminar contraseñas
        self.boton_eliminar_contraseña = ttk.Button(
            self.frame_administrar_contraseñas,
            text="Eliminar Contraseñas",
            command=self.eliminar_contraseñas
        )
        self.boton_eliminar_contraseña.pack(pady=15)

        # Botón para volver a la pantalla de opciones
        self.boton_volver = ttk.Button(
            self.frame_administrar_contraseñas,
            text="Volver",
            command=self.mostrar_opciones,
            style="Secondary.TButton"
        )
        self.boton_volver.pack(pady=15)

    def añadir_nueva_contraseña(self):
        """
        Muestra la pantalla para añadir una nueva contraseña.
        Permite al usuario ingresar un asunto y la contraseña correspondiente.
        """
        self.limpiar_frame()
        self.frame_añadir_contraseña = ttk.Frame(self.master)
        self.frame_añadir_contraseña.pack()

        # Campo para ingresar el asunto de la nueva contraseña
        self.label_asunto = ttk.Label(self.frame_añadir_contraseña, text="Asunto:")
        self.label_asunto.pack()
        self.entry_asunto = ttk.Entry(self.frame_añadir_contraseña)
        self.entry_asunto.pack()

        # Campo para ingresar la nueva contraseña
        self.label_contraseña = ttk.Label(self.frame_añadir_contraseña, text="Contraseña:")
        self.label_contraseña.pack()
        self.entry_contraseña = ttk.Entry(self.frame_añadir_contraseña, show='*')
        self.entry_contraseña.pack()

        # Botón para guardar la nueva contraseña
        self.boton_guardar_contraseña = ttk.Button(
            self.frame_añadir_contraseña,
            text="Guardar Contraseña",
            command=self.guardar_contraseña
        )
        self.boton_guardar_contraseña.pack(pady=15)

        # Botón para volver a la pantalla de administración de contraseñas
        self.boton_volver = ttk.Button(
            self.frame_añadir_contraseña,
            text="Volver",
            command=self.administrar_contraseñas,
            style="Secondary.TButton"
        )
        self.boton_volver.pack(pady=15)

    def gestionar_contraseñas(self):
        """
        Muestra la pantalla para gestionar las contraseñas almacenadas.
        Permite mostrar u ocultar las contraseñas individuales.
        """
        contraseñas = profile_management.obtener_contraseñas(self.usuario_actual, self.clave_sesion, self.public_key_pem)

        self.limpiar_frame()
        self.frame_gestionar_contraseñas = ttk.Frame(self.master)
        self.frame_gestionar_contraseñas.pack()

        if contraseñas:
            self.contraseñas_visibles = {}

            # Muestra cada contraseña en la lista con la opción de mostrar/ocultar
            for idx, contraseña in enumerate(contraseñas):
                ttk.Label(self.frame_gestionar_contraseñas, text=f"Asunto: {contraseña['asunto']}").pack()

                self.contraseñas_visibles[idx] = False
                frame_contraseña = ttk.Frame(self.frame_gestionar_contraseñas)
                frame_contraseña.pack()

                label_contraseña = ttk.Label(frame_contraseña, text="********")
                label_contraseña.pack(side="left")

                boton_mostrar = ttk.Button(frame_contraseña, text="Mostrar")
                boton_mostrar.pack(side="left", padx=5)

                # Configura el botón para mostrar u ocultar la contraseña
                boton_mostrar.config(
                    command=lambda i=idx, lbl=label_contraseña, btn=boton_mostrar, contra=contraseña['contraseña']:
                    self.mostrar_ocultar_contraseña(i, lbl, btn, contra)
                )
        else:
            ttk.Label(self.frame_gestionar_contraseñas, text="No hay contraseñas guardadas.").pack()

        # Botón para volver a la pantalla de administración de contraseñas
        self.boton_volver = ttk.Button(
            self.frame_gestionar_contraseñas,
            text="Volver",
            command=self.administrar_contraseñas,
            style="Secondary.TButton"
        )
        self.boton_volver.pack(pady=15)

    def mostrar_ocultar_contraseña(self, idx, label_contraseña, boton_mostrar, contraseña):
        """
        Muestra u oculta una contraseña específica según su estado actual.
        Cambia el texto del botón y la visualización de la contraseña.

        :param idx: Índice de la contraseña en la lista
        :param label_contraseña: Etiqueta que muestra la contraseña
        :param boton_mostrar: Botón que controla la visibilidad de la contraseña
        :param contraseña: Texto de la contraseña
        """
        if self.contraseñas_visibles[idx]:
            label_contraseña.config(text="********")
            boton_mostrar.config(text="Mostrar")
        else:
            label_contraseña.config(text=contraseña)
            boton_mostrar.config(text="Ocultar")

        # Alterna el estado de visibilidad de la contraseña
        self.contraseñas_visibles[idx] = not self.contraseñas_visibles[idx]

    def eliminar_contraseñas(self):
        """
        Muestra la pantalla para eliminar contraseñas.
        Lista todas las contraseñas almacenadas con la opción de eliminarlas individualmente.
        """
        contraseñas = profile_management.obtener_contraseñas(self.usuario_actual, self.clave_sesion, self.public_key_pem)

        self.limpiar_frame()
        self.frame_eliminar_contraseñas = ttk.Frame(self.master)
        self.frame_eliminar_contraseñas.pack()

        if contraseñas:
            # Muestra cada contraseña con la opción de eliminarla
            for contraseña in contraseñas:
                frame_contraseña = ttk.Frame(self.frame_eliminar_contraseñas)
                frame_contraseña.pack()

                ttk.Label(frame_contraseña, text=f"Asunto: {contraseña['asunto']}").pack(side="left")
                ttk.Button(
                    frame_contraseña,
                    text="Eliminar",
                    command=lambda asunto=contraseña['asunto']: self.eliminar_contraseña(asunto),
                    style="Delete.TButton"
                ).pack(side="left", padx=5, pady=10)
        else:
            ttk.Label(self.frame_eliminar_contraseñas, text="No hay contraseñas guardadas.").pack()

        # Botón para volver a la pantalla de administración de contraseñas
        self.boton_volver = ttk.Button(
            self.frame_eliminar_contraseñas,
            text="Volver",
            command=self.administrar_contraseñas,
            style="Secondary.TButton"
        )
        self.boton_volver.pack(pady=15)

    def guardar_contraseña(self):
        """
        Guarda una nueva contraseña ingresada por el usuario.
        Valida la entrada y, si es correcta, la almacena en el sistema.
        """
        asunto = self.entry_asunto.get()
        contraseña = self.entry_contraseña.get()

        # Verifica que el asunto y la contraseña no estén vacíos
        if not asunto or not contraseña:
            messagebox.showerror("Error", "Debes proporcionar un asunto y una contraseña.")
            return

        try:
            # Guarda la contraseña en el sistema
            profile_management.guardar_contraseña(self.usuario_actual, asunto, contraseña, self.clave_sesion, self.private_key_pem)
            messagebox.showinfo("Éxito", "Contraseña guardada exitosamente.")
            self.administrar_contraseñas()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def eliminar_contraseña(self, asunto):
        """
        Elimina una contraseña específica basada en el asunto proporcionado.

        :param asunto: Asunto de la contraseña a eliminar
        """
        try:
            # Elimina la contraseña del sistema
            profile_management.eliminar_contraseña(self.usuario_actual, asunto)
            messagebox.showinfo("Éxito", "Contraseña eliminada exitosamente.")
            self.eliminar_contraseñas()
        except Exception as e:
            messagebox.showerror("Error", str(e))



# =====================
# EJECUCIÓN DE LA APLICACIÓN
# =====================
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()