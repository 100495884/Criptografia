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


# =====================
# INTERFAZ GRÁFICA
# =====================
class App:
    def __init__(self, master):
        self.master = master
        self.master.title("Sistema de Registro y Autenticación")
        self.master.geometry("700x600")
        self.master.configure(bg="white")  # Fondo completamente blanco

        # Configuración global de fondo blanco para todos los Frames
        self.master.option_add("*Frame.Background", "white")

        # Estilos personalizados
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Configuración de estilo para Frames
        self.style.configure("TFrame", background="white")

        # Configuración de estilo para etiquetas
        self.style.configure(
            "TLabel",
            padding=10,
            relief="flat",
            background="white",
            foreground="black",
            font=("Helvetica", 12, "bold")
        )


        # Configuración de estilo para botones primarios con tamaño fijo
        self.style.configure(
            "TButton",
            relief="flat",
            background="#1330ED",  # Azul navy claro
            foreground="white",
            font=("Helvetica", 12, "bold"),
            width=20,
            padding=(0, 10),
        )
        self.style.map(
            "TButton",
            background=[("active", "#1029C9")],  # Azul más oscuro al hacer hover
            foreground=[("active", "white")]
        )

        # Configuración de estilo para botones secundarios con tamaño fijo
        self.style.configure(
            "Secondary.TButton",
            relief="flat",
            background="#1A237E",  # Azul navy oscuro
            foreground="white",
            font=("Helvetica", 12, "bold"),
            width=20,
        )
        self.style.map(
            "Secondary.TButton",
            background=[("active", "#0D1B55")],  # Azul navy más oscuro al hacer hover
            foreground=[("active", "white")]
        )

        # Configuración de estilo para entradas de texto
        self.style.configure(
            "TEntry",
            padding=(0, 5),
            foreground="Black",
        )
        self.master.option_add("*TEntry.Font", ("Helvetica", 12))
        self.master.option_add("*TEntry.Width", 20)
        self.master.option_add("*TEntry.Justify", "center")



        # Frame principal
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

        # Inicializamos variables para mantener el estado
        self.usuario_actual = None
        self.clave_sesion = None

        # Frames para las diferentes pantallas
        self.frame_registro = None
        self.frame_login = None
        self.frame_contraseña = None
        self.frame_opciones = None
        self.frame_cambiar_contraseña = None
        self.frame_nueva_contraseña = None
        self.frame_restaurar_contraseña = None
        self.frame_introducir_pin = None
        self.frame_añadir_contraseña = None
        self.frame_consultar_perfil = None
        self.frame_consultar_contraseñas = None
        self.frame_eliminar_contraseña = None
        self.frame_mostrar_contraseña = None
        self.frame_administrar_contraseña = None


    def limpiar_frame(self):
        for widget in self.master.winfo_children():
            widget.destroy()


    def volver_menu(self):
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
        usuarios = json_management.cargar_usuarios()
        nombre_usuario = self.usuario_actual
        password = self.entry_password_login.get()

        try:
            if register_login.autenticar_usuario(nombre_usuario, password):
                self.usuario_actual = nombre_usuario
                user_data = usuarios[nombre_usuario]
                salt_cifrado = base64.urlsafe_b64decode(user_data['salt_cifrado'])
                self.clave_sesion = encryption.derivar_clave_cifrado(password, salt_cifrado)
                messagebox.showinfo("Éxito", f"Ingreso exitoso como {nombre_usuario}.")
                self.mostrar_opciones()
        except ValidationError as e:
            messagebox.showerror("Error", str(e))

        # Función para mostrar la pantalla de recuperación de contraseña

    # Modificación en los métodos de cifrado y descifrado para usar `self.clave_sesion`

    def cifrar_dato(self, mensaje: str) -> dict:
        return encryption.cifrar_aes_gcm(mensaje, self.clave_sesion)

    def descifrar_dato(self, cifrado: bytes, nonce: bytes, tag: bytes) -> str:
        if self.clave_sesion is None:
            raise ValueError("Clave de sesión no está inicializada.")
        return encryption.descifrar_aes_gcm(cifrado, self.clave_sesion, nonce, tag)

    def mostrar_opciones(self):
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
        self.clave_sesion = None
        self.master.quit()

    def consultar_perfil(self):
        usuarios = json_management.cargar_usuarios()
        user_data = usuarios[self.usuario_actual]

        email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
        email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
        email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])

        telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono']['cifrado'])
        telefono_nonce = base64.urlsafe_b64decode(user_data['telefono']['nonce'])
        telefono_tag = base64.urlsafe_b64decode(user_data['telefono']['tag'])

        email = self.descifrar_dato(email_cifrado, email_nonce, email_tag)
        telefono = self.descifrar_dato(telefono_cifrado, telefono_nonce, telefono_tag)

        # Limpiar el frame actual
        self.limpiar_frame()
        self.frame_consultar_perfil = ttk.Frame(self.master)
        self.frame_consultar_perfil.pack(pady=10)

        # Mostrar la información del perfil en una sola Label por línea
        ttk.Label(self.frame_consultar_perfil, text=f"Correo Electrónico: {email}").pack(pady=5)
        ttk.Label(self.frame_consultar_perfil, text=f"Teléfono: {telefono}").pack(pady=5)

        num_claves = len(user_data.get("contraseñas", []))
        ttk.Label(self.frame_consultar_perfil, text=f"Número de Claves Almacenadas: {num_claves}").pack(pady=5)

        # Botón para cerrar (volver al menú anterior)
        self.boton_cerrar = ttk.Button(self.frame_consultar_perfil, text="Cerrar", command=self.mostrar_opciones, style="Secondary.TButton")
        self.boton_cerrar.pack(pady=15)

    def mostrar_cambiar_contraseña(self):
        self.limpiar_frame()
        self.frame_cambiar_contraseña = ttk.Frame(self.master)
        self.frame_cambiar_contraseña.pack()

        self.label_actual = ttk.Label(self.frame_cambiar_contraseña, text="Contraseña actual:")
        self.label_actual.pack()
        self.entry_actual = ttk.Entry(self.frame_cambiar_contraseña, show='*')
        self.entry_actual.pack()

        self.boton_confirmar = ttk.Button(self.frame_cambiar_contraseña, text="Continuar", command=self.verificar_contraseña_actual)
        self.boton_confirmar.pack(pady=15)

        self.boton_volver = ttk.Button(self.frame_cambiar_contraseña, text="Volver", command=self.mostrar_opciones, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

    def verificar_contraseña_actual(self):
        usuarios = json_management.cargar_usuarios()
        nombre_usuario = self.usuario_actual
        password_actual = self.entry_actual.get()

        # Asegúrate de que estás accediendo a 'salt_password' y 'hashed_password' en el JSON
        salt_password = base64.urlsafe_b64decode(usuarios[nombre_usuario]['salt_password'])
        hashed_password = usuarios[nombre_usuario]['hashed_password']

        if password_hashing.verificar_password(password_actual, salt_password, hashed_password):
            self.mostrar_nueva_contraseña()
        else:
            messagebox.showerror("Error", "La contraseña actual es incorrecta.")

    def mostrar_nueva_contraseña(self):
        self.limpiar_frame()
        self.frame_nueva_contraseña = (self.master)

        self.label_nueva = ttk.Label(self.frame_nueva_contraseña, text="Nueva contraseña:")
        self.label_nueva.pack()
        self.entry_nueva = ttk.Entry(self.frame_nueva_contraseña, show='*')
        self.entry_nueva.pack()

        self.label_confirmar = ttk.Label(self.frame_nueva_contraseña, text="Confirmar nueva contraseña:")
        self.label_confirmar.pack()
        self.entry_confirmar = ttk.Entry(self.frame_nueva_contraseña, show='*')
        self.entry_confirmar.pack()

        self.boton_confirmar_nueva = ttk.Button(self.frame_nueva_contraseña, text="Cambiar contraseña", command=self.cambiar_contraseña, )
        self.boton_confirmar_nueva.pack(pady=15)

        self.boton_volver_nueva = ttk.Button(self.frame_nueva_contraseña, text="Volver", command=self.mostrar_opciones, style="Secondary.TButton")
        self.boton_volver_nueva.pack(pady=15)

    def cambiar_contraseña(self):
        usuarios = json_management.cargar_usuarios()
        nombre_usuario = self.usuario_actual
        nueva_password = self.entry_nueva.get()
        confirmar_password = self.entry_confirmar.get()

        if nueva_password != confirmar_password:
            messagebox.showerror("Error", "Las contraseñas no coinciden.")
            return

        try:
            data_validation.validar_contraseña(nueva_password)
        except ValidationError as e:
            messagebox.showerror("Error", str(e))
            return

        # Paso 1: Descifrar datos personales y contraseñas almacenadas con la clave actual
        user_data = usuarios[nombre_usuario]

        telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono']['cifrado'])
        telefono_nonce = base64.urlsafe_b64decode(user_data['telefono']['nonce'])
        telefono_tag = base64.urlsafe_b64decode(user_data['telefono']['tag'])

        email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
        email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
        email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])

        # Descifrar email y teléfono
        telefono_descifrado = self.descifrar_dato(telefono_cifrado, telefono_nonce, telefono_tag)
        email_descifrado = self.descifrar_dato(email_cifrado, email_nonce, email_tag)

        # Descifrar contraseñas almacenadas
        contraseñas_descifradas = []
        for contraseña in user_data.get('contraseñas', []):
            contraseña_cifrada = base64.urlsafe_b64decode(contraseña['contraseña'])
            nonce = base64.urlsafe_b64decode(contraseña['nonce'])
            tag = base64.urlsafe_b64decode(contraseña['tag'])
            contrasena_descifrada = self.descifrar_dato(contraseña_cifrada, nonce, tag)
            contraseñas_descifradas.append((contraseña['asunto'], contrasena_descifrada))

        # Paso 2: Generar nuevo salt y hash para la nueva contraseña
        salt_password = password_hashing.generar_salt()
        salt_cifrado = password_hashing.generar_salt()
        hashed_password = password_hashing.hash_password(nueva_password, salt_password)
        nueva_clave = encryption.derivar_clave_cifrado(nueva_password, salt_cifrado)

        # Paso 3: Recifrar datos personales y contraseñas almacenadas con la nueva clave
        email_cifrado_nuevo = encryption.cifrar_aes_gcm(email_descifrado, nueva_clave)
        telefono_cifrado_nuevo = encryption.cifrar_aes_gcm(telefono_descifrado, nueva_clave)

        # Recifrar cada contraseña con la nueva clave
        contraseñas_cifradas_nuevas = []
        for asunto, contrasena_descifrada in contraseñas_descifradas:
            contrasena_cifrada = encryption.cifrar_aes_gcm(contrasena_descifrada, nueva_clave)
            contraseñas_cifradas_nuevas.append({
                'asunto': asunto,
                'contraseña': base64.urlsafe_b64encode(contrasena_cifrada['cifrado']).decode('utf-8'),
                'nonce': base64.urlsafe_b64encode(contrasena_cifrada['nonce']).decode('utf-8'),
                'tag': base64.urlsafe_b64encode(contrasena_cifrada['tag']).decode('utf-8')
            })

        # Actualizar los datos del usuario en el JSON
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

        json_management.guardar_usuarios(usuarios)

        # Paso 4: Actualizar la clave de sesión con la nueva clave
        self.clave_sesion = nueva_clave
        messagebox.showinfo("Éxito", "Contraseña cambiada exitosamente.")
        self.mostrar_opciones()


    def mostrar_pantalla_introducir_pin(self, nombre_usuario):
        self.limpiar_frame()
        self.frame_introducir_pin = ttk.Frame(self.master)
        self.frame_introducir_pin.pack()

        self.label_pin = ttk.Label(self.frame_introducir_pin, text="Ingresa el PIN enviado a tu correo:")
        self.label_pin.pack()
        self.entry_pin = ttk.Entry(self.frame_introducir_pin)
        self.entry_pin.pack()

        self.boton_verificar_pin = ttk.Button(self.frame_introducir_pin, text="Verificar PIN",
                                              command=lambda: self.verificar_pin())
        self.boton_verificar_pin.pack(pady=15)

        self.boton_volver = ttk.Button(self.frame_introducir_pin, text="Volver", command=self.volver_menu, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

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
        self.frame_administrar_contraseñas.pack()

        # Botón para añadir una nueva contraseña
        self.boton_añadir_contraseña = ttk.Button(self.frame_administrar_contraseñas, text="Nueva Contraseña",
                                                  command=self.añadir_nueva_contraseña)
        self.boton_añadir_contraseña.pack(pady=15)

        # Botón para gestionar contraseñas
        self.boton_gestionar_contraseñas = ttk.Button(self.frame_administrar_contraseñas, text="Gestionar Contraseñas",
                                                      command=self.gestionar_contraseñas)
        self.boton_gestionar_contraseñas.pack(pady=15)

        # Botón para eliminar contraseñas
        self.boton_eliminar_contraseña = ttk.Button(self.frame_administrar_contraseñas, text="Eliminar Contraseñas",
                                                    command=self.eliminar_contraseñas)
        self.boton_eliminar_contraseña.pack(pady=15)

        # Botón para salir o volver
        self.boton_volver = ttk.Button(self.frame_administrar_contraseñas, text="Volver", command=self.mostrar_opciones, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

        # Pantalla para añadir una nueva contraseña

    def añadir_nueva_contraseña(self):
        self.limpiar_frame()
        self.frame_añadir_contraseña = ttk.Frame(self.master)
        self.frame_añadir_contraseña.pack()


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
        self.boton_guardar_contraseña.pack(pady=15)

        self.boton_volver = ttk.Button(self.frame_añadir_contraseña, text="Volver",
                                       command=self.administrar_contraseñas, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

        # Pantalla para gestionar contraseñas (ver todas)

    # Pantalla para gestionar contraseñas (ver todas)
    def gestionar_contraseñas(self):
        contraseñas = profile_management.obtener_contraseñas(self.usuario_actual, self.clave_sesion)

        self.limpiar_frame()
        self.frame_gestionar_contraseñas = ttk.Frame(self.master)
        self.frame_gestionar_contraseñas.pack()

        if contraseñas:
            self.contraseñas_visibles = {}

            for idx, contraseña in enumerate(contraseñas):
                ttk.Label(self.frame_gestionar_contraseñas, text=f"Asunto: {contraseña['asunto']}").pack()

                self.contraseñas_visibles[idx] = False
                frame_contraseña = ttk.Frame(self.frame_gestionar_contraseñas)
                frame_contraseña.pack()

                label_contraseña = ttk.Label(frame_contraseña, text="********")
                label_contraseña.pack(side="left")

                boton_mostrar = ttk.Button(frame_contraseña, text="Mostrar")
                boton_mostrar.pack(side="left", padx=5)

                boton_mostrar.config(
                    command=lambda i=idx, lbl=label_contraseña, btn=boton_mostrar, contra=contraseña['contraseña']:
                    self.mostrar_ocultar_contraseña(i, lbl, btn, contra))
        else:
            ttk.Label(self.frame_gestionar_contraseñas, text="No hay contraseñas guardadas.").pack()

        self.boton_volver = ttk.Button(self.frame_gestionar_contraseñas, text="Volver",
                                       command=self.administrar_contraseñas, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

    # Función para mostrar/ocultar la contraseña
    def mostrar_ocultar_contraseña(self, idx, label_contraseña, boton_mostrar, contraseña):
        if self.contraseñas_visibles[idx]:
            label_contraseña.config(text="********")
            boton_mostrar.config(text="Mostrar")
        else:
            label_contraseña.config(text=contraseña)
            boton_mostrar.config(text="Ocultar")

        self.contraseñas_visibles[idx] = not self.contraseñas_visibles[idx]

    # Pantalla para eliminar contraseñas
    # Pantalla para eliminar contraseñas
    def eliminar_contraseñas(self):
        contraseñas = profile_management.obtener_contraseñas(self.usuario_actual,
                                          self.clave_sesion)  # Llamar a la función que obtiene contraseñas

        self.limpiar_frame()
        self.frame_eliminar_contraseñas = ttk.Frame(self.master)
        self.frame_eliminar_contraseñas.pack()

        if contraseñas:
            for contraseña in contraseñas:
                frame_contraseña = ttk.Frame(self.frame_eliminar_contraseñas)
                frame_contraseña.pack()

                ttk.Label(frame_contraseña, text=f"Asunto: {contraseña['asunto']}").pack(side="left")
                ttk.Button(frame_contraseña, text="Eliminar",
                           command=lambda asunto=contraseña['asunto']: self.eliminar_contraseña(asunto)).pack(
                    side="left", padx=5)
        else:
            ttk.Label(self.frame_eliminar_contraseñas, text="No hay contraseñas guardadas.").pack()

        self.boton_volver = ttk.Button(self.frame_eliminar_contraseñas, text="Volver",
                                       command=self.administrar_contraseñas, style="Secondary.TButton")
        self.boton_volver.pack(pady=15)

        # Función para guardar contraseña

    def guardar_contraseña(self):
        asunto = self.entry_asunto.get()
        contraseña = self.entry_contraseña.get()

        if not asunto or not contraseña:
            messagebox.showerror("Error", "Debes proporcionar un asunto y una contraseña.")
            return

        try:
            # Pasamos `self.clave_sesion` al método externo `guardar_contraseña`
            profile_management.guardar_contraseña(self.usuario_actual, asunto, contraseña, self.clave_sesion)
            messagebox.showinfo("Éxito", "Contraseña guardada exitosamente.")
            self.administrar_contraseñas()

        except Exception as e:
            messagebox.showerror("Error", str(e))

        # Función para eliminar contraseña

    def eliminar_contraseña(self, asunto):
        try:
            profile_management.eliminar_contraseña(self.usuario_actual, asunto)  # Llama al método externo con usuario y asunto
            messagebox.showinfo("Éxito", "Contraseña eliminada exitosamente.")
            self.eliminar_contraseñas()  # Actualizar la lista de contraseñas mostrada en la interfaz
        except Exception as e:
            messagebox.showerror("Error", str(e))


# =====================
# EJECUCIÓN DE LA APLICACIÓN
# =====================
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()