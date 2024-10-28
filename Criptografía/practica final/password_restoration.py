import base64
import random
import smtplib
import json_management
import encryption
from exceptions import ValidationError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# =====================
# FUNCIONES DE RESTAURACIÓN DE CONTRASEÑA
# =====================


# Enviar aviso de cambio de contraseña
def enviar_correo_aviso_cambio_contraseña(nombre_usuario, clave_email):
    usuarios = json_management.cargar_usuarios()
    user_data = usuarios[nombre_usuario]

    email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
    email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
    email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])
    email = encryption.descifrar_aes_gcm(email_cifrado, clave_email, email_nonce, email_tag)

    # Configuración del servidor de correo
    servidor_correo = "smtp.gmail.com"
    puerto = 587
    correo_envio = "100495692@alumnos.uc3m.es"
    contraseña_correo = "miep iewr zlmc ycfp"

    # Crear el mensaje de correo
    mensaje = MIMEMultipart()
    mensaje['From'] = correo_envio
    mensaje['To'] = email
    mensaje['Subject'] = "Cambio de contraseña"
    cuerpo_mensaje = f"Hola {nombre_usuario},\n\nTu contraseña ha sido cambiada exitosamente. Si no has sido tú, por favor contacta con el personal de mantenimiento escribiendo a este mismo email."
    mensaje.attach(MIMEText(cuerpo_mensaje, 'plain'))

    # Enviar correo
    try:
        servidor = smtplib.SMTP(servidor_correo, puerto)
        servidor.starttls()
        servidor.login(correo_envio, contraseña_correo)
        servidor.send_message(mensaje)
        servidor.quit()
    except smtplib.SMTPException as e:
        raise ValidationError(f"Error al enviar el correo electrónico: {e}")

