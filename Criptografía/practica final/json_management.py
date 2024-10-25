import os
import json


ARCHIVO_USUARIOS = "usuarios.json"

# =====================
# FUNCIONES DE MANEJO DE JSON
# =====================

def cargar_usuarios():
    if os.path.exists(ARCHIVO_USUARIOS):
        with open(ARCHIVO_USUARIOS, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                # Retorna un diccionario vacío si el archivo está vacío o no tiene formato JSON válido
                return {}
    return {}


def guardar_usuarios(usuarios):
    with open(ARCHIVO_USUARIOS, "w") as file:
        json.dump(usuarios, file, indent=4)