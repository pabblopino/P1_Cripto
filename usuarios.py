"""
Se encarga del registro y la autenticación de los usuarios, recogiendo
sus datos, aplicando hash, y guardando estos datos en la base de datos
"""

import os
import hashlib
import sqlite3
import logging
from db import conectar

os.makedirs("datos", exist_ok=True)

# Configuración básica de logging
# Crea o añade entradas a un archivo de registro (para trazabilidad de eventos)
# En vez de usar print() para mostrar todo por pantalla (que se pierde al cerrar la app), logging guarda la información en un archivo de registro (log)
# Vamos que para guardar informacion sobre votos seria importante
logging.basicConfig(
    filename="datos/app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

N_ITERACIONES = 10000

# Validación de contraseñas
def validar_password(password):
    """
    Comprueba que la contraseña cumpla con criterios mínimos de seguridad.
    - Mínimo 8 caracteres
    - Al menos una mayúscula, una minúscula y un número
    """
    if len(password) < 8:
        print("La contraseña debe tener al menos 8 caracteres.")
        logging.warning("Intento de registro con contraseña demasiado corta.") #logging es un módulo de Python que sirve para registrar automáticamente mensajes importantes del programa
        return False
    if not any(c.islower() for c in password):
        print("La contraseña debe contener al menos una letra minúscula.")
        return False
    if not any(c.isupper() for c in password):
        print("La contraseña debe contener al menos una letra mayúscula.")
        return False
    if not any(c.isdigit() for c in password):
        print("La contraseña debe contener al menos un número.")
        return False
    return True

# Registrar usuario
def registrar_usuario(nombre, email, password):
    """Registra un nuevo usuario aplicando hash con PBKDF2-HMAC-SHA256."""
    if not validar_password(password):
        logging.info(f"Registro fallido para {email}: contraseña débil.")
        return

    conn = conectar()
    c = conn.cursor()

    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, N_ITERACIONES)

    try:
        c.execute("INSERT INTO usuarios (nombre, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                  (nombre, email, password_hash, salt))
        conn.commit()
        print("Usuario registrado correctamente.")
        logging.info(f"Usuario registrado correctamente: {email}")
    except sqlite3.IntegrityError:
        print("Error: el email ya ha sido registrado con otro usuario.")
        logging.warning(f"Intento de registro duplicado: {email}")
    finally:
        conn.close()

# Autenticación de usuario

def autenticar_usuario(email, password):
    """Verifica las credenciales de un usuario comparando hashes."""
    conn = conectar()
    c = conn.cursor()

    c.execute("SELECT id, password_hash, salt FROM usuarios WHERE email = ?", (email,))
    resultado = c.fetchone() # Devuelve la primera fila que coincide, si no coincide ninguna devuelve None
    conn.close()

    if resultado:
        usuario_id, password_hash, salt = resultado
        nuevo_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, N_ITERACIONES)

        if nuevo_hash == password_hash:
            print("Login del usuario correcto.")
            logging.info(f"Inicio de sesión correcto: {email}")
            return usuario_id #Esto hay que verlo si Pablete, pero si devuelve usuario valdria con lo que he puesto en el main

    print("Email o contraseña incorrectos.")
    logging.warning(f"Inicio de sesión fallido: {email}")
    return None