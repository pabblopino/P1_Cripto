"""
Se encarga del registro y la autenticación de los usuarios, recogiendo
sus datos, aplicando hash, y guardando estos datos en la base de datos
"""

import os
import hashlib # Mirar si bcrypt, hashlib, passlib, scrypt o argon2
import sqlite3
from db import conectar
N_ITERACIONES = 10000

def registrar_usuario(nombre, email, password):
    conn = conectar()
    c = conn.cursor()

    # Genera un salt aleatorio
    salt = os.urandom(16)
    
    # Se genera el hash de la contraseña
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, N_ITERACIONES) # Esto hay que verlo

    try:
        c.execute("INSERT INTO usuarios (nombre, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                  (nombre, email, password_hash, salt))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error, el email ya ha sido registrado con otro usuario")
    finally: # Con finally cerramos la conexión aunque salte la excepción
        conn.close()


def autenticar_usuario(email, password):
    conn = conectar()
    c = conn.cursor()

    c.execute("SELECT id, password_hash, salt FROM usuarios WHERE email = ?", (email,)) # Por qué select de esas??
    resultado = c.fetchone() # Devuelve la primera fila que coincide, si no coincide ninguna devuelve None
    conn.close()

    if resultado:
        usuario_id, password_hash, salt = resultado

        # Se genera el nuevo hash para ver si coincide con el guardado en la base de datos
        nuevo_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, N_ITERACIONES) # Esto hay que verlo
        
        if nuevo_hash == password_hash:
            print("Login del usuario correcto")
            return usuario_id # Esto hay que verlo
            
    
    print("Email o contraseña incorrectos")
    return None