"""
Este archivo recoge las funciones con las cuales se crea y
accede a la base de datos.
"""
import sqlite3
import os

DB_PATH =  "datos/votacion.db"

def conectar():
    """Crea la conexión con la base de datos"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")  # Soporte para claves foráneas
    return conn

def crear_tablas():
    """Crea las tablas usuarios y votos en la base de datos (si no existen)"""
    conn = conectar() # Conecta con la base de datos
    c = conn.cursor() # Creación del cursor que ejecuta las consultas SQL

    # Creación de la tabla usuarios
    c.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              nombre TEXT NOT NULL,
              email TEXT UNIQUE NOT NULL,
              password_hash BLOB NOT NULL,
              salt_auth BLOB NOT NULL,
              public_key BLOB NOT NULL,     -- Clave Pública RSA (PEM)
              private_key_enc BLOB NOT NULL,-- Clave Privada RSA (Cifrada)
              salt_priv BLOB NOT NULL,
              nonce_priv BLOB NOT NULL
              )
    """)

    # Creación de la tabla votos
    c.execute(
    """CREATE TABLE IF NOT EXISTS votos (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              usuario_id INTEGER NOT NULL,
              voto_cifrado BLOB NOT NULL,
              nonce_aes BLOB NOT NULL,
              aad BLOB,
              clave_aes_cifrada BLOB NOT NULL, -- La clave AES cifrada con RSA
              FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
              )
    """)

    # Creación de la tabla votos compartidos
    c.execute("""
    CREATE TABLE IF NOT EXISTS votos_compartidos (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              voto_origen_id INTEGER NOT NULL,
              receptor_id INTEGER NOT NULL,
              clave_aes_receptor BLOB NOT NULL,     -- La clave AES cifrada con la pública del receptor
              
              FOREIGN KEY(voto_origen_id) REFERENCES votos(id),
              FOREIGN KEY(receptor_id) REFERENCES usuarios(id)
              )
    """)

    # Hacemos commit de los cambios y cerramos la conexión
    conn.commit() 
    conn.close()


if __name__ == "__main__":
    """Esto es para que se creen las tablas solamente si se ejecuta este
    archivo directamente"""
    crear_tablas()