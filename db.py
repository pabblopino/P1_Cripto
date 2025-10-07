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
    conn = conectar() # No es mejor conn = sqlite3.connect(DB_PATH)?
    c = conn.cursor() # Creación del cursor que ejecuta las consultas SQL

    # Creación de la tabla usuarios
    c.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              nombre TEXT NOT NULL,
              email TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              salt TEXT NOT NULL
              )
    ''')

    # Creación de la tabla votos
    c.execute('''
    CREATE TABLE IF NOT EXISTS votos (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              usuario_id INTEGER NOT NULL,
              voto_cifrado TEXT NOT NULL,
              FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
              )
    ''')

    # Hacemos commit de los cambios y cerramos la conexión
    conn.commit() 
    conn.close()


if __name__ == "__main__":
    """Esto es para que se creen las tablas solamente si se ejecuta este
    archivo directamente"""
    crear_tablas()