"""
Se encarga del registro y la autenticación de los usuarios, recogiendo
sus datos, aplicando hash, y guardando estos datos en la base de datos
"""

import os
import hashlib
import sqlite3
import logging
from db import conectar


# Imports para crear las llaves del usuario y cifrarlas
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuración básica de logging
# Crea o añade entradas a un archivo de registro (para trazabilidad de eventos)
# En vez de usar print() para mostrar todo por pantalla (que se pierde al cerrar la app), logging guarda la información en un archivo de registro (log)
# Vamos que para guardar informacion sobre votos seria importante
logging.basicConfig(
    filename="datos/app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Elegimos 600.000 iteraciones ya que es el valor recomendado por OWASP para
# aumentar la seguridad frente a ataques de fuerza bruta
N_ITERACIONES = 600000


# =========================================== 
# ========== COMIENZO DE FUNCIONES ==========
# =========================================== 
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

def derivar_clave_encriptacion(password, salt):
    """
    Convierte la contraseña del usuario en una llave AES de 32 bytes.
    La usaremos para cifrar/descifrar su Clave Privada RSA.
    """
    # 32 bytes, porque nuestro AES necesita clave de 256 bits
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, N_ITERACIONES, dklen=32)

# Registrar usuario
def registrar_usuario(nombre, email, password):
    """Registra un nuevo usuario aplicando hash con PBKDF2-HMAC-SHA256."""
    if not validar_password(password):
        logging.info(f"Registro fallido para {email}: contraseña débil.")
        return

    conn = conectar()
    c = conn.cursor()

    # 1. Creamos el hash para la contraseña del usuario a registrar
    salt_auth = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_auth, N_ITERACIONES)


    # 2. Creamos el par de llaves del usuario
    # 65537 es el exponente público, 2048 es el tamaño de la clave en bits, y ambos son los valores mínimos que recomienda cryptography.io
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # 3. Serializamos la Clave PÚBLICA (La convertimos a bytes para guardarla visible)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 4. Serializamos y Ciframos la Clave PRIVADA (La protegemos)
    #   4.1 Primero la convertimos a bytes (Serializar)
    priv_bytes_raw = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # !! Aún no ciframos aquí, solo convertimos. Mirar si hacerlo así o no
    )

    #   4.2 Ahora la ciframos con AES usando la contraseña del usuario
    salt_priv = os.urandom(16) # !! Hace falta salt??
    key_kek = derivar_clave_encriptacion(password, salt_priv) # Derivamos clave AES
    aes_kek = AESGCM(key_kek) # KEK -> Key Encryption Key (Clave de Encriptación de Clave)
    nonce_priv = os.urandom(12)
    
    # Ciframos los bytes de la clave privada
    private_key_enc = aes_kek.encrypt(nonce_priv, priv_bytes_raw, None)

    # 5. Guardamos todo en la base de datos
    try:
        # !! Si usamos un salt y nonce nuevos al final, debemos guardarlos en la base de datos??
        c.execute("""INSERT INTO usuarios 
                  (nombre, email, password_hash, salt_auth, public_key, private_key_enc, salt_priv, nonce_priv) 
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (nombre, email, password_hash, salt_auth, public_bytes, private_key_enc, salt_priv, nonce_priv))
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

    # 1. Recuperamos todos los datos del usuario almacenados en la base de datos
    c.execute("""SELECT id, password_hash, salt_auth, public_key, private_key_enc, salt_priv, nonce_priv 
                 FROM usuarios WHERE email = ?""", (email,))
    resultado = c.fetchone() # Devuelve la primera fila que coincide, si no coincide ninguna devuelve None
    conn.close()

    if resultado:

        # 2. Comprobamos que la contraseña del usuario coincide y es correcta
        usuario_id, password_hash, salt_auth, pub_bytes, priv_enc, salt_priv, nonce_priv = resultado

        nuevo_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_auth, N_ITERACIONES)

        if nuevo_hash == password_hash:
            try:
                key_kek = derivar_clave_encriptacion(password, salt_priv)
                aes_kek = AESGCM(key_kek)

                # Desciframos los bytes
                priv_bytes = aes_kek.decrypt(nonce_priv, priv_enc, None)
                
                # 4. Deserializamos (Bytes -> Objeto Python)
                # Convertimos los bytes en objetos que Python entiende para poder usarlos luego
                private_key_obj = serialization.load_pem_private_key(priv_bytes, password=None)
                public_key_obj = serialization.load_pem_public_key(pub_bytes)

                # 5. Devolvemos las llaves al main para que pueda utilizarlas
                print("Login del usuario correcto.")
                logging.info(f"Inicio de sesión correcto: {email}")
                return usuario_id, private_key_obj, public_key_obj
            except Exception as e:
                logging.error(f"Fallo al descifrar la clave privada: {e}")
                return None
            
    print("Email o contraseña incorrectos.")
    logging.warning(f"Inicio de sesión fallido: {email}")
    return None


# ==========================================
# ===== FUNCIONES PARA COMPARTIR VOTOS =====
# ==========================================

def obtener_info_receptor(email):
    """
    Busca un usuario por email y devuelve su información pública: ID y Clave Pública
    Sirve para poder enviarle cosas cifradas
    """
    conn = conectar()
    c = conn.cursor()
    c.execute("SELECT id, public_key FROM usuarios WHERE email = ?", (email,))
    result = c.fetchone()
    conn.close()

    if result:
        user_id, pub_key = result
        pub_key_obj = serialization.load_pem_public_key(pub_key)
        return user_id, pub_key_obj
    else:
        return None # Tratar esto al llamar a esta función e imprimir error