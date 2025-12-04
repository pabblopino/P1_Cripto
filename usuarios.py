"""
Se encarga del registro y la autenticación de los usuarios, recogiendo
sus datos, aplicando hash, y guardando estos datos en la base de datos
"""

import os
import sqlite3
import logging
from db import conectar
from certificados import verificar_cert, generar_csr
from config import DIR_SOLICITUDES, DIR_CERTIFICADOS
from crypto_utils import (
    derivar_clave_aes, 
    cifrar_datos_aes, 
    descifrar_datos_aes, 
    generar_par_claves_rsa, 
    validar_password
)

# Imports para crear las llaves del usuario y cifrarlas
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

# Configuración básica de logging
# Crea o añade entradas a un archivo de registro (para trazabilidad de eventos)
# En vez de usar print() para mostrar todo por pantalla (que se pierde al cerrar la app), logging guarda la información en un archivo de registro (log)
# Vamos que para guardar informacion sobre votos seria importante
logging.basicConfig(
    filename="datos/app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def registrar_usuario(nombre, email, password):
    """
    Registra un nuevo usuario aplicando hash con PBKDF2-HMAC-SHA256,
    generando una solicitud CSR que debe aprobar la autoridad de certificación raíz
    """
    if not validar_password(password):
        return

    conn = conectar()
    c = conn.cursor()

    # 1. Creamos el hash para la contraseña del usuario a registrar y su clave privada
    salt_auth = os.urandom(16)
    password_hash = derivar_clave_aes(password, salt_auth)
    
    private_key = generar_par_claves_rsa()
    
    # 2. Generamos del CSR (Solicitud de Firma)
    if not generar_csr(nombre, email, private_key):
        print ("Error: El CSR no se ha generado correctamente")
        return


    # 3. Serializamos y Ciframos la Clave PRIVADA (La protegemos)
    #   3.1 Primero la convertimos a bytes (Serializar)
    priv_bytes_raw = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # !! Aún no ciframos aquí, solo convertimos. Mirar si hacerlo así o no
    )

    #   3.2 Ahora la ciframos con AES usando la contraseña del usuario
    salt_priv = os.urandom(16)
    private_key_enc, nonce_priv = cifrar_datos_aes(priv_bytes_raw, password, salt_priv)

    # 4. Guardamos todo en la base de datos
    try:
        c.execute("""INSERT INTO usuarios 
                  (nombre, email, password_hash, salt_auth, public_cert, private_key_enc, salt_priv, nonce_priv) 
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (nombre, email, password_hash, salt_auth, None, private_key_enc, salt_priv, nonce_priv))
        conn.commit()

        print(f"✅ Usuario registrado. CSR generado en: \"{DIR_SOLICITUDES}/{email}.csr\"")
        print("⚠️  AVISO: Tu cuenta está PENDIENTE de validación por la Autoridad (AC1).")
        logging.info(f"Registro pendiente: {email}")
                     
    except sqlite3.IntegrityError:
        print("Error: el email ya ha sido registrado con otro usuario.")
        logging.warning(f"Intento de registro duplicado: {email}")
    finally:
        conn.close()


def autenticar_usuario(email, password):
    """
    Verifica las credenciales de un usuario, su password y certificado de clave pública
    """
    conn = conectar()
    c = conn.cursor()

    # 1. Recuperamos todos los datos del usuario almacenados en la base de datos
    c.execute("""SELECT id, password_hash, salt_auth, public_cert, private_key_enc, salt_priv, nonce_priv 
                 FROM usuarios WHERE email = ?""", (email,))
    resultado = c.fetchone() # Devuelve la primera fila que coincide, si no coincide ninguna devuelve None

    if resultado:

        usuario_id, password_hash, salt_auth, cert_blob, priv_enc, salt_priv, nonce_priv = resultado

        # 2. Comprobamos que la contraseña del usuario coincide y es correcta
        nuevo_hash = derivar_clave_aes(password, salt_auth)

        if nuevo_hash != password_hash:
            print("Contraseña incorrecta.")
            conn.close()
            return None
        
        # 3. Comprobamos que el usuario tenga certificado, y verificamos su firma
        try:
            # 3.1 Nos aseguramos de que el certificado existe en la base de datos
            if not cert_blob:
                # 3.1.1 Comprobamos si el certificado ya ha sido firmado y todavía no se había actualizado
                ruta_crt = f"{DIR_CERTIFICADOS}/{email}.crt"

                if os.path.exists(ruta_crt):
                    print("⬇️  Certificado emitido encontrado. Instalando en perfil de usuario...")
                    with open(ruta_crt, "rb") as f:
                        cert_blob = f.read()
                    
                        # Ejecutamos la actualización
                        c.execute("UPDATE usuarios SET public_cert = ? WHERE id = ?", (cert_blob, usuario_id))
                        conn.commit()

                else:
                    print("\nSu certificado todavía no ha sido emitido, el administrador debe firmar tu CSR primero.")
                    print("\nMuchas gracias por su paciencia.")
                    conn.close()
                    return None
            
            # 3.2 Cargamos el certificado del usuario
            user_cert = x509.load_pem_x509_certificate(cert_blob)

            # 3.3 Verificamos el certificado del usuario
            if not verificar_cert(user_cert):
                print("❌ Acceso denegado: El certificado no es válido o ha caducado.")
                conn.close()
                return None
        
            # 4. Desciframos la clave privada y obtenemos la pública del certificadoo
            priv_bytes = descifrar_datos_aes(priv_enc, nonce_priv, password, salt_priv)
            
            # 4. Deserializamos (Bytes -> Objeto Python)
            # Convertimos los bytes en objetos que Python entiende para poder usarlos luego
            private_key_obj = serialization.load_pem_private_key(priv_bytes, password=None)
            public_key_obj = user_cert.public_key()

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
    c.execute("SELECT id, public_cert FROM usuarios WHERE email = ?", (email,))
    result = c.fetchone()
    conn.close()

    if not result or not result[1]: # No existe el id o el certificado es NULL
        print(f"Usuario {email} no encontrado o sin certificado.")
        return None
    
    user_id, cert_blob = result

    try:
        # Cargamos certificado y extraemos la pública
        user_cert = x509.load_pem_x509_certificate(cert_blob)

        if not verificar_cert(user_cert):
            print(f"⚠️  ALERTA: El certificado de {email} no es confiable.")
            return None

        return user_id, user_cert.public_key()
    
    except Exception as e:
        print(f"Usuario {email} no encontrado o sin certificado válido.")
        logging.warning(f"Intento de usar certificado inválido de {email}: {e}")
        return None # Tratar esto al llamar a esta función e imprimir error