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
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Almacenamos la ruta del certificado de la autoridad raíz (ya que es público)
RUTA_AC1 = "AC1/ac1cert.pem"

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
    """
    Registra un nuevo usuario aplicando hash con PBKDF2-HMAC-SHA256,
    generando una solicitud CSR que debe aprobar la autoridad de certificación raíz
    """
    if not validar_password(password):
        logging.info(f"Registro fallido para {email}: contraseña débil.")
        return

    conn = conectar()
    c = conn.cursor()

    # 1. Creamos el hash para la contraseña del usuario a registrar y su clave privada
    salt_auth = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_auth, N_ITERACIONES)

    # 65537 es el exponente público, 2048 es el tamaño de la clave en bits, y ambos son los valores mínimos que recomienda cryptography.io
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 2. Generamos del CSR (Solicitud de Firma)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre), # Nombre común
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email), # Email del estudiante
    ])).sign(private_key, hashes.SHA256())

    # 2.1 Guardamos el CSR en la carpeta de solicitudes de AC1
    ruta_csr = f"AC1/solicitudes/{email}.csr"

    with open(ruta_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # 3. Serializamos y Ciframos la Clave PRIVADA (La protegemos)
    #   3.1 Primero la convertimos a bytes (Serializar)
    priv_bytes_raw = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # !! Aún no ciframos aquí, solo convertimos. Mirar si hacerlo así o no
    )

    #   3.2 Ahora la ciframos con AES usando la contraseña del usuario
    salt_priv = os.urandom(16) # !! Hace falta salt??
    key_kek = derivar_clave_encriptacion(password, salt_priv) # Derivamos clave AES
    aes_kek = AESGCM(key_kek) # KEK -> Key Encryption Key (Clave de Encriptación de Clave)
    nonce_priv = os.urandom(12)
    
    # Ciframos los bytes de la clave privada
    private_key_enc = aes_kek.encrypt(nonce_priv, priv_bytes_raw, None)

    # 4. Guardamos todo en la base de datos
    try:
        c.execute("""INSERT INTO usuarios 
                  (nombre, email, password_hash, salt_auth, public_cert, private_key_enc, salt_priv, nonce_priv) 
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (nombre, email, password_hash, salt_auth, None, private_key_enc, salt_priv, nonce_priv))
        conn.commit()

        print(f"✅ Usuario registrado. CSR generado en: {ruta_csr}")
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
        nuevo_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_auth, N_ITERACIONES)

        if nuevo_hash != password_hash:
            print("Contraseña incorrecta.")
            conn.close()
            return None
        
        # 3. Comprobamos que el usuario tenga certificado, y verificamos su firma
        try:
            # 3.1 Nos aseguramos de que el certificado existe en la base de datos
            if not cert_blob:
                # 3.1.1 Comprobamos si el certificado ya ha sido firmado y todavía no se había actualizado
                ruta_repo_publico = f"AC1/nuevoscerts/{email}.crt"

                if os.path.exists(ruta_repo_publico):
                    print("⬇️  Certificado emitido encontrado. Instalando en perfil de usuario...")
                    with open(ruta_repo_publico, "rb") as f:
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

            # 3.3 Cargamos el certificado de la autoridad raíz
            if not os.path.exists(RUTA_AC1):
             print("❌ Error crítico: No se encuentra el certificado de la Autoridad Raíz (ac1cert.pem).")
             conn.close()
             return None
            
            with open(RUTA_AC1, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            try:
                user_cert.verify_directly_issued_by(ca_cert)

                # !!! AQUÍ DEBEMOS COMPROBAR LAS FECHAS DEL CERTIFICADO
            except Exception as e:
                print("❌ ALERTA DE SEGURIDAD: El certificado del usuario NO ha sido firmado por nuestra AC1.")
                print(f"   Detalle: {e}")
                conn.close()
                return None
        
            # 4. Desciframos la clave privada y obtenemos la pública del certificadoo
            key_kek = derivar_clave_encriptacion(password, salt_priv)
            aes_kek = AESGCM(key_kek)

            # Desciframos los bytes
            priv_bytes = aes_kek.decrypt(nonce_priv, priv_enc, None)
            
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

        if not os.path.exists(RUTA_AC1):
            print("Error: No se encuentra la CA Raíz.")
            return None
            
        with open(RUTA_AC1, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        user_cert.verify_directly_issued_by(ca_cert) # !! Ver bien cómo se hace

        return user_id, user_cert.public_key()
    
    except Exception as e:
        print(f"Usuario {email} no encontrado o sin certificado válido.")
        logging.warning(f"Intento de usar certificado inválido de {email}: {e}")
        return None # Tratar esto al llamar a esta función e imprimir error