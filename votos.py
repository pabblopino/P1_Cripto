"""
Se encarga de controlar el sistema de votación. Cifra el voto antes de guardarlo y
guarda este voto cifrado en la tabla correspondiente de la base de datos
"""
import os
import logging
from db import conectar

# Hemos elegido el algoritmo de encriptación AES-GCM (en cryptography.io)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Ruta del propio archivo votos.py
DATOS_DIR = os.path.join(BASE_DIR, "datos")
os.makedirs(DATOS_DIR, exist_ok=True)

KEY_PATH = os.path.join(DATOS_DIR, "clave_aes.key")
LOG_PATH = os.path.join(DATOS_DIR, "app.log")

# === CONFIGURACIÓN DE LOGGING ===
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
# Parámetros informativos
ALGORITHM_NAME = "AES-GCM"
KEY_LENGTH_BITS = 256
AAD_DESCRIPTION = "'votacion'"

def generar_clave():
    clave = AESGCM.generate_key(bit_length=256)
    # Antes de guardar la clave, nos aseguramos de que exista la carpeta 'datos/'.
    # Si no existe, esta línea la crea automáticamente para evitar errores al escribir el archivo.
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, "wb") as f:
        f.write(clave)
    logging.info(f"Clave AES generada y almacenada en {KEY_PATH}")
    print(f" Clave AES-{KEY_LENGTH_BITS} generada y guardada en {KEY_PATH}.")


def cargar_clave():
    if not os.path.exists(KEY_PATH):
        logging.warning("Clave AES no encontrada. Generando una nueva...")
        generar_clave()
    with open(KEY_PATH, "rb") as f:
        return f.read()
    

def descifrar_voto(voto_cifrado, nonce, aad):
    clave = cargar_clave()
    clave_aes = AESGCM(clave)
    voto_descifrado = clave_aes.decrypt(nonce, voto_cifrado, aad)
    info_msg = (f"Descifrado: Algoritmo {ALGORITHM_NAME} | "
                f"Longitud de clave: {KEY_LENGTH_BITS} bits | "
                f"AAD: {AAD_DESCRIPTION}")
    logging.info(info_msg)
    print("Voto descifrado correctamente.")
    print("   " + info_msg)
    return voto_descifrado.decode()

def almacenar_voto(usuario_id, voto):
    conn = conectar()
    c = conn.cursor()

    clave = cargar_clave()
    clave_aes = AESGCM(clave) 

     # Nonce (number used once), un valor aleatorio usado junto a la clave para cifrar.
     # Es parecido a un salt utilizado en los hash, con la diferencia de que este se usa en cifrado
    nonce = os.urandom(12)

    ## AAD (Additional Authenticted Data), datos autenticados pero no cifrados.
    aad = b"votacion" # Mirar bien qué es

    voto_cifrado = clave_aes.encrypt(nonce, voto.encode(), aad)

    c.execute(
        "INSERT INTO votos (usuario_id, voto_cifrado, nonce, aad) VALUES (?, ?, ?, ?)",
        (usuario_id, voto_cifrado, nonce, aad)
    )

    conn.commit()
    conn.close()
    info_msg = (f"Cifrado: Algoritmo {ALGORITHM_NAME} | "
                f"Longitud de clave: {KEY_LENGTH_BITS} bits | "
                f"AAD: {AAD_DESCRIPTION}")
    logging.info(f" Voto cifrado con AES-GCM (256 bits) almacenado para usuario ID {usuario_id}.")
    print("Voto cifrado y almacenado correctamente en la base de datos.")
    print("   " + info_msg)

def obtener_voto(usuario_id):
    """Devuelve el voto cifrado del usuario si existe, sino None"""
    conn = conectar()
    c = conn.cursor()
    c.execute("SELECT voto_cifrado, nonce, aad FROM votos WHERE usuario_id = ?", (usuario_id,))
    resultado = c.fetchone()
    conn.close()
    return resultado  # Devuelve tupla (voto_cifrado, nonce, aad) o None

def actualizar_voto(usuario_id, nuevo_voto):
    """Borra el voto anterior y almacena uno nuevo"""
    conn = conectar()
    c = conn.cursor()
    c.execute("DELETE FROM votos WHERE usuario_id = ?", (usuario_id,))
    conn.commit()
    conn.close()
    almacenar_voto(usuario_id, nuevo_voto)   