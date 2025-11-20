"""
Se encarga de controlar el sistema de votación. Cifra el voto antes de guardarlo y
guarda este voto cifrado en la tabla correspondiente de la base de datos
"""
import os
import logging
from db import conectar

# Hemos elegido el algoritmo de encriptación AES-GCM (en cryptography.io)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Ruta del propio archivo votos.py
DATOS_DIR = os.path.join(BASE_DIR, "datos")
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


def almacenar_voto(usuario_id, voto, public_key):
    """
    Realiza el Cifrado Híbrido:
    1. Genera clave AES única. 2. Cifra voto con AES. 3. Cifra clave AES con RSA Pública.
    """
    conn = conectar()
    c = conn.cursor()

    # 1. Generamos la clave de sesión AES que se va a usar para cifrar este voto
    clave_sesion_aes = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(clave_sesion_aes)
    # Nonce (number used once), un valor aleatorio usado junto a la clave para cifrar.
    # Es parecido a un salt utilizado en los hash, con la diferencia de que este se usa en cifrado
    nonce_aes = os.urandom(12)
    ## AAD (Additional Authenticted Data), datos autenticados pero no cifrados.
    aad = b"votacion"

    # 2. Ciframos el voto con AESGCM
    voto_cifrado = aes.encrypt(nonce_aes, voto.encode(), aad)

    # 3. Ciframos la clave AES con la clave pública RSA del usuario
    clave_sesion_cifr = public_key.encrypt(
        clave_sesion_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Guardamos todo en la base de datos
    c.execute(
        "INSERT INTO votos (usuario_id, voto_cifrado, nonce_aes, aad, clave_aes_cifrada) VALUES (?, ?, ?, ?, ?)",
        (usuario_id, voto_cifrado, nonce_aes, aad, clave_sesion_cifr)
    )

    conn.commit()
    conn.close()
    logging.info(f"Voto almacenado con cifrado híbrido para usuario {usuario_id}")
    print("Voto cifrado (AES) y clave protegida (RSA) correctamente.")


def descifrar_voto(voto_dat, private_key):
    """
    Descifrado Híbrido:
    1. Descifra la clave AES (la llave del sobre) usando la Clave Privada RSA.
    2. Descifra el voto con la clave AES recuperada.
    """
    voto_cifrado, nonce_aes, aad, clave_aes_cifrada_rsa = voto_dat

    try:
        # 1. Recuperar la clave AES (Usando tu llave privada RSA)
        clave_sesion_aes = private_key.decrypt(
            clave_aes_cifrada_rsa,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Descifrar el Voto con la clave AES recuperada
        aes = AESGCM(clave_sesion_aes)
        voto_plano = aes.decrypt(nonce_aes, voto_cifrado, aad)
        
        return voto_plano.decode()
    
    except Exception as e:
        logging.error(f"Error descifrando voto híbrido: {e}")
        return "❌ Error: Voto no descifrable (Clave privada incorrecta o datos corruptos)."


def obtener_voto(usuario_id):
    """Devuelve los datos cifrados necesarios para el descifrado."""
    conn = conectar()
    c = conn.cursor()
    c.execute("SELECT voto_cifrado, nonce_aes, aad, clave_aes_cifrada FROM votos WHERE usuario_id = ?", (usuario_id,))
    resultado = c.fetchone()
    conn.close()
    return resultado  # Devuelve tupla (voto_cifrado, nonce_aes, aad, clave_aes_cifrada) o None

def actualizar_voto(usuario_id, nuevo_voto, public_key):
    """Borra el voto anterior y almacena uno nuevo"""
    conn = conectar()
    c = conn.cursor()
    c.execute("DELETE FROM votos WHERE usuario_id = ?", (usuario_id,))
    conn.commit()
    conn.close()
    almacenar_voto(usuario_id, nuevo_voto, public_key)   