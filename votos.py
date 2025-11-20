"""
Se encarga de controlar el sistema de votación. Cifra el voto antes de guardarlo y
guarda este voto cifrado en la tabla correspondiente de la base de datos
"""
import os
import logging
from db import conectar
from usuarios import obtener_info_receptor

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



# ==========================================
# ===== FUNCIONES PARA COMPARTIR VOTOS =====
# ==========================================


def compartir_voto(user_origen_id, email_destino, private_key_origen):
    """
    Con los datos públicos del receptor, el emisor manda su voto cifrado, de manera
    que se añade a la tabla de votos_compartidos en la base de datos
    """
    
    # 1. Buscamos al usuario destino (su información pública)
    info_destino = obtener_info_receptor(email_destino)

    if not info_destino:
        print("Error: El email introducido no coincide con ningún usuario registrado")
        return
    
    id_destino, public_key_destino = info_destino

    # 2. Recuperamos el voto y la clave cifrada del emisor
    conn = conectar()
    c = conn.cursor()

    c.execute("SELECT id, voto_cifrado, nonce_aes, aad, clave_aes_cifrada FROM votos WHERE usuario_id = ?", (user_origen_id,))
    datos_voto = c.fetchone()

    if not datos_voto:
        print("No tienes ningún voto registrado para poder compartir")
        conn.close()
        return

    voto_id, _, _, _, clave_aes_emisor_enc = datos_voto # _ significa que son datos que no cogemos, no nos interesan 
    try:
        # 3. Desciframos la clave clave AES con la privada del emisor
        clave_aes_emisor = private_key_origen.decrypt(
            clave_aes_emisor_enc,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # 4. Ahora esta clave AES, la ciframos con la pública del receptor
        clave_aes_para_receptor = public_key_destino.encrypt(
            clave_aes_emisor,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # 5. Guardamos los datos en la tabla de compartidos
        c.execute("INSERT INTO votos_compartidos (voto_origen_id, receptor_id, clave_aes_receptor) VALUES (?, ?, ?)",
                  (voto_id, id_destino, clave_aes_para_receptor))
        conn.commit()
        print(f"Voto compartido exitosamente con {email_destino}.")

    except Exception as e:
        print(f"Error al compartir: {e}")
    finally:
        conn.close()


def ver_votos_compartidos(usuario_id, private_key):
    conn = conectar()
    c = conn.cursor()

    # 1. Buscamos los votos compartidos del usuario en la base de datos
    c.execute("""
        SELECT u.email, v.voto_cifrado, v.nonce_aes, v.aad, vc.clave_aes_receptor
        FROM votos_compartidos vc
        JOIN votos v ON vc.voto_origen_id = v.id
        JOIN usuarios u ON v.usuario_id = u.id
        WHERE vc.receptor_id = ?
    """, (usuario_id,))

    filas = c.fetchall()
    conn.close()
    
    if not filas:
        print("No tienes ningún voto compartido disponible")
        return
    
    print(f"\n--- Tienes {len(filas)} votos compartidos ---")

    for email_emisor, voto_cifrado, nonce, aad, clave_para_receptor in filas:
        try:
            # 2. Desciframos la clave AES utilizando la clave privada del receptor
            clave_aes = private_key.decrypt(
                clave_para_receptor,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            # 3. Una vez tenemos la clave AES, desciframos cada voto con ella
            aes = AESGCM(clave_aes)
            voto_en_claro = aes.decrypt(nonce, voto_cifrado, aad).decode()

            print(f"De {email_emisor}: {voto_en_claro}")
        
        except Exception as e:
            print(f"De {email_emisor}: Error al descifrar el voto")