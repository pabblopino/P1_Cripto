"""
Se encarga de controlar el sistema de votación. Cifra el voto antes de guardarlo y
guarda este voto cifrado en la tabla correspondiente de la base de datos
"""
import os
from db import conectar

# Hemos elegido el algoritmo de encriptación AES-GCM (en cryptography.io)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_PATH = "datos/clave_aes.key" # Ver bien dónde

def generar_clave():
    clave = AESGCM.generate_key(bit_length=256)
    with open(KEY_PATH, "wb") as f:
        f.write(clave)


def cargar_clave():
    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError(f"No existe la clave en {KEY_PATH}")
    with open(KEY_PATH, "rb") as f:
        return f.read()
    

def descifrar_voto(voto_cifrado, nonce, aad):
    clave = cargar_clave()
    clave_aes = AESGCM(clave)
    voto_descifrado = clave_aes.decrypt(nonce, voto_cifrado, aad)
    return voto_descifrado.decode()

def almacenar_voto(usuario_id, voto):
    conn = conectar()
    c = conn.cursor()

    clave = cargar_clave()
    clave_aes = AESGCM(clave) # ??

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
    print("Voto cifrado almacenado correctamente en la base de datos")