"""
Se encarga de controlar el sistema de votación. Cifra el voto antes de guardarlo y
guarda este voto cifrado en la tabla correspondiente de la base de datos
"""
import os
import logging
import sqlite3
from db import conectar
from usuarios import obtener_info_receptor
from certificados import verificar_cert
from crypto_utils import firmar_datos, verificar_firma_datos, envolver_clave_rsa, desenvolver_clave_rsa
from config import LOG_PATH

# Hemos elegido el algoritmo de encriptación AES-GCM (en cryptography.io)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography import x509

# === CONFIGURACIÓN DE LOGGING ===
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def almacenar_voto(usuario_id, voto, public_key, private_key):
    """
    Realiza el Cifrado Híbrido:
    1. Genera clave AES única. 2. Cifra voto con AES. 3. Cifra clave AES con RSA Pública.
    """
    conn = conectar()
    c = conn.cursor()

    # 1. Generamos la firma digital en el voto, con la clave privada del usuario
    signature = firmar_datos(voto, private_key)
    logging.info(f"Firma digital generada para el usuario {usuario_id} (Algoritmo: RSA-PSS-SHA256)")

    # 2. Generamos la clave de sesión AES que se va a usar para cifrar este voto
    clave_sesion_aes = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(clave_sesion_aes)
    # Nonce (number used once), un valor aleatorio usado junto a la clave para cifrar.
    # Es parecido a un salt utilizado en los hash, con la diferencia de que este se usa en cifrado
    nonce_aes = os.urandom(12)
    ## AAD (Additional Authenticted Data), datos autenticados pero no cifrados.
    aad = b"votacion"

    # 3. Ciframos el voto con AESGCM
    voto_cifrado = aes.encrypt(nonce_aes, voto.encode(), aad)

    # 4. Ciframos la clave AES con la clave pública RSA del usuario
    clave_sesion_cifr = envolver_clave_rsa(clave_sesion_aes, public_key)

    # 5. Guardamos todo en la base de datos
    c.execute(
        "INSERT INTO votos (usuario_id, voto_cifrado, nonce_aes, aad, clave_aes_cifrada, firma) VALUES (?, ?, ?, ?, ?, ?)",
        (usuario_id, voto_cifrado, nonce_aes, aad, clave_sesion_cifr, signature)
    )

    conn.commit()
    conn.close()
    logging.info(f"Voto almacenado con cifrado híbrido para usuario {usuario_id}")
    print("Voto cifrado (AES) y clave protegida (RSA) correctamente.")


def descifrar_voto(voto_dat, private_key, public_key):
    """
    Descifrado Híbrido:
    1. Descifra la clave AES (la llave del sobre) usando la Clave Privada RSA.
    2. Descifra el voto con la clave AES recuperada.
    """
    voto_cifrado, nonce_aes, aad, clave_aes_cifrada_rsa, firma = voto_dat

    try:
        # 1. Recuperar la clave AES (Usando tu llave privada RSA)
        clave_sesion_aes = desenvolver_clave_rsa(clave_aes_cifrada_rsa, private_key)

        # 2. Descifrar el voto con la clave AES recuperada
        aes = AESGCM(clave_sesion_aes)
        voto_plano_bytes = aes.decrypt(nonce_aes, voto_cifrado, aad)
        voto_plano = voto_plano_bytes.decode()

        # 3. Verificar la firma digital del voto
        if not verificar_firma_datos(firma, voto_plano_bytes, public_key):
            logging.critical(f"Fallo en verificación de firma: {e}")
            return None, "❌ ALERTA: Firma Digital INVÁLIDA (El voto podría estar manipulado)"
        
        print("✅ Firma Digital VÁLIDA (Integridad confirmada)")
        return voto_plano, "Verificación de firma digital exitosa."        
        
    except Exception as e:
        logging.error(f"Error descifrando voto híbrido: {e}")
        return None, "❌ Error: Voto no descifrable (Clave privada incorrecta o datos corruptos)."


def obtener_voto(usuario_id):
    """Devuelve los datos cifrados necesarios para el descifrado."""
    conn = conectar()
    c = conn.cursor()
    c.execute("SELECT voto_cifrado, nonce_aes, aad, clave_aes_cifrada, firma FROM votos WHERE usuario_id = ?", (usuario_id,))
    resultado = c.fetchone()
    conn.close()
    return resultado  # Devuelve tupla (voto_cifrado, nonce_aes, aad, clave_aes_cifrada) o None

def actualizar_voto(usuario_id, nuevo_voto, public_key, private_key):
    """Borra el voto anterior y almacena uno nuevo"""
    conn = conectar()
    c = conn.cursor()

    # 1. Generamos la nueva firma
    signature = firmar_datos(nuevo_voto, private_key)

    # 2. Generamos nueva clave AES y ciframos el nuevo contenido
    clave_sesion_aes = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(clave_sesion_aes)
    nonce_aes = os.urandom(12)
    aad = b"votacion"
    voto_cifrado = aes.encrypt(nonce_aes, nuevo_voto.encode(), aad)

    # 3. Ciframos la nueva clave AES con RSA
    clave_sesion_cifr = envolver_clave_rsa(clave_sesion_aes, public_key)

    # 4. Borramos de la tabla votos_compartidos si es que era uno de ellos
    c.execute("DELETE FROM votos_compartidos WHERE voto_origen_id IN (SELECT id FROM votos WHERE usuario_id=?)", (usuario_id,))
    compartidos_borrados = c.rowcount

    # 5. Actualizamos el voto en la tabla de votos
    c.execute("""
        UPDATE votos 
        SET voto_cifrado=?, nonce_aes=?, aad=?, clave_aes_cifrada=?, firma=?
        WHERE usuario_id=?
    """, (voto_cifrado, nonce_aes, aad, clave_sesion_cifr, signature, usuario_id))

    conn.commit()
    conn.close()
    logging.info(f"Voto actualizado y refirmado para usuario {usuario_id}")

    if compartidos_borrados > 0:
        logging.info(f"Se han borrado {compartidos_borrados} accesos compartidos al actualizar el voto de {usuario_id}")
    print("✅ Tu voto ha sido actualizado correctamente.")



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
        clave_aes_emisor = desenvolver_clave_rsa(clave_aes_emisor_enc, private_key_origen)

        # 4. Ahora esta clave AES, la ciframos con la pública del receptor
        clave_aes_para_receptor = envolver_clave_rsa(clave_aes_emisor, public_key_destino)

        # 5. Guardamos los datos en la tabla de compartidos
        try:
            c.execute("INSERT INTO votos_compartidos (voto_origen_id, receptor_id, clave_aes_receptor) VALUES (?, ?, ?)",
                  (voto_id, id_destino, clave_aes_para_receptor))
            conn.commit()
            print(f"Voto compartido exitosamente con {email_destino}.")
        except sqlite3.IntegrityError:
            print(f"Ya has compartido este voto previamente con {email_destino}.")
        except Exception as e:
            print(f"Error al compartir: {e}")

    except Exception as e:
        print(f"Error al compartir: {e}")
    finally:
        conn.close()


def ver_votos_compartidos(usuario_id, private_key):
    conn = conectar()
    c = conn.cursor()

    # Primero buscamos los votos compartidos del usuario en la base de datos
    c.execute("""
        SELECT u.email, v.voto_cifrado, v.nonce_aes, v.aad, vc.clave_aes_receptor, v.firma, u.public_cert
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

    for email_emisor, voto_cifrado, nonce, aad, clave_para_receptor, firma, cert_blob in filas:
        try:
            # 1. Comprobamos que el usuario emisor tiene un certificado válido
            if not cert_blob:
                print(f"De {email_emisor}: [ERROR] El emisor no tiene certificado válido.")
                continue
            
            cert_emisor = x509.load_pem_x509_certificate(cert_blob)

            if not verificar_cert(cert_emisor):
                print(f"De {email_emisor}: ❌ [PELIGRO] Certificado del emisor NO confiable (Falsificado o caducado).")
                continue
            
            # Si es válido, entonces ya extraemos la clave pública del emisor
            public_key_emisor = cert_emisor.public_key()

            # 2. Desciframos la clave AES utilizando la clave privada del receptor
            clave_aes = desenvolver_clave_rsa(clave_para_receptor, private_key)

            # 3. Una vez tenemos la clave AES, desciframos cada voto con ella
            aes = AESGCM(clave_aes)
            voto_en_claro_bytes = aes.decrypt(nonce, voto_cifrado, aad)
            voto_texto = voto_en_claro_bytes.decode()

            # 4. Verificamos la firma digital del voto
            if not verificar_firma_datos(firma, voto_en_claro_bytes, public_key_emisor):
                print(f"De {email_emisor}: [BLOQUEADO POR SEGURIDAD] | ❌ Firma INVÁLIDA")
                
            print(f"De {email_emisor}: {voto_texto} | ✅ Firma VÁLIDA (Auténtico)") 
                    
        except Exception as e:
            print(f"De {email_emisor}: Error al descifrar el voto")