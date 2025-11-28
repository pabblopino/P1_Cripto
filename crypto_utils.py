import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from config import N_ITERACIONES_PBKDF2, AES_KEY_LENGTH, RSA_EXPONENT, RSA_KEY_SIZE

def derivar_clave_aes(password, salt):
    """
    Deriva una clave AES de 32 bytes desde la contraseña
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        N_ITERACIONES_PBKDF2, 
        dklen=AES_KEY_LENGTH
    )

def cifrar_datos_aes(datos, password, salt):
    """
    Cifra bytes usando una clave derivada de la contraseña, en nuestra práctica, sólo
    la utilizamos para cifrar la clave privada serializada, dejándola ahora lista para
    ser almacenada en la BD
    Devuelve (datos_cifrados, nonce)
    """
    key_kek = derivar_clave_aes(password, salt) # Derivamos clave AES
    aes = AESGCM(key_kek) # KEK -> Key Encryption Key (Clave de Encriptación de Clave)
    nonce = os.urandom(12)
    datos_cifrados = aes.encrypt(nonce, datos, None)
    return datos_cifrados, nonce

def descifrar_datos_aes(datos_cifrados, nonce, password, salt):
    """
    Descifra bytes usando una clave derivada de la contraseña
    """
    key_kek = derivar_clave_aes(password, salt)
    aes = AESGCM(key_kek)
    return aes.decrypt(nonce, datos_cifrados, None)

def generar_par_claves_rsa():
    """
    Genera una clave privada RSA estándar (la pública no ya que se
    obtiene de la privada con private_key.public_key())
    """
    return rsa.generate_private_key(
        public_exponent=RSA_EXPONENT,
        key_size=RSA_KEY_SIZE
    )

def validar_password(password):
    """
    Comprueba que la contraseña cumpla con criterios mínimos de seguridad.
    - Mínimo 8 caracteres
    - Al menos una mayúscula, una minúscula y un número
    """
    if len(password) < 8:
        print("La contraseña debe tener al menos 8 caracteres.")
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