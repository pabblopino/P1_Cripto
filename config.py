import os

# Rutas de Archivos
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATOS_DIR = os.path.join(BASE_DIR, "datos")
DB_PATH = os.path.join(DATOS_DIR, "votacion.db")
LOG_PATH = os.path.join(DATOS_DIR, "app.log")

# Rutas AC1
RUTA_AC1_CERT = "AC1/ac1cert.pem"
DIR_SOLICITUDES = "AC1/solicitudes"
DIR_CERTIFICADOS = "A"

# Configuración Algoritmos Criptográficos
N_ITERACIONES_PBKDF2 = 600000
RSA_KEY_SIZE = 2048 # Ambos valores de rsa son los mínimos recomendados en cryptography.io
RSA_EXPONENT = 65537 
AES_KEY_LENGTH = 32  # 256 bits
AES_NONCE_SIZE = 12
SALT_SIZE = 16