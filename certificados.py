"""
Se definen las funciones necesarias para hacer las comprobaciones relacionadas
con los certificados
"""

import os
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from datetime import datetime
from config import DIR_TRUST_STORAGE

def cargar_ca_storage():
    """
    Se encarga de cargar el certificado de la autoridad de certificación raíz AC1
    """
    trusted_ca_certs = []

    if not os.path.exists(DIR_TRUST_STORAGE):
        print(f"⚠️  Advertencia: No existe el almacén de confianza '{DIR_TRUST_STORAGE}'")
        return []
    
    for archivo in os.listdir(DIR_TRUST_STORAGE):
        if archivo.endswith(".pem") or archivo.endswith(".crt"):
            ruta_completa = os.path.join(DIR_TRUST_STORAGE, archivo)
            try:
                with open(ruta_completa, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read())
                    trusted_ca_certs.append(ca_cert)
            except Exception as e:
                print(f"⚠️  No se pudo cargar la CA {archivo}: {e}")

    return trusted_ca_certs


def generar_csr(nombre, email, private_key):
    """
    Genera el csr correspondente a un usuario, y lo almacena en la carpeta de solicitudes
    de AC1
    """
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "TOLEDO"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC2M"),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])).sign(private_key, hashes.SHA256())

    ruta_csr = f"AC1/solicitudes/{email}.csr"

    with open(ruta_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return True


def verificar_cert(cert):
    """
    Verifica la validez del certificado de un usuario, comprobando su firma por
    AC1, así como su período de vigencia
    """

    # Primero buscamos a la autoridad raíz dentro de todas las de nuestro almacén de confianza 
    trusted_ca_certs = cargar_ca_storage()

    if not trusted_ca_certs:
        print("❌ Error: El Almacén de Confianza está vacío.")
        return False

    ca_padre = None

    for ca in trusted_ca_certs:
        if ca.subject == cert.issuer:
            ca_padre = ca
            break
    
    if not ca_padre:
        print(f"❌ Error: El emisor del certificado ({cert.issuer}) no está en nuestro Almacén de Confianza.")
        return False

    # Tras encontrar al padre, ya podemos proceder a verificar la cadena de certificación
    try:
        cert.verify_directly_issued_by(ca_padre)

    except ValueError:
        print("❌ Error: El certificado no fue emitido por la Autoridad de Certificación especificada.")
        return False
    except InvalidSignature:
        print("❌ Error: La firma del certificado es inválida. Puede estar corrupto o haber sido modificado.")
        return False

    tiempo_actual = datetime.now()
    if cert.not_valid_before > tiempo_actual:
        print(f"Error: El certificado aún no es válido. Empieza el: {cert.not_valid_before}")
        return False

    if cert.not_valid_after < tiempo_actual:
        print(f"Error: El certificado ha caducado. Venció el: {cert.not_valid_after}")
        return False
    
    print("El certificado se ha validado correctamente")
    return True