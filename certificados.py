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
from datetime import datetime, timezone

RUTA_AC1 = "AC1/ac1cert.pem"

def cargar_ca_cert():
    """
    Se encarga de cargar el certificado de la autoridad de certificación raíz AC1
    """
    if not os.path.exists(RUTA_AC1):
        print("❌ Error: No se encuentra el certificado de la Autoridad Raíz (ac1cert.pem).")
        return None
    
    with open(RUTA_AC1, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_cert


def generar_csr(nombre, email, private_key):
    """
    Genera el csr correspondente a un usuario, y lo almacena en la carpeta de solicitudes
    de AC1
    """
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
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
    ca_cert = cargar_ca_cert()
    try:
        cert.verify_directly_issued_by(ca_cert)

    except ValueError:
        print("❌ Error: El certificado no fue emitido por la Autoridad de Certificación especificada.")
        return False
    except InvalidSignature:
        print("❌ Error: La firma del certificado es inválida. Puede estar corrupto o haber sido modificado.")
        return False

    tiempo_actual = datetime.now(timezone.utc) # !!! Poner datetime.now(timezone.utc)????
    if cert.not_valid_before > tiempo_actual: # !!! Poner not_valid_before_utc????
        print(f"Error: El certificado aún no es válido. Empieza el: {cert.not_valid_before}")
        return False

    if cert.not_valid_after < tiempo_actual: # !!! Poner not_valid_after_utc????
        print(f"Error: El certificado ha caducado. Venció el: {cert.not_valid_after}")
        return False
    
    print("El certificado se ha validado correctamente")
    return True