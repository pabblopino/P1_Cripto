#!/bin/bash

# ==========================================================
# ===== Creación de la autoridad de certificación raíz =====
# =========================================================

echo -e "\n\n--- Iniciando creación de AC1 ---\n"
# 1. Generación de la estructura de directorios necesaria
#    e inicialización de ficheros serial e index.txt
rm -rf AC1

mkdir -p AC1 A
cp openssl_AC1.cnf AC1/

cd AC1
mkdir solicitudes crls nuevoscerts privado
echo '01' > serial
touch index.txt

echo -e "\nDirectorios creados en AC1/"

# 2. Generación de par de claves RSA, junto con certificado autofirmado por AC1
echo -e "\nGenerando clave privada y certificado raíz"
echo -e "\nIntroduzca una contraseña válida: "
openssl req -x509 -newkey rsa:2048 -days 360 -out ac1cert.pem -outform PEM -config openssl_AC1.cnf
# Se pide una contraseña para crear la clave privada de AC1, que habrá que recordar para cuando queramos usarla
openssl x509 -in ac1cert.pem -text -noout

# 3. Comprobación de errores (código de estado del comando anterior)
if [ $? -eq 0 ]; then
    echo "✅ ¡Autoridad de Certificación AC1 creada correctamente!"
    echo "   - Certificado: AC1/ac1cert.pem"
    echo "   - Clave privada: AC1/privado/ac1key.pem"

    # Para finalizar, crea una copia de su certificado certificado en el almacén de confianza
    cd ..
    rm -rf Trust_Storage
    mkdir Trust_Storage

    cp AC1/ac1cert.pem Trust_Storage/
    echo "✅ Certificado raíz instalado en Trust_Storage/ac1cert.pem"
else
    echo "❌ Error al generar la AC1"
fi
