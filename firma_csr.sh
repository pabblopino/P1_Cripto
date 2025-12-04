#!/bin/bash

# ===========================================================
# ===== Script para firmar solicitudes (CSR) siendo AC1 =====
# ===========================================================

# 1. Verificamos que se pasa el email a firmar como argumento
email=$1

if [ -z "$email" ]; then
  echo -e "\nError en el formato: ./firmar_csr.sh usuario@email.com\n"
  exit 1
fi

# 2. Comprobamos que existe la solicitud de certificado (CSR) del usuario
CSR_PATH="solicitudes/$email.csr"

if [ ! -f "AC1/$CSR_PATH" ];then
 echo -e "\nError: No existe ninguna solicitud del usuario $email\n"
 exit 1
fi

# 3. Firmamos el certificado del usuario
echo -e "\nFirmando la solicitud de: $email:"
cd AC1

openssl ca -in "$CSR_PATH" \
           -notext \
           -config openssl_AC1.cnf \
           -batch


if [ $? -eq 0 ]; then
  
  # Almacenamos el nombre del certificado que se acaba de generar
  ULTIMO_CERT=$(ls -t nuevoscerts/*pem | head -n 1)
  echo -e "\nCertificado generado en AC1/$ULTIMO_CERT"
  
  cp "$ULTIMO_CERT" "../A/$email.crt"
else
  echo -e "\nFalló la firma del certificado"
  exit 1
fi

cd ..
