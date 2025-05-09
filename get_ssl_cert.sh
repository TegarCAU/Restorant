#!/bin/bash

# Skrip Otomatisasi Sertifikat SSL Let's Encrypt untuk TegarResto

# Konfigurasi
DOMAIN="tegarresto.com"
EMAIL="admin@tegarresto.com"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
KEYSTORE_PATH="./tegarresto_keystore.p12"
KEYSTORE_PASSWORD=$(openssl rand -base64 32)

# Instal Certbot
sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx

# Dapatkan Sertifikat SSL
sudo certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email ${EMAIL} \
    -d ${DOMAIN} \
    -d www.${DOMAIN}

# Konversi ke PKCS12 Keystore
openssl pkcs12 -export \
    -in ${CERT_DIR}/fullchain.pem \
    -inkey ${CERT_DIR}/privkey.pem \
    -out ${KEYSTORE_PATH} \
    -passout pass:${KEYSTORE_PASSWORD}

# Simpan password ke environment variable
echo "export SSL_KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD}" >> ~/.bashrc
source ~/.bashrc

# Atur ulang konfigurasi server web
sudo systemctl restart nginx

echo "Sertifikat SSL berhasil diinstal untuk ${DOMAIN}"
echo "Keystore tersimpan di: ${KEYSTORE_PATH}"
