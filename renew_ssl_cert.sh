#!/bin/bash

# Skrip Renewal Otomatis Sertifikat SSL Let's Encrypt

# Konfigurasi
DOMAIN="tegarresto.com"
EMAIL="admin@tegarresto.com"
KEYSTORE_PATH="./tegarresto_keystore.p12"

# Cek dan update sertifikat
sudo certbot renew --quiet --non-interactive

# Jika sertifikat diperbarui, konversi ulang
if [ $? -eq 0 ]; then
    CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
    KEYSTORE_PASSWORD=$(openssl rand -base64 32)

    openssl pkcs12 -export \
        -in ${CERT_DIR}/fullchain.pem \
        -inkey ${CERT_DIR}/privkey.pem \
        -out ${KEYSTORE_PATH} \
        -passout pass:${KEYSTORE_PASSWORD}

    # Update environment variable
    echo "export SSL_KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD}" > ~/.ssl_keystore_env
    source ~/.ssl_keystore_env

    # Restart server
    sudo systemctl restart nginx
    echo "Sertifikat SSL berhasil diperbarui"
else
    echo "Tidak ada sertifikat yang perlu diperbarui"
fi
