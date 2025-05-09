# Konfigurasi Environment Variables & Manajemen Keamanan

## 🔐 Filosofi Keamanan
Keamanan bukan sekadar fitur, melainkan komitmen berkelanjutan untuk melindungi data dan pengalaman pengguna.

## 🛡️ Kredensial & Variabel Konfigurasi

### 1. Autentikasi & Identitas
- **JWT Secret Key**
  - Variabel: `JWT_SECRET_KEY`
  - Kriteria:
    * Minimal 32 karakter
    * Kombinasi huruf besar, kecil, angka, dan simbol
    * Dihasilkan menggunakan generator kriptografis
  - Contoh: `export JWT_SECRET_KEY='K3R4h4s14R4h4s14Y4ngS4nG4tR4h4s14!'`

- **Kredensial Default**
  - Username Admin: `APP_DEFAULT_USERNAME`
    * Default: `admin`
    * Wajib diganti pada environment produksi
  - Password Admin: `APP_DEFAULT_PASSWORD`
    * Default: `admin123`
    * Wajib memenuhi kriteria kompleksitas

### 2. Konfigurasi Pengguna
- **Kredensial Pengguna**
  - Password: `APP_USER_PASSWORD`
    * Default: `user123`
    * Wajib memiliki:
      - Minimal 12 karakter
      - Kombinasi huruf besar/kecil
      - Minimal 1 angka
      - Minimal 1 simbol khusus

### Cara Penggunaan

#### Windows PowerShell
```powershell
$env:JWT_SECRET_KEY = 'rahasia123'
$env:APP_DEFAULT_USERNAME = 'adminbaru'
$env:APP_DEFAULT_PASSWORD = 'passwordbaru'
java SimpleWebServer
```

#### Linux/Mac Terminal
```bash
export JWT_SECRET_KEY='rahasia123'
export APP_DEFAULT_USERNAME='adminbaru'
export APP_DEFAULT_PASSWORD='passwordbaru'
java SimpleWebServer
```

🔒 **PENTING**: 
- Jangan commit kredensial ke repository
- Gunakan environment variable atau file konfigurasi terpisah
- Ganti default key dan password di production

## 🔐 Daftar Environment Variable Keamanan

### Autentikasi & Token
- `JWT_SECRET_KEY`: Kunci rahasia untuk signing JWT
- `APP_DEFAULT_USERNAME`: Username default
- `APP_DEFAULT_PASSWORD`: Password default
- `SSL_KEYSTORE_PASSWORD`: Password keystore SSL

### Rate Limiting
- `MAX_LOGIN_REQUESTS`: Batasan request login per menit
- `MAX_REFRESH_REQUESTS`: Batasan request refresh token
- `MAX_FILE_REQUESTS`: Batasan request akses file

### CSRF Protection
- `CSRF_TOKEN_EXPIRATION`: Waktu kedaluwarsa CSRF token

### Two-Factor Authentication (2FA)
- `2FA_ENABLED`: Aktifkan/nonaktifkan 2FA
- `2FA_SECRET_{USERNAME}`: Secret key untuk 2FA
- `2FA_ALGORITHM`: Algoritma generasi token (default: TOTP)
- `2FA_TOKEN_LENGTH`: Panjang token 2FA
- `2FA_TOKEN_EXPIRATION`: Waktu kedaluwarsa token 2FA

## 🛡️ Konfigurasi Keamanan Lanjutan

### Generating Secure Credentials
```bash
# Generate JWT Secret Key
openssl rand -base64 32

# Generate SSL Keystore Password
openssl rand -base64 16
```

### Best Practices
- Gunakan password kompleks
- Rotasi kredensial secara berkala
- Simpan secret di password manager
- Gunakan environment variable

### Monitoring
- Aktifkan logging
- Monitor percobaan login
- Pantau rate limiting

🚨 ## 👨‍💻 Manajemen Insiden & Respons Keamanan

### 🛑 Protokol Mitigasi Risiko
1. **Deteksi Dini**
   - Monitoring real-time aktivitas sistem
   - Analisis log keamanan
   - Deteksi anomali dan perilaku mencurigakan

2. **Respons Cepat**
   - Isolasi sistem yang terinfeksi
   - Pembatasan akses
   - Dokumentasi kronologis insiden

3. **Pemulihan**
   - Backup berkala
   - Rencana pemulihan sistematis
   - Audit keamanan pasca-insiden

### 💻 Incident Response Team (IRT)
- **Struktur Tim**
  * Security Lead
  * Network Administrator
  * Forensic Analyst
  * Compliance Officer

### 🔎 Investigasi & Pelaporan
- Dokumentasi komprehensif
- Laporan forensik terperinci
- Rekomendasi perbaikan berkelanjutan

## 🌍 Manajemen Keamanan Lanjutan

### Penyimpanan Kredensial
1. **Produksi**
   - Gunakan secret management service
   - Contoh: AWS Secrets Manager, HashiCorp Vault
   - Rotasi kredensial secara berkala

2. **Development**
   - Gunakan `.env` file (tambahkan ke .gitignore)
   - Enkripsi file kredensial
   - Gunakan environment variable lokal
   - Gunakan password manager

### Best Practices
- Hindari hardcoded credentials
- Gunakan principle of least privilege
- Enkripsi sensitive data
- Logging untuk tracking perubahan

### Troubleshooting
- Cek environment variable: `echo $JWT_SECRET_KEY`
- Validasi input dengan log
- Gunakan mode debug untuk investigasi

### Contoh Konfigurasi Aman
```bash
# Generate random secret key
openssl rand -base64 32

# Set environment variable securely
export JWT_SECRET_KEY=$(openssl rand -base64 32)

# Aktifkan 2FA
export 2FA_ENABLED=true
export 2FA_SECRET_admin=$(openssl rand -base64 20)
```

### Konfigurasi 2FA
- Gunakan Google Authenticator atau Authy
- Scan QR Code yang diberikan
- Simpan backup code dengan aman
- Nonaktifkan 2FA jika kehilangan akses

### Monitoring
- Aktifkan logging keamanan
- Monitor percobaan login
- Set up alert untuk aktivitas mencurigakan

🛡️ **Keamanan adalah proses berkelanjutan, bukan produk akhir**
