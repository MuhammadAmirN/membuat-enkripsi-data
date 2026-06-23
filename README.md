# 🔐 Hybrid Crypto App — Enkripsi & Dekripsi File

Aplikasi web sederhana berbasis **Flask** untuk mengenkripsi dan mendekripsi file menggunakan kombinasi **AES (simetris)** dan **RSA (asimetris)** — biasa disebut *hybrid encryption*. Setiap pengguna memiliki sepasang kunci RSA sendiri, dan file dapat dibagikan secara aman ke pengguna lain maupun ke semua pengguna.

## ✨ Fitur

- **Registrasi & Login** pengguna, lengkap dengan hashing password (Werkzeug).
- Setiap pendaftaran akun otomatis membuat **pasangan kunci RSA 2048-bit** (public & private key) untuk pengguna tersebut.
- **Upload file** yang langsung dienkripsi dengan **AES (mode EAX)** menggunakan kunci AES acak 128-bit.
- Kunci AES tersebut kemudian dienkripsi dengan **RSA Public Key** milik pemilik file (dan, bila dibagikan, dengan public key penerima juga) — inilah konsep *hybrid encryption*.
- **Berbagi file** ke pengguna tertentu atau ke seluruh pengguna ("ALL").
- **Download file terenkripsi** (ciphertext mentah) atau **dekripsi & download** file asli (hanya bisa dilakukan oleh pemilik atau penerima yang sah).
- Data pengguna & metadata file disimpan di **database MySQL** melalui SQLAlchemy.

## 🧠 Cara Kerja (Hybrid Encryption)

1. Saat upload, file dienkripsi dengan **AES** → menghasilkan `ciphertext`, `nonce`, dan `tag`.
2. Kunci AES (yang dipakai sekali pakai) dienkripsi dengan **RSA Public Key** pemilik file → menghasilkan `encrypted_key`.
3. Jika file dibagikan, kunci AES yang sama juga dienkripsi ulang dengan public key penerima → `encrypted_key_shared`.
4. Saat dekripsi, sistem memverifikasi hak akses, lalu men-dekripsi kunci AES menggunakan **RSA Private Key** milik pengguna yang berwenang, dan akhirnya men-dekripsi file dengan kunci AES tersebut.

## 🗂️ Struktur Proyek

```
membuat-enkripsi-data-main/
├── app.py                 # Aplikasi Flask utama (routing, model, logika upload/download)
├── crypto_utils.py        # Fungsi-fungsi enkripsi/dekripsi AES & RSA
├── requirements.txt       # Daftar dependensi Python
├── hybird__crypt.sql      # Skema database MySQL
├── static/style.css       # Styling tampilan
├── templates/
│   ├── login.html
│   ├── register.html
│   └── upload.html        # Dashboard utama (upload, daftar file)
├── keys/                  # Contoh file kunci/nonce/tag hasil enkripsi
└── uploads/                # Folder hasil file upload (dibuat otomatis)
```

## ⚙️ Teknologi

- **Python 3** & **Flask** — web framework
- **Flask-SQLAlchemy** — ORM database
- **PyMySQL** — driver MySQL
- **pycryptodome** — library kriptografi (AES, RSA)
- **Werkzeug** — hashing password
- **MySQL** — database

## 🚀 Instalasi & Menjalankan

### 1. Clone / extract proyek
```bash
cd membuat-enkripsi-data-main
```

### 2. Buat virtual environment (opsional tapi disarankan)
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### 3. Install dependensi
```bash
pip install -r requirements.txt
pip install flask_sqlalchemy pymysql
```
> Catatan: `requirements.txt` saat ini hanya mencantumkan `flask` dan `pycryptodome`. Pastikan juga menginstall `flask_sqlalchemy`, `pymysql`, dan `werkzeug` (biasanya sudah terpasang otomatis bersama Flask).

### 4. Siapkan database MySQL
Buat database bernama `hybird_crypt`, lalu import skema:
```bash
mysql -u root -p hybird_crypt < hybird__crypt.sql
```
Sesuaikan kredensial koneksi di `app.py` jika perlu:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/hybird_crypt'
```

### 5. Jalankan aplikasi
```bash
python app.py
```
Aplikasi akan berjalan di `http://127.0.0.1:5000`.

## 🖥️ Tampilan Aplikasi

### Halaman Login
![Login](shot_login.png)

### Halaman Registrasi
![Registrasi](shot_register.png)

### Dashboard (Upload & Enkripsi File)
![Dashboard](shot_dashboard.png)

## 🔒 Catatan Keamanan

- `app.secret_key` di kode masih berupa nilai statis (`'rahasia_sangat_aman'`) — **ganti dengan nilai rahasia yang kuat dan unik** sebelum digunakan di luar lingkungan pengembangan.
- Private key RSA disimpan langsung di database tanpa enkripsi tambahan — pada implementasi produksi sebaiknya dilindungi lebih lanjut (misalnya dienkripsi dengan password pengguna).
- Proyek ini ditujukan untuk **tujuan pembelajaran/demo** konsep hybrid encryption, bukan untuk produksi langsung.

## 👥 Kredit

Proyek dibuat untuk keperluan pembelajaran enkripsi data — *Hybrid Crypto App* © 2025, Kelompok 10.
