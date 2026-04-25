# Rnsm-Fernet

simulasi enkripsi dan dekripsi file menggunakan library `cryptography`.

## Deskripsi File

* **Encrypt.py**
  Script untuk mengenkripsi file dalam direktori menggunakan metode Fernet (symmetric encryption).

* **Decrypt.py**
  Script untuk mendekripsi file yang telah dienkripsi menggunakan kunci yang sama.

* **Hibrida.py**
  Script simulasi enkripsi file menggunakan metode hibrida (AES untuk data dan RSA untuk enkripsi kunci).

## Kebutuhan

* Python 3.x
* Library `cryptography`

Install dependency:

```bash
pip install cryptography
```

## Cara Menjalankan

### Enkripsi File (Fernet)

```bash
python Encrypt.py
```

### Dekripsi File

```bash
python Decrypt.py
```

### Enkripsi Hibrida (AES + RSA)

```bash
python Hibrida.py
```

Masukkan path target saat diminta oleh program.

## Catatan

Disarankan menjalankan script pada folder uji atau lingkungan laboratorium.
Jangan dijalankan pada direktori sistem atau data penting.

## Tujuan Pembelajaran

* Memahami konsep enkripsi file
* Mengenal penggunaan Fernet (symmetric encryption)
* Memahami metode enkripsi hibrida (AES dan RSA)
* Mempelajari simulasi dasar workflow enkripsi file

