# import library

import os
from cryptography.fernet import Fernet

# inisialisasi file

files = []

for  file in os.listdir():
        if file == "Encrypt.py" or file == "kunci.key" or file == "Decrypt.py":
                continue
        if os.path.isfile(file):
                files.append(file)
print(files)

with open("kunci.key", "rb") as kunci:
        kunci_rahasia = kunci.read()

for file in files:
        with open(file, "rb") as batu:
                content = batu.read()
        content_deskripsi = Fernet(kunci_rahasia).decrypt(content)
        with open(file, "wb") as batu:
                batu.write(content_deskripsi)
