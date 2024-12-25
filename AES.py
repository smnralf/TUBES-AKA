import time
import random
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes

# Fungsi untuk mengukur waktu enkripsi
def measure_time(func, *args):
    start_time = time.time()
    result = func(*args)
    return time.time() - start_time, result

# Ukuran kunci yang diuji
key_sizes = [1024, 2048, 4096]

# Hasil pengukuran RSA
rsa_encrypt_times = []
rsa_decrypt_times = []
ecc_encrypt_times = []
ecc_decrypt_times = []

# Uji RSA
for key_size in key_sizes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    message = b"Test message RSA"

    # RSA Enkripsi
    enc_time, ciphertext = measure_time(public_key.encrypt, message, PKCS1v15())
    rsa_encrypt_times.append(enc_time)

    # RSA Dekripsi
    dec_time, plaintext = measure_time(private_key.decrypt, ciphertext, PKCS1v15())
    rsa_decrypt_times.append(dec_time)

# Uji ECC
for key_size in key_sizes:
    private_key = ec.generate_private_key(ec.SECP256R1())  # Kurva Elliptik
    public_key = private_key.public_key()
    message = b"Test message ECC"

    # ECC Enkripsi (simulasi dengan hashing)
    enc_time, ciphertext = measure_time(public_key.public_numbers)
    ecc_encrypt_times.append(enc_time)

    # ECC Dekripsi (simulasi)
    dec_time, plaintext = measure_time(private_key.private_numbers)
    ecc_decrypt_times.append(dec_time)

# Plot Hasil
import matplotlib.pyplot as plt

plt.figure(figsize=(10, 5))

# RSA Grafik
plt.subplot(1, 2, 1)
plt.plot(key_sizes, rsa_encrypt_times, label="RSA Encrypt Time", marker='o')
plt.plot(key_sizes, rsa_decrypt_times, label="RSA Decrypt Time", marker='o')
plt.xlabel("Key Size (bits)")
plt.ylabel("Time (seconds)")
plt.title("RSA Encryption/Decryption Time")
plt.legend()
plt.grid()

# ECC Grafik
plt.subplot(1, 2, 2)
plt.plot(key_sizes, ecc_encrypt_times, label="ECC Encrypt Time", marker='o')
plt.plot(key_sizes, ecc_decrypt_times, label="ECC Decrypt Time", marker='o')
plt.xlabel("Key Size (bits)")
plt.ylabel("Time (seconds)")
plt.title("ECC Encryption/Decryption Time")
plt.legend()
plt.grid()

plt.tight_layout()
plt.show()
