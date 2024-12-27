import time
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes

sys.setrecursionlimit(6899) 

# mengukur waktu eksekusi
def measure_time(func, *args):
    start_time = time.time()
    result = func(*args)
    return time.time() - start_time, result

# Implementasi Iteratif
def modular_exponentiation_iterative(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

# Implementasi Rekursif
def modular_exponentiation_recursive(base, exp, mod):
    if exp == 0:
        return 1
    elif exp == 1:
        return base % mod
    half = modular_exponentiation_recursive(base, exp // 2, mod)
    half = (half * half) % mod
    if exp % 2 != 0:
        half = (half * base) % mod
    return half

# Fungsi dummy untuk ECC recursive simulation (penggandaan titik)
def ecc_point_multiplication_recursive(point, scalar):
    if scalar == 0:
        return None  # Titik di "infinity"
    elif scalar == 1:
        return point
    elif scalar % 2 == 0:
        half = ecc_point_multiplication_recursive(point, scalar // 2)
        return half + half  # Penjumlahan titik pada ECC
    else:
        half = ecc_point_multiplication_recursive(point, scalar // 2)
        return half + half + point

# Fungsi dummy untuk ECC iterative simulation
def ecc_point_multiplication_iterative(point, scalar):
    result = None
    addend = point

    while scalar > 0:
        if scalar % 2 == 1:
            result = result + addend if result else addend
        addend = addend + addend
        scalar //= 2

    return result

# Ukuran kunci yang diuji
key_sizes = [1024, 2048, 4096]

# Hasil pengukuran RSA
rsa_encrypt_times_iter = []
rsa_decrypt_times_iter = []
rsa_encrypt_times_rec = []
rsa_decrypt_times_rec = []

ecc_encrypt_times_iter = []
ecc_decrypt_times_iter = []
ecc_encrypt_times_rec = []
ecc_decrypt_times_rec = []

# Uji RSA
for key_size in key_sizes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    message = b"Test message RSA"

    # RSA Enkripsi (Iteratif)
    enc_time, _ = measure_time(modular_exponentiation_iterative, 2, 65537, 2 ** key_size)
    rsa_encrypt_times_iter.append(enc_time)

    # RSA Dekripsi (Iteratif)
    dec_time, _ = measure_time(modular_exponentiation_iterative, 2, private_key.private_numbers().d, 2 ** key_size)
    rsa_decrypt_times_iter.append(dec_time)

    # RSA Enkripsi (Rekursif)
    enc_time, _ = measure_time(modular_exponentiation_recursive, 2, 65537, 2 ** key_size)
    rsa_encrypt_times_rec.append(enc_time)

    # RSA Dekripsi (Rekursif)
    dec_time, _ = measure_time(modular_exponentiation_recursive, 2, private_key.private_numbers().d, 2 ** key_size)
    rsa_decrypt_times_rec.append(dec_time)

# Uji ECC
for key_size in key_sizes:
    private_key = ec.generate_private_key(ec.SECP256R1())  # Kurva Elliptik
    public_key = private_key.public_key()
    point = (1, 2)  # Dummy point untuk simulasi

    # ECC Enkripsi (Iteratif)
    enc_time, _ = measure_time(ecc_point_multiplication_iterative, point, key_size)
    ecc_encrypt_times_iter.append(enc_time)

    # ECC Dekripsi (Iteratif)
    dec_time, _ = measure_time(ecc_point_multiplication_iterative, point, key_size)
    ecc_decrypt_times_iter.append(dec_time)

    # ECC Enkripsi (Rekursif)
    enc_time, _ = measure_time(ecc_point_multiplication_recursive, point, key_size)
    ecc_encrypt_times_rec.append(enc_time)

    # ECC Dekripsi (Rekursif)
    dec_time, _ = measure_time(ecc_point_multiplication_recursive, point, key_size)
    ecc_decrypt_times_rec.append(dec_time)

# Plot Hasil
import matplotlib.pyplot as plt

plt.figure(figsize=(15, 10))

# RSA Grafik
plt.subplot(2, 2, 1)
plt.plot(key_sizes, rsa_encrypt_times_iter, label="Iterative RSA Encrypt", marker='o')
plt.plot(key_sizes, rsa_encrypt_times_rec, label="Recursive RSA Encrypt", marker='o')
plt.xlabel("Key Size (bits)")
plt.ylabel("Time (seconds)")
plt.title("RSA Encryption Time")
plt.legend()
plt.grid()

plt.subplot(2, 2, 2)
plt.plot(key_sizes, rsa_decrypt_times_iter, label="Iterative RSA Decrypt", marker='o')
plt.plot(key_sizes, rsa_decrypt_times_rec, label="Recursive RSA Decrypt", marker='o')
plt.xlabel("Key Size (bits)")
plt.ylabel("Time (seconds)")
plt.title("RSA Decryption Time")
plt.legend()
plt.grid()

# ECC Grafik
plt.subplot(2, 2, 3)
plt.plot(key_sizes, ecc_encrypt_times_iter, label="Iterative ECC Encrypt", marker='o')
plt.plot(key_sizes, ecc_encrypt_times_rec, label="Recursive ECC Encrypt", marker='o')
plt.xlabel("Key Size (bits)")
plt.ylabel("Time (seconds)")
plt.title("ECC Encryption Time")
plt.legend()
plt.grid()

plt.subplot(2, 2, 4)
plt.plot(key_sizes, ecc_decrypt_times_iter, label="Iterative ECC Decrypt", marker='o')
plt.plot(key_sizes, ecc_decrypt_times_rec, label="Recursive ECC Decrypt", marker='o')
plt.xlabel("Key Size (bits)")
plt.ylabel("Time (seconds)")
plt.title("ECC Decryption Time")
plt.legend()
plt.grid()

plt.tight_layout()
plt.show()
