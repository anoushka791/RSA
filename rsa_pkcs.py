# -*- coding: utf-8 -*-
"""rsa_pkcs.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1HKPxLYGFvuLJMXVvQyfGMDvQUeE3km9G
"""

import random

def is_probable_prime(n, k=5):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_probable_prime(num):
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_key_pair(bit_length):
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    while True:
        e = random.randint(2, phi_n)
        if gcd(e, phi_n) == 1:
            break

    d = mod_inverse(e, phi_n)
    return (e, n), (d, n)

def pad_for_encryption(message, block_size):
    padding_length = block_size - 3 - len(message)
    padding = bytes([random.randint(1, 255) for _ in range(padding_length)])
    return b'\x00\x02' + padding + b'\x00' + message

def pad_for_decryption(padded_message, block_size):
    assert padded_message[0] == 0 and padded_message[1] == 2
    padding_start = 2
    while padded_message[padding_start] != 0:
        padding_start += 1
    return padded_message[padding_start + 1:]

def encrypt_string(message, public_key):
    e, n = public_key
    block_size = (n.bit_length() + 7) // 8
    padded_message = pad_for_encryption(message.encode('utf-8'), block_size)
    num_blocks = len(padded_message) // block_size
    encrypted_data = []
    for i in range(num_blocks):
        block = padded_message[i*block_size : (i+1)*block_size]
        num = int.from_bytes(block, 'big')
        encrypted_block = pow(num, e, n)
        encrypted_data.append(encrypted_block)
    return encrypted_data

def decrypt_string(encrypted_data, private_key):
    d, n = private_key
    block_size = (n.bit_length() + 7) // 8
    padded_message = b''
    for encrypted_block in encrypted_data:
        decrypted_block = pow(encrypted_block, d, n).to_bytes(block_size, 'big')
        padded_message += decrypted_block
    decrypted_data = pad_for_decryption(padded_message, block_size)
    return decrypted_data.decode('utf-8')

if __name__ == "__main__":
    bit_length = 256  # You can adjust this for different security levels
    public_key, private_key = generate_key_pair(bit_length)

    message = input("Enter the string to encrypt: ")

    encrypted_data = encrypt_string(message, public_key)
    decrypted_data = decrypt_string(encrypted_data, private_key)

    print("Encrypted:", encrypted_data)
    print("Decrypted:", decrypted_data)