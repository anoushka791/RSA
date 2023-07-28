# RSA
# Public Key Encryption/Decryption in Python

This repository contains a Python implementation of a public key encryption and decryption scheme. The code uses the RSA algorithm for encryption and decryption, which is a widely-used asymmetric cryptographic algorithm.

## How It Works

The code consists of several functions that perform different steps of the encryption and decryption process:

1. `generate_prime(bits)`: This function generates a random prime number with the specified number of bits.

2. `is_probable_prime(n, k=5)`: A primality test function that checks whether a given number is probably prime. It uses the Miller-Rabin primality test with `k` iterations for increased accuracy.

3. `gcd(a, b)`: Calculates the greatest common divisor (GCD) of two numbers using the Euclidean algorithm.

4. `mod_inverse(a, m)`: Computes the modular multiplicative inverse of `a` modulo `m` using the extended Euclidean algorithm.

5. `generate_key_pair(bit_length)`: Generates a public-private key pair using RSA. It generates two random prime numbers `p` and `q`, calculates the public modulus `n`, and the private exponent `d`.

6. `pad_for_encryption(message, block_size)`: Pads the input message to a multiple of the block size for encryption. It uses random padding to prevent deterministic attacks.

7. `pad_for_decryption(padded_message, block_size)`: Removes the padding from the decrypted message after decryption.

8. `encrypt_string(message, public_key)`: Encrypts a given string using the public key.

9. `decrypt_string(encrypted_data, private_key)`: Decrypts the encrypted data using the private key.

## How to Use

1. Clone the repository and navigate to the directory.

2. Run the `main.py` script using Python: `python main.py`

3. Enter the string you want to encrypt when prompted.

4. The script will generate a public-private key pair, encrypt the input string using the public key, and then decrypt it using the private key.

## Security Considerations

The security of RSA encryption relies on the difficulty of factoring large composite numbers. The security level can be adjusted by changing the `bit_length` parameter in the `generate_key_pair` function. Higher bit lengths increase security but also require more computational resources.

It's important to use a secure random number generator for cryptographic operations. The `random` module in Python is used in this code, which should be sufficient for demonstration purposes. In a production environment, a cryptographic-strength random number generator should be used.

Please note that this implementation is for educational and demonstration purposes only and should not be used for production-level security. In real-world applications, it is recommended to use established cryptographic libraries and tools that have been thoroughly tested and audited for security.

Feel free to explore and experiment with the code. If you have any questions or suggestions, please don't hesitate to create an issue or reach out!

Happy encrypting and decrypting!
