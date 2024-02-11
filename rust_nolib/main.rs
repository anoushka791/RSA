use rsa::{RsaPrivateKey, PaddingScheme, PublicKey};
use rand::rngs::OsRng;
use hex;

fn main() {
    // Create an instance of a random number generator
    let mut rng = OsRng;

    // Generate a pair of RSA private and public keys
    let (private_key, public_key) = generate_rsa_keys(&mut rng, 2048usize);

    // Define the plaintext message to be encrypted
    let message = b"Hello, RSA with OAEP padding!";

    // Display the original plaintext message
    display_message(message);

    // Encrypt the plaintext message using the RSA public key
    let encrypted_message = encrypt_with_rsa(&public_key, &mut rng, message);

    // Display the encrypted message in a hexadecimal format
    display_encrypted_message(&encrypted_message);

    // Decrypt the encrypted message using the RSA private key
    let decrypted_message = decrypt_with_rsa(&private_key, &encrypted_message);

    // Display the decrypted message, which should match the original plaintext
    display_decrypted_message(&decrypted_message);
}

// Generate RSA private and public keys
//
// # Arguments:
// * 'rng' - A mutable reference to a random number generator
// * 'bits' - The number of bits for the generated key (e.g., 2048, 4096)
//
// # Returns: A tuple containing the RSA private and public keys
fn generate_rsa_keys(rng: &mut OsRng, bits: usize) -> (RsaPrivateKey, rsa::RsaPublicKey) {
    let private_key = RsaPrivateKey::new(rng, bits).expect("Failed to generate the RSA private key");
    let public_key = private_key.to_public_key();
    (private_key, public_key)
}

// Display the given message as a UTF-8 string
//
// # Arguments
// * 'message' - A byte slice containing the message to be displayed

fn display_message(message: &[u8]) {
    println!("> plaintext: {}", String::from_utf8_lossy(message));
}

// Encrypt a given message using RSA with OAEP padding
//
// # Arguments
// * 'public_key' - A reference to the RSA public key used for encryption
// * 'rng' - A mutable reference to a random number generator
// * 'message' - A byte slice containing the message to be encrypted
//
// # Returns: A vector containing the encrypted message
fn encrypt_with_rsa(public_key: &rsa::RsaPublicKey, rng: &mut OsRng, message: &[u8]) -> Vec<u8> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    public_key.encrypt(rng, padding, message).expect("Failed to encrypt the message")
}

// Display the encrypted message in hexadecimal format
//
// # Arguments
// * 'encrypted_message' - A byte slice containing the encrypted message
fn display_encrypted_message(encrypted_message: &[u8]) {
    let encoded = hex::encode(encrypted_message);
    println!("> encrypted text with padding: {}", encoded);
}

// Decrypt a given encrypted message using RSA with OAEP padding
//
// # Arguments
// * 'private_key' - A reference to the RSA private key used for decryption
// * 'encrypted_message' - A byte slice containing the encrypted message to be decrypted
//
// # Returns: A vector containing the decrypted message
fn decrypt_with_rsa(private_key: &RsaPrivateKey, encrypted_message: &[u8]) -> Vec<u8> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    private_key.decrypt(padding, encrypted_message).expect("Failed to decrypt the message")
}

// Display the decrypted message as a UTF-8 string
//
// # Arguments
//* 'decrypted_message' - A byte slice containing the decrypted message
fn display_decrypted_message(decrypted_message: &[u8]) {
    println!("> decrypted text: {}", String::from_utf8_lossy(decrypted_message));
}
