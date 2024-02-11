use num_bigint::BigUint;
use sha2::{Digest, Sha256};

fn main() {
    let (public_key, private_key) = generate_rsa_keypair();
    let message = "Hello, RSA with OAEP padding!";
    let message_bytes = message.as_bytes();
    
    println!("Message length before encoding: {}", message_bytes.len());
    let encrypted = rsa_encrypt(&public_key, message_bytes);
    println!("Encoded message length: {}", encrypted.to_bytes_be().len());
    
    let decrypted_bytes = rsa_decrypt(&private_key, &encrypted);
    let decrypted_message = String::from_utf8(decrypted_bytes).unwrap();
    println!("Decrypted message: {}", decrypted_message);
}

struct RSAKey {
    n: BigUint,
    e: BigUint,
    d: BigUint,
}

// ... [Your existing functions here: mod_inverse, extended_gcd, generate_rsa_keypair, generate_prime, is_probable_prime, generate_random_bytes, generate_random_bigint] ...

fn oaep_encode(message: &[u8], n: &BigUint) -> BigUint {
    let k = ((n.bits() as usize + 7) / 8) as usize;
    let mut rng = rand::thread_rng();

    assert!(message.len() <= k - 41, "Message is too long for this key size and OAEP padding");

    let seed = generate_random_bytes(32, &mut rng); // SHA-256 output size
    let mut hasher = Sha256::new();
    hasher.update(&seed);
    let digest = hasher.finalize();
    let masked_seed = xor_bytes(&seed, &digest);

    let mut hasher = Sha256::new();
    hasher.update(&masked_seed);
    let digest = hasher.finalize();
    let padding = vec![0u8; k - message.len() - 33];
    let mut db = vec![0u8; 1];
    db.extend_from_slice(&digest);
    db.extend_from_slice(&padding);
    db.extend_from_slice(message);
    
    let masked_db = xor_bytes(&db, &digest);
    
    let mut encoded_message = vec![];
    encoded_message.extend_from_slice(&masked_seed);
    encoded_message.extend_from_slice(&masked_db);

    BigUint::from_bytes_be(&encoded_message)
}

fn oaep_decode(encoded_message: &BigUint, n: &BigUint) -> Vec<u8> {
    let k = ((n.bits() + 7) / 8) as usize;
    
    let mut encoded_message_bytes = encoded_message.to_bytes_be();
    if encoded_message_bytes.len() < 2 * k {
        let padding_len = 2 * k - encoded_message_bytes.len();
        let mut new_encoded_message_bytes = vec![0u8; padding_len];
        new_encoded_message_bytes.extend_from_slice(&encoded_message_bytes);
        encoded_message_bytes = new_encoded_message_bytes;
    }
    
    if encoded_message_bytes.len() > 2 * k || encoded_message_bytes.len() < k {
        panic!("Encoded message is not the expected length");
    }

    let (masked_seed_bytes, masked_db_bytes) = encoded_message_bytes.split_at(k);

    let mut hasher = Sha256::new();
    hasher.update(masked_seed_bytes);
    let digest = hasher.finalize();
    let seed = xor_bytes(masked_seed_bytes, &digest);
    
    let mut hasher = Sha256::new();
    hasher.update(&seed);
    let digest = hasher.finalize();
    let db = xor_bytes(masked_db_bytes, &digest);

    // Strip off the leading zeros and 1 byte.
    let message_start = db.iter().position(|&x| x == 1).unwrap_or_else(|| db.len()) + 1;

    db[message_start..].to_vec()
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

fn rsa_encrypt(public_key: &RSAKey, message: &[u8]) -> BigUint {
    let encoded_message = oaep_encode(message, &public_key.n);
    encoded_message.modpow(&public_key.e, &public_key.n)
}

fn rsa_decrypt(private_key: &RSAKey, encoded_message: &BigUint) -> Vec<u8> {
    let decoded_message = encoded_message.modpow(&private_key.d, &private_key.n);
    oaep_decode(&decoded_message, &private_key.n)
}
