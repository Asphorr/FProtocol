use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use base64::{decode, encode};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rsa::{pkcs8::DecodePublicKey, pkcs8::EncodePrivateKey, PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};

const AES_KEY_SIZE: usize = 32;
const RSA_KEY_SIZE: usize = 2048;
const HMAC_KEY_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let (priv_key, pub_key) = generate_rsa_keypair();
    let (session_key, shared_key) = ecdh_key_exchange();

    let secret_msg = "Classified Information";
    let encrypted = encrypt_message(secret_msg, &pub_key, &shared_key);
    let decrypted = decrypt_message(&encrypted, &priv_key, &shared_key);

    println!("Encrypted Message: {}", encrypted);
    println!("Decrypted Message: {}", decrypted);
}

// Generates an RSA key pair
fn generate_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE).expect("Failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

// Implements Elliptic Curve Diffie-Hellman (ECDH) key exchange
fn ecdh_key_exchange() -> (Scalar, [u8; AES_KEY_SIZE]) {
    let mut rng = OsRng;
    let private_key = Scalar::random(&mut rng);
    let public_key = RistrettoPoint::random(&mut rng) * private_key;
    
    // Simulate key exchange with another party
    let other_private_key = Scalar::random(&mut rng);
    let other_public_key = RistrettoPoint::random(&mut rng) * other_private_key;
    
    // Compute shared secret
    let shared_secret = (other_public_key * private_key).compress();
    let mut hasher = Sha512::new();
    hasher.update(shared_secret.as_bytes());
    let shared_key = hasher.finalize();
    
    let mut aes_key = [0u8; AES_KEY_SIZE];
    aes_key.copy_from_slice(&shared_key[0..AES_KEY_SIZE]);
    (private_key, aes_key)
}

// Encrypts a message using hybrid encryption (RSA + AES + HMAC)
fn encrypt_message(message: &str, pub_key: &RsaPublicKey, shared_key: &[u8; AES_KEY_SIZE]) -> String {
    let (aes_key, iv, cipher_text) = aes_encrypt_string(message, shared_key);
    let hmac_signature = hmac_sign(&cipher_text, shared_key);

    let mut data_to_encrypt = Vec::new();
    data_to_encrypt.extend_from_slice(&aes_key);
    data_to_encrypt.extend_from_slice(&iv);

    let mut rng = OsRng;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let encrypted_aes_key = pub_key
        .encrypt(&mut rng, padding, &data_to_encrypt)
        .expect("Failed to encrypt AES key");

    base64_encode(&[&encrypted_aes_key, &cipher_text, &hmac_signature])
}

// Decrypts a message using hybrid encryption (RSA + AES + HMAC)
fn decrypt_message(encrypted_data: &str, priv_key: &RsaPrivateKey, shared_key: &[u8; AES_KEY_SIZE]) -> String {
    let decoded_data = base64_decode(encrypted_data);
    let (encrypted_aes_key, cipher_text, hmac_signature) = split_encrypted_data(&decoded_data);

    let padding = PaddingScheme::new_oaep::<Sha256>();
    let decrypted_aes_key_iv = priv_key
        .decrypt(padding, encrypted_aes_key)
        .expect("Failed to decrypt AES key");

    let (aes_key, iv) = split_aes_key_iv(&decrypted_aes_key_iv);

    // Verify HMAC signature
    hmac_verify(&cipher_text, hmac_signature, shared_key);

    aes_decrypt_string(cipher_text, aes_key, iv)
}

// Encrypts a string using AES-256
fn aes_encrypt_string(message: &str, shared_key: &[u8; AES_KEY_SIZE]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let aes_key = obscure_random_bytes(AES_KEY_SIZE);
    let iv = obscure_random_bytes(16);
    let cipher = Aes256::new(GenericArray::from_slice(&aes_key));
    let mut block = GenericArray::clone_from_slice(message.as_bytes());
    cipher.encrypt_block(&mut block);
    (aes_key, iv, block.to_vec())
}

// Decrypts a string using AES-256
fn aes_decrypt_string(cipher_text: &[u8], aes_key: &[u8], iv: &[u8]) -> String {
    let cipher = Aes256::new(GenericArray::from_slice(aes_key));
    let mut block = GenericArray::clone_from_slice(cipher_text);
    cipher.decrypt_block(&mut block);
    String::from_utf8(block.to_vec()).expect("Invalid UTF-8 data")
}

// Signs data using HMAC-SHA256
fn hmac_sign(data: &[u8], shared_key: &[u8; AES_KEY_SIZE]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(shared_key).expect("Invalid HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// Verifies the HMAC signature
fn hmac_verify(data: &[u8], signature: &[u8], shared_key: &[u8; AES_KEY_SIZE]) {
    let mut mac = HmacSha256::new_from_slice(shared_key).expect("Invalid HMAC key");
    mac.update(data);
    mac.verify_slice(signature).expect("Invalid HMAC signature");
}

// Generates a random byte array of a given size
fn obscure_random_bytes(size: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut bytes = vec![0; size];
    rng.fill_bytes(&mut bytes);
    bytes
}

// Base64 encodes multiple byte arrays into a single string
fn base64_encode(parts: &[&[u8]]) -> String {
    let mut combined = Vec::new();
    for part in parts {
        combined.extend_from_slice(part);
    }
    encode(&combined)
}

// Base64 decodes a string into a byte array
fn base64_decode(encoded: &str) -> Vec<u8> {
    decode(encoded).expect("Invalid base64 string")
}

// Splits the combined byte array into the encrypted AES key, ciphertext, and HMAC signature
fn split_encrypted_data(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let encrypted_key_size = RSA_KEY_SIZE / 8;
    let hmac_signature_size = 32;
    let (encrypted_aes_key, rest) = data.split_at(encrypted_key_size);
    let (cipher_text, hmac_signature) = rest.split_at(rest.len() - hmac_signature_size);
    (encrypted_aes_key, cipher_text, hmac_signature)
}

// Splits the combined byte array into the AES key and IV
fn split_aes_key_iv(data: &[u8]) -> (&[u8], &[u8]) {
    let (key, rest) = data.split_at(AES_KEY_SIZE);
    let (iv, _) = rest.split_at(16);
    (key, iv)
}
