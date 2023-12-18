use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce, Key
};
use anyhow::Result;

pub fn gen_nonce() -> XNonce {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 192-bits; unique per message

    return nonce;
}

pub fn gen_key() -> Key {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    return key;
}

pub fn str_to_key(key_string: &[u8]) -> Key {
    let key = Key::from_slice(key_string);
    return *key
}

pub fn str_to_nonce(key_string: &[u8]) -> XNonce {
    let nonce = XNonce::from_slice(key_string);
    return *nonce
}

pub fn encrypt(nonce: XNonce, key: Key, plaintext: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(&key);
    match cipher.encrypt(&nonce, plaintext) {
        Ok(ciphertext) => Ok(ciphertext),
        Err(e) => Err(e),
    }
 }
 
 pub fn decrypt(nonce: XNonce, key: Key, ciphertext: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(&key);
    match cipher.decrypt(&nonce, ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(e),
    }
 }