use openssl::crypto::symm::Crypter;
use openssl::crypto::symm::Mode::{Encrypt, Decrypt};
use openssl::crypto::symm::Type::AES_128_ECB;
use rand;
//use std::rand::random;

pub fn encrypt_128(data: &[u8], key: &[u8]) -> Vec<u8> {
    // TODO: randomise iv
    let iv = vec![0; key.len()];
    let crypter = Crypter::new(AES_128_ECB);
    crypter.init(Encrypt, key, iv.as_slice());
    crypter.pad(false);
    let mut output = crypter.update(data);
    output.extend_from_slice(crypter.finalize().as_slice());
    output
}

pub fn decrypt_128(data: &[u8], key: &[u8]) -> Vec<u8> {
    // TODO: randomise iv
    let iv = vec![0; key.len()];
    let crypter = Crypter::new(AES_128_ECB);
    crypter.init(Decrypt, key, iv.as_slice());
    crypter.pad(false);
    let mut output = crypter.update(data);
    output.extend_from_slice(crypter.finalize().as_slice());
    output
}

pub fn generate_key(size: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(size as usize);
    for _ in 0..size {
        key.push(rand::random::<u8>());
    }
    key
}
