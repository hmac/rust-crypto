use openssl::crypto::symm::Crypter;
use openssl::crypto::symm::Mode::{Encrypt, Decrypt};
use openssl::crypto::symm::Type::AES_128_ECB;

pub fn encrypt_128(data: &[u8], key: &[u8]) -> Vec<u8> {
    // TODO: randomise iv
    let iv = Vec::from_elem(key.len(), 0);
    let crypter = Crypter::new(AES_128_ECB);
    crypter.init(Encrypt, key.as_slice(), iv);
    crypter.pad(false);
    let mut output = crypter.update(data.as_slice());
    output.push_all(crypter.finalize().as_slice());
    output
}

pub fn decrypt_128(data: &[u8], key: &[u8]) -> Vec<u8> {
    // TODO: randomise iv
    let iv = Vec::from_elem(key.len(), 0);
    let crypter = Crypter::new(AES_128_ECB);
    crypter.init(Decrypt, key.as_slice(), iv);
    crypter.pad(false);
    let mut output = crypter.update(data.as_slice());
    output.push_all(crypter.finalize().as_slice());
    output
}
