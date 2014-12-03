use openssl::crypto::symm::Crypter;
use openssl::crypto::symm::Mode::{Encrypt, Decrypt};
use openssl::crypto::symm::Type::AES_128_ECB;

pub fn encrypt(data: &[u8], key: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let len: u8 = 16;
    let padded_key = pad_block(key, len);

    let crypter = Crypter::new(AES_128_ECB);
    crypter.init(Encrypt, padded_key.as_slice(), iv.clone());
    crypter.pad(false);

    let pt_blocks = to_blocks(data, len);
    let mut ciphertext: Vec<Vec<u8>> = Vec::new();
    let mut cipherblock = iv;
    for block in pt_blocks.iter() {
        cipherblock = xor(cipherblock.as_slice(), block.as_slice());
        cipherblock = crypter.update(cipherblock.as_slice());
        ciphertext.push(cipherblock.clone());
    }
    return ciphertext.as_slice().concat_vec()
}

pub fn decrypt(data: &[u8], key: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let len: u8 = 16;
    let padded_key = pad_block(key, len);

    let ct_blocks = to_blocks(data, len);

    let crypter = Crypter::new(AES_128_ECB);
    crypter.init(Decrypt, padded_key.as_slice(), iv.clone());
    crypter.pad(false);

    let mut plaintext: Vec<Vec<u8>> = Vec::new();
    let mut ct_block = iv;
    for block in ct_blocks.iter() {
        let decrypted_block = crypter.update(block.as_slice());
        let xor_block = xor(ct_block.as_slice(), decrypted_block.as_slice()); 
        plaintext.push(xor_block.clone());
        ct_block = block.clone();
    }
    return plaintext.as_slice().concat_vec()
}

// Holds all bytes of a ciphertext/plaintext, and implements Iterator that
// allows the bytes to be iterated over in blocks of given blocksize.
// NOTE: data must be reversed
struct BlockVector {
    data: Vec<u8>,
    blocksize: u8
}

impl Iterator<Vec<u8>> for BlockVector {
    fn next(&mut self) -> Option<Vec<u8>> {
        if self.data.len() == 0 {
            return None;
        }
        let mut next_block = Vec::new();
        for _ in range(0, self.blocksize) {
            let b = self.data.pop();
            if b.is_none() {
                break;
            }
            next_block.push(b.unwrap());
        }
        return Some(next_block);
    }
}

fn to_blocks(data: &[u8], length: u8) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut padded_data = pad_block(data, length);
    padded_data.reverse(); // This allows us to optimise BlockVector
    let mut block_vec = BlockVector {data: padded_data, blocksize: 16};

    for block in block_vec {
        blocks.push(block);
    }

    blocks.clone()
}

fn pad_block(block: &[u8], length: u8) -> Vec<u8> {
    let block_len: u8 = block.len().to_u8().unwrap_or(0);
    if block_len % length == 0 {
        return block.to_vec();
    }
    let padding_len: u8 = if block_len < length {
        length - block_len
    } else {
        length - (block_len % length)
    };
    let mut v = Vec::new();
    for b in block.iter() {
        v.push(b.clone());
    }
    for _ in range(0, padding_len) {
        v.push(padding_len);
    }
    v.clone()
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(_a, _b)| {
    *_a ^ *_b
  }).collect::<Vec<u8>>()
}
