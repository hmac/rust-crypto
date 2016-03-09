// PKCS#7 Padding
// Pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.
// e.g. "YELLOW SUBMARINE" padded to 20 bytes becomes "YELLOW SUBMARINE\x04\x04\x04\x04"

pub fn pad(block: &[u8], length: u8) -> Vec<u8> {
    let block_len = block.len() as u8;
    let padding_len = if block_len < length {
        length - block_len
    } else { 0 };
    let mut v = Vec::new();
    for b in block.iter() {
        v.push(b.clone());
    }
    for _ in 0..padding_len {
        v.push(padding_len);
    }
    v
}
