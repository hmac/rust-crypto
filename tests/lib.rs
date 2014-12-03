extern crate crypto;
extern crate serialize;
use serialize::hex::FromHex;
use crypto::aes::ecb;
use crypto::aes::cbc;
use crypto::pkcs7;

fn dehex(hex: &str) -> Vec<u8> {
    hex.from_hex().ok().expect("hex conversion failed")
}

// ECB
#[test]
fn test_encrypt_128() {
    let pt = dehex("1695fe475421cace3557daca01f445ff");
    let key = dehex("edfdb257cb37cdf182c5455b0c0efebb");
    let expected_ct = dehex("7888beae6e7a426332a7eaa2f808e637");
    let ct = ecb::encrypt_128(pt.as_slice(), key.as_slice());
    println!("{}", ct);
    println!("{}", expected_ct);
    assert!(ct == expected_ct);
}

#[test]
fn test_decrypt_128() {
    let key = dehex("54b760dd2968f079ac1d5dd20626445d");
    let ct = dehex("065bd5a9540d22d5d7b0f75d66cb8b30");
    let expected_pt = dehex("46f2c98932349c338e9d67f744a1c988");
    let pt = ecb::decrypt_128(ct.as_slice(), key.as_slice());
    println!("{}", pt);
    println!("{}", expected_pt);
    assert!(pt == expected_pt);
}


// CBC
#[test]
fn test_encrypt() {
    // 1 block
    let pt = dehex("45cf12964fc824ab76616ae2f4bf0822");
    let key = dehex("1f8e4973953f3fb0bd6b16662e9a3c17");
    let iv = dehex("2fe2b333ceda8f98f4a99b40d2cd34a8");
    let expected_ct = dehex("0f61c4d44c5147c03c195ad7e2cc12b2");
    let ct = cbc::encrypt(pt.as_slice(), key.as_slice(), iv);
    println!("{}", ct);
    println!("{}", expected_ct);
    assert!(ct == expected_ct);

    // 2 blocks
    let key = dehex("0700d603a1c514e46b6191ba430a3a0c");
    let iv = dehex("aad1583cd91365e3bb2f0c3430d065bb");
    let pt = dehex("068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91");
    let expected_ct = dehex("c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00");
    let ct = cbc::encrypt(pt.as_slice(), key.as_slice(), iv);
    println!("{}", ct);
    println!("{}", expected_ct);
    assert!(ct == expected_ct);
}

#[test]
fn test_decrypt() {
    // 1 block
    let key = dehex("6a7082cf8cda13eff48c8158dda206ae");
    let iv = dehex("bd4172934078c2011cb1f31cffaf486e");
    let ct = dehex("f8eb31b31e374e960030cd1cadb0ef0c");
    let expected_pt = dehex("940bc76d61e2c49dddd5df7f37fcf105");
    let pt = cbc::decrypt(ct.as_slice(), key.as_slice(), iv);
    println!("{}", pt);
    println!("{}", expected_pt);
    assert!(pt == expected_pt);

    // 2 blocks
    let key = dehex("625eefa18a4756454e218d8bfed56e36");
    let iv = dehex("73d9d0e27c2ec568fbc11f6a0998d7c8");
    let ct = dehex("5d6fed86f0c4fe59a078d6361a142812514b295dc62ff5d608a42ea37614e6a1");
    let expected_pt = dehex("360dc1896ce601dfb2a949250067aad96737847a4580ede2654a329b842fe81e");
    let pt = cbc::decrypt(ct.as_slice(), key.as_slice(), iv);
    println!("{}", pt);
    println!("{}", expected_pt);
    assert!(pt == expected_pt);
}

// PKCS#7
#[test]
fn test_padding() {
    assert!(pkcs7::pad(&[0u8], 2) == vec![0u8, 1]);
    assert!(pkcs7::pad(&[0u8], 1) == vec![0u8]);
    let expected = ("YELLOW SUBMARINE".as_bytes()).to_vec() + vec![4,4,4,4];
    assert!(pkcs7::pad("YELLOW SUBMARINE".as_bytes(), 20) == expected)
}