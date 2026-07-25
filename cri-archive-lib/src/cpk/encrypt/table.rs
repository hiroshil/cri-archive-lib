//! CRI @UTF table XOR cipher.

#[derive(Debug)]
pub struct TableDecryptor;

impl TableDecryptor {
    const ENCRYPTED_PREFIX: [u8; 4] = [0x1f, 0x9e, 0xf3, 0xf5];

    pub fn is_encrypted(bytes: &[u8]) -> bool {
        bytes.starts_with(&Self::ENCRYPTED_PREFIX)
    }

    pub fn decrypt_utf(input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        Self::decrypt_utf_in_place(&mut result);
        result
    }

    pub fn decrypt_utf_in_place(input: &mut [u8]) {
        let mut key = 0x5fu8;
        for byte in input {
            *byte ^= key;
            key = key.wrapping_mul(0x15);
        }
    }
}
