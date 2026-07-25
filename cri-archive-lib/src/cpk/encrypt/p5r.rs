//! Implementation rewritten from the original CriFsV2Lib in C#:
//! https://github.com/Sewer56/CriFsV2Lib/blob/master/CriFsV2Lib/Encryption/Game/P5RCrypto.cs
//!
//! In-place encryption mechanism used by Persona 5 Royal.
//! Present on PC and PS4 JP version (not used in US PS4).
//!
//! Basically:
//! - data[0x20..0x420] = data[0x20..0x420] ^ data[0x420..0x820]
//!
//! In human words:
//! - XOR the first 0x20-0x420 bytes with 0x420-0x820 bytes.
//!
//! Credit: Lipsum/Zarroboogs for providing the original reference decryption code.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m256i, _mm256_loadu_si256, _mm256_xor_si256, _mm256_storeu_si256,
    __m128i, _mm_loadu_si128, _mm_xor_si128, _mm_storeu_si128
};

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{ uint8x16_t, vld1q_u8, vst1q_u8, veorq_u8 };

use std::ptr::{ read_unaligned, write_unaligned };
use crate::cpk::encrypt::data::FileDecryptor;
use crate::cpk::file::CpkFile;

#[derive(Debug)]
pub struct P5RDecryptor;

impl FileDecryptor for P5RDecryptor {
    fn is_encrypted(file: &CpkFile, _stream: &[u8]) -> bool { file.user_string() == "CRI_CFATTR:ENCRYPT" }
    fn decrypt_in_place(input: &mut [u8]) {
        // Files shorter than 0x820 can't be "decrypted".
        // They aren't "encrypted" to begin with, even if they are marked with ENCRYPT user string
        if input.len() < 0x820 { return; }
        let input = &mut input[P5RDecryptor::ENCRYPTED_DATA_OFFSET..];
        if cfg!(target_arch = "x86_64") {
            if cfg!(target_feature = "avx2") {
                return Self::decrypt_in_place_avx2(input);
            } else if cfg!(target_feature = "sse3") {
                return Self::decrypt_in_place_sse3(input);
            }
        } else if cfg!(all(target_arch = "aarch64", target_feature = "neon")) {
            return Self::decrypt_in_place_neon(input);
        }
        Self::decrypt_in_place_u64(input);
    }
}

impl P5RDecryptor {
    // Offset of encrypted data.
    pub(crate) const ENCRYPTED_DATA_OFFSET: usize = 0x20;

    // Number of bytes to decrypt.
    const NUM_BYTES_TO_DECRYPT: usize = 0x400;

    #[cfg(target_arch = "x86_64")]
    const NEXT_BLOCK_AVX2: usize = Self::NUM_BYTES_TO_DECRYPT / size_of::<__m256i>(); // 0x20

    #[inline(always)]
    #[allow(unused_variables, unused_mut)]
    pub fn decrypt_in_place_avx2(input: &mut [u8]) {
        #[cfg(target_arch = "x86_64")]
        for i in 0..Self::NEXT_BLOCK_AVX2 {
            unsafe {
                let v = _mm256_loadu_si256((input.as_ptr() as *const __m256i).add(i));
                let n = _mm256_loadu_si256((input.as_ptr() as *const __m256i).add(i + Self::NEXT_BLOCK_AVX2));
                _mm256_storeu_si256((input.as_mut_ptr() as *mut __m256i).add(i) as _, _mm256_xor_si256(v, n));
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    const NEXT_BLOCK_SSE3: usize = Self::NUM_BYTES_TO_DECRYPT / size_of::<__m128i>(); // 0x40

    #[inline(always)]
    #[allow(unused_variables, unused_mut)]
    pub fn decrypt_in_place_sse3(input: &mut [u8]) {
        #[cfg(target_arch = "x86_64")]
        for i in 0..Self::NEXT_BLOCK_SSE3 {
            unsafe {
                let v = _mm_loadu_si128((input.as_ptr() as *const __m128i).add(i));
                let n = _mm_loadu_si128((input.as_ptr() as *const __m128i).add(i + Self::NEXT_BLOCK_SSE3));
                _mm_storeu_si128((input.as_mut_ptr() as *mut __m128i).add(i) as _, _mm_xor_si128(v, n));
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    const NEXT_BLOCK_NEON: usize = Self::NUM_BYTES_TO_DECRYPT / size_of::<uint8x16_t>(); // 0x40

    #[inline(always)]
    #[allow(unused_variables, unused_mut)]
    pub fn decrypt_in_place_neon(input: &mut [u8]) {
        #[cfg(target_arch = "aarch64")]
        // Untested. Anyone have a MacBook?
        for i in 0..Self::NEXT_BLOCK_NEON {
            unsafe {
                let v = vld1q_u8(input.as_ptr().add(i << 4));
                let n = vld1q_u8(input.as_ptr().add((i + Self::NEXT_BLOCK_NEON) << 4));
                vst1q_u8(input.as_mut_ptr().add(i << 4), veorq_u8(v, n));
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    const NEXT_BLOCK_U64: usize = Self::NUM_BYTES_TO_DECRYPT / size_of::<u64>(); // 0x80

    #[inline(always)]
    pub fn decrypt_in_place_u64(input: &mut [u8]) {
        #[cfg(target_arch = "x86_64")]
        for i in 0..Self::NEXT_BLOCK_U64 {
            // unsafe { *(input.as_ptr() as *mut u64).add(i)
            //     ^= *(input.as_ptr() as *const u64).add(i + Self::NEXT_BLOCK_U64); }
            // (LLVM generates the exact same assembly for this)
            unsafe { write_unaligned((input.as_ptr() as *mut u64).add(i),
                read_unaligned((input.as_ptr() as *mut u64).add(i)) ^
                    read_unaligned((input.as_ptr() as *mut u64).add(i + Self::NEXT_BLOCK_U64))
            )};
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::error::Error;
    use std::ops::{Deref, DerefMut};
    use crate::cpk::encrypt::p5r::P5RDecryptor;

    // #[repr(align(8))]
    #[derive(Debug, Clone)]
    pub struct P5RData([u8; 0x821]);
    impl P5RData {
        fn new() -> Self {
            Self(std::array::from_fn::<u8, 0x821, _>(|i| (i & 0xff) as u8))
        }
    }
    impl Deref for P5RData {
        type Target = [u8; 0x821];
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl DerefMut for P5RData {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[test]
    fn can_decrypt_p5r() -> Result<(), Box<dyn Error>> {
        let values = P5RData::new();
        let mut encrypted_avx2 = values.clone();
        let mut encrypted_sse3 = values.clone();
        let mut encrypted_u64 = values.clone();
        P5RDecryptor::decrypt_in_place_avx2(&mut encrypted_avx2[P5RDecryptor::ENCRYPTED_DATA_OFFSET..]);
        P5RDecryptor::decrypt_in_place_sse3(&mut encrypted_sse3[P5RDecryptor::ENCRYPTED_DATA_OFFSET..]);
        P5RDecryptor::decrypt_in_place_u64(&mut encrypted_u64[P5RDecryptor::ENCRYPTED_DATA_OFFSET..]);
        assert_eq!(&*encrypted_sse3, &*encrypted_avx2);
        assert_eq!(&*encrypted_u64, &*encrypted_avx2);
        P5RDecryptor::decrypt_in_place_avx2(&mut encrypted_avx2[P5RDecryptor::ENCRYPTED_DATA_OFFSET..]);
        P5RDecryptor::decrypt_in_place_sse3(&mut encrypted_sse3[P5RDecryptor::ENCRYPTED_DATA_OFFSET..]);
        P5RDecryptor::decrypt_in_place_u64(&mut encrypted_u64[P5RDecryptor::ENCRYPTED_DATA_OFFSET..]);
        assert_eq!(&*encrypted_avx2, &*values);
        assert_eq!(&*encrypted_sse3, &*values);
        assert_eq!(&*encrypted_u64, &*values);
        Ok(())
    }
}