//! Implementation rewritten from the original CriFsV2Lib in C#:
//! https://github.com/Sewer56/CriFsV2Lib/blob/master/CriFsV2Lib/Compression/CriLayla.cs
//!
//! # Explanation of CRILayla
//!
//! ## General Structure
//! - LZSS based.  (offset & length pairs, can encode raw byte)
//! - At end of file is 0x100 of uncompressed data, this is data that will be start of file.
//!
//! ## Compression Details
//!
//! Block uses compression flag, if flag is set to 0, next 8 bits are copied to output raw.
//!
//! ```text
//!     1 ?????????
//!     |
//!     compression flag
//! ```
//!
//! Data is decompressed from end, i.e.
//! ```text
//!     *writePtr = ???
//!     writePtr--
//!
//!     We write the decompressed data from its end.
//! ```
//!
//! Copy Block
//! ```text
//!     1 aaaaaaaaaaaaa bbb
//!     | |             | variable length
//!     | 13 bits of offset
//!     compression flag
//! ```
//!
//! To get length we read in the following (fibbonaci) order i.e.
//!     - 2 bits (max 3)
//!     - 3 bits (max 7)
//!     - 5 bits (max 31)
//!     - 8 bits
//!
//! And add the length to existing length variable.
//! If the max value is returned, we read next number of bits in fib sequence, up to 8 bits. Then
//! read 8s until max value no longer returned.

use crate::cpk::free_list::FreeList;
use crate::from_slice;
use crate::utils::slice::FromSlice;
use crate::utils::endianness::LittleEndian;

static LAYLA_HEADER_MAGIC: u64 = 0x414C59414C495243; // CRILAYLA

static BIT_MASK: [u32; 16] = [
    0x0000, 0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f,
    0x00ff, 0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff
];

#[repr(C)]
#[derive(Debug)]
pub struct LaylaHeader {
    magic: u64,
    uncompressed_size: u32,
    uncompressed_header_offset: u32
}

impl LaylaHeader {
    pub fn from_stream(file: &[u8]) -> &Self {
        unsafe { &*(file.as_ptr() as *const Self) }
    }
}

#[derive(Debug)]
pub struct LaylaDecompressorCursor {
    cdata: *const u8,
    bits_left: usize
}

impl LaylaDecompressorCursor {
    pub fn new(cdata: *const u8, bits_left: usize) -> Self {
        Self { cdata, bits_left }
    }

    pub fn get_cdata(&self) -> *const u8 { self.cdata }

    pub fn get_bits_left(&self) -> usize { self.bits_left }

    #[inline]
    fn bit_mask(n: usize) -> u32 {
        unsafe { *BIT_MASK.get_unchecked(n) }
    }

    pub fn read_1(&mut self) -> bool {
        if self.bits_left != 0 {
            self.bits_left -= 1;
        } else {
            // path only used if bits_left == 0, faster than branchless equivalent
            self.cdata = unsafe { self.cdata.sub(1) };
            self.bits_left = 7;
        }
        (unsafe { *self.cdata } >> self.bits_left) & 1 != 0
    }

    pub fn read_13(&mut self) -> u32 {
        // Read first set.
        if self.bits_left == 0 {
            self.cdata = unsafe { self.cdata.sub(1) };
            self.bits_left = 8;
        }
        let mut bits = 13 - self.bits_left;
        let mut res = (unsafe { *self.cdata } as u32) & Self::bit_mask(self.bits_left);
        // bitsleft == 0 is guaranteed, so we reset to 8
        self.cdata = unsafe { self.cdata.sub(1) };
        self.bits_left = 8;
        // Read more from next byte.
        let bit_round = bits.min(self.bits_left);
        res = (res << bit_round) | (((unsafe { *self.cdata } as u32) >> (self.bits_left - bit_round)) & Self::bit_mask(bit_round));
        bits -= bit_round;
        // It's possible, we might need 3 reads in some cases so we keep unrolling
        if bits == 0 {
            self.bits_left -= bit_round;
            return res;
        }
        // Read byte if needed
        self.cdata = unsafe { self.cdata.sub(1) };
        self.bits_left = 8;
        // If there are more to read from next byte.
        res = (res << bits) | (((unsafe { *self.cdata } as u32) >> (self.bits_left - bits)) & Self::bit_mask(bits));
        self.bits_left -= bits;
        res
    }

    /*
    pub fn read_13(&mut self) -> u32 {
        let mut bits = 13;
        if self.bits_left == 0 {
            self.cdata = unsafe { self.cdata.sub(1) };
            self.bits_left = 8;
        }
        let mut res = 0;
        for _ in 0..3 {
            let bit_round = bits.min(self.bits_left);
            res = (res << bit_round) | (((unsafe { *self.cdata } as u32) >> (self.bits_left - bit_round)) & Self::bit_mask(bit_round));
            bits -= bit_round;
            // Early return if 13 bits cover 2 bytes
            if bits == 0 {
                self.bits_left -= bit_round;
                return res;
            }
            self.cdata = unsafe { self.cdata.sub(1) };
            self.bits_left = 8;
        }
        res
    }
    */

    pub fn read_8(&mut self) -> u8 {
        self.cdata = unsafe { self.cdata.sub(1) };
        if self.bits_left != 0 {
            // We must split between 2 reads if there are more to read from next byte.
            let extra_bit = 8 - self.bits_left;
            return ((unsafe { *self.cdata.add(1) } & (Self::bit_mask(self.bits_left) as u8)) << extra_bit) // high bit
                | ((unsafe { *self.cdata } >> (8 - extra_bit)) & (Self::bit_mask(extra_bit) as u8)); // low bit
        }
        unsafe { *self.cdata }
    }

    const READ_2_BITS: usize = 2;

    pub fn read_2(&mut self) -> u8 {
        let new_byte = self.bits_left == 0;
        // fast/common path
        if self.bits_left >= Self::READ_2_BITS || new_byte {
            self.bits_left = if new_byte { 6 } else { self.bits_left - 2 };
            self.cdata = unsafe { self.cdata.sub(new_byte as usize) };
            // We removed from bits_left above, so we don't subtract here. This is necessary because branchless.
            return unsafe { (*self.cdata >> self.bits_left) & 3 };
        }
        // Only possible scenario is if bits_left == 1
        // bits_left == 0 & bits_left == 2 will take fast path.
        let result = unsafe { ((*self.cdata & 1) << 1) | (*self.cdata.sub(1) >> 7) };
        self.bits_left = 7; // Guaranteed
        self.cdata = unsafe { self.cdata.sub(1) };
        result
    }

    pub fn read_max_8(&mut self, mut bits: usize) -> u8 {
        self.cdata = unsafe { self.cdata.sub((self.bits_left == 0) as usize) };
        if self.bits_left == 0 { self.bits_left = 8; }
        let mut res = 0;
        for _ in 0..2 {
            let bit_round = bits.min(self.bits_left);
            res = (res << bit_round) | ((unsafe { *self.cdata } >> (self.bits_left - bit_round)) & (Self::bit_mask(bit_round) as u8));
            bits -= bit_round;
            // Early return if n bits cover 1 byte
            if bits == 0 {
                self.bits_left -= bit_round;
                return res;
            }
            self.cdata = unsafe { self.cdata.sub(1) };
            self.bits_left = 8;
        }
        res
    }
}

#[derive(Debug)]
pub(crate) struct LaylaDecompressorImpl<'a> {
    header: &'a LaylaHeader,
    input: &'a [u8],
    output: &'a mut [u8]
}

impl<'a> LaylaDecompressorImpl<'a> {
    // Minimum length of LZ77 copy command.
    const MIN_COPY_LENGTH: usize = 3;

    pub fn new(header: &'a LaylaHeader, input: &'a [u8], output: &'a mut [u8]) -> Self {
        Self { header, input, output }
    }

    const DEFAULT_PIPELINE_LENGTH: usize = 3;
    const EXTRA_PIPELINE_LENGTH: usize = 8;

    pub fn decompress(&mut self) {
        // Copy uncompressed 0x100 header (after compressed data) to start of file
        let uncmp_data = unsafe { self.input.as_ptr().add(
            self.header.uncompressed_header_offset as usize) };
        unsafe { std::ptr::copy_nonoverlapping(uncmp_data, self.output.as_mut_ptr(), LaylaDecompressor::UNCOMPRESSED_DATA_SIZE) };
        // Pointer to which we're copying data to.
        let (mut pwrite, pmin) = unsafe { (
            self.output.as_mut_ptr()
                .add(LaylaDecompressor::UNCOMPRESSED_DATA_SIZE + self.header.uncompressed_size as usize - 1),
            self.output.as_ptr().add(LaylaDecompressor::UNCOMPRESSED_DATA_SIZE)) };
        // Bitstream State
        let mut cursor = LaylaDecompressorCursor::new(uncmp_data, 0);
        while pwrite as usize >= pmin as usize {
            if cursor.read_1() { // Check for compression flag
                let offset = cursor.read_13() as usize + Self::MIN_COPY_LENGTH;
                let mut length = Self::MIN_COPY_LENGTH;
                // Read variable fibonnaci length (unrolled).
                let this_level = cursor.read_2();
                length += this_level as usize;
                if this_level == 3 {
                    let this_level = cursor.read_max_8(3);
                    length += this_level as usize;
                    if this_level == 7 {
                        let this_level = cursor.read_max_8(5);
                        length += this_level as usize;
                        if this_level == 0x1f {
                            loop {
                                let this_level = cursor.read_8();
                                length += this_level as usize;
                                if this_level != u8::MAX { break; }
                            }
                        }
                    }
                }
                // LZ77 Copy Below.

                // The optimal way to write this loop depends on average length of copy,
                // and average length of copy depends on the data we're dealing with.

                // As such, this would vary per files.
                // For text, length tends to be around 6 on average, for models around 9.
                // In this implementation we'll put bias towards short copies where length < 10.

                // Note: Min length is 3 (also seems to be most common length), so we can keep that out of the
                // loop and make best use of pipelining.
                unsafe {
                    *pwrite = *pwrite.add(offset);
                    *(pwrite.sub(1)) = *(pwrite.sub(1).add(offset));
                    *(pwrite.sub(2)) = *(pwrite.sub(2).add(offset));
                }
                if length < Self::EXTRA_PIPELINE_LENGTH {
                    unsafe { pwrite = pwrite.sub(Self::DEFAULT_PIPELINE_LENGTH); }
                    if length == Self::DEFAULT_PIPELINE_LENGTH { continue; }
                    for _ in 0..length - Self::DEFAULT_PIPELINE_LENGTH {
                        unsafe {
                            *pwrite = *pwrite.add(offset);
                            pwrite = pwrite.sub(1);
                        }
                    }
                } else {
                    unsafe {
                        *(pwrite.sub(3)) = *(pwrite.sub(3).add(offset));
                        *(pwrite.sub(4)) = *(pwrite.sub(4).add(offset));
                        *(pwrite.sub(5)) = *(pwrite.sub(5).add(offset));
                        *(pwrite.sub(6)) = *(pwrite.sub(6).add(offset));
                        *(pwrite.sub(7)) = *(pwrite.sub(7).add(offset));
                        pwrite = pwrite.sub(Self::EXTRA_PIPELINE_LENGTH);
                        for _ in 0..length - Self::EXTRA_PIPELINE_LENGTH {
                            *pwrite = *pwrite.add(offset);
                            pwrite = pwrite.sub(1);
                        }
                    }
                }
            } else {
                // uncompressed, copy directly
                unsafe {
                    *pwrite = cursor.read_8();
                    pwrite = pwrite.sub(1);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct LaylaDecompressor;

impl LaylaDecompressor {
    // Size of uncompressed data under CRILAYLA.
    const UNCOMPRESSED_DATA_SIZE: usize = 0x100;

    pub fn is_compressed(input: &[u8]) -> bool {
        input.len() >= size_of::<LaylaHeader>()
            && from_slice!(input, u64, LittleEndian) == LAYLA_HEADER_MAGIC
    }

    pub fn decompress(input: &[u8], free_list: &mut FreeList) -> Vec<u8> {
        let header = LaylaHeader::from_stream(input);
        let mut result = free_list.allocate(header.uncompressed_size as usize + Self::UNCOMPRESSED_DATA_SIZE);
        let cmp_slice = unsafe { std::slice::from_raw_parts(
            input.as_ptr().add(size_of::<LaylaHeader>()), input.len() - size_of::<LaylaHeader>()) };
        let mut dcmp_impl = LaylaDecompressorImpl::new(header, cmp_slice, result.as_mut_slice());
        dcmp_impl.decompress();
        result.to_vec()
    }
}

#[cfg(test)]
pub mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::io::Read;
    use crate::cpk::compress::layla::{LaylaDecompressor, LaylaDecompressorCursor};
    use crate::cpk::free_list::FreeList;

    #[test]
    fn cursor_read_stream_1bit() -> Result<(), Box<dyn Error>> {
        let stream = 0xAAu8; // 0b10101010
        let expected_bools = [true, false, true, false, true, false, true, false];
        let mut cursor = LaylaDecompressorCursor::new(
            unsafe { (&raw const stream).add(1) }, 0);
        let actual_bools = std::array::from_fn::<bool, 8, _>(|_| cursor.read_1());
        assert_eq!(expected_bools, actual_bools);
        Ok(())
    }

    #[test]
    fn cursor_read_stream_2bit() -> Result<(), Box<dyn Error>> {
        let stream = [0x93u8, 0x93]; // 0b10010011
        // normal path
        let expect_0offset = [2, 1, 0, 3, 2, 1, 0, 3];
        let mut cursor = LaylaDecompressorCursor::new(
            unsafe { stream.as_ptr().add(stream.len()) }, 0);
        let actual = std::array::from_fn::<u8, 8, _>(|_| cursor.read_2());
        assert_eq!(expect_0offset, actual);
        // bits_left == 1 path
        let expect_7offset = [0, 2, 1, 3, 0, 2, 1];
        let mut cursor = LaylaDecompressorCursor::new(
            unsafe { stream.as_ptr().add(stream.len() - 1) }, 7);
        let actual = std::array::from_fn::<u8, 7, _>(|_| cursor.read_2());
        assert_eq!(expect_7offset, actual);
        Ok(())
    }

    #[test]
    fn cursor_read_stream_8bit() -> Result<(), Box<dyn Error>> {
        // read_8
        let stream = [0xcau8; 8]; // 0b11001010
        // byte aligned path
        let expect_0offset = [0xcau8; 8]; // lol
        let mut cursor = LaylaDecompressorCursor::new(
            unsafe { stream.as_ptr().add(stream.len()) }, 0);
        let actual = std::array::from_fn::<u8, 8, _>(|_| cursor.read_8());
        assert_eq!(expect_0offset, actual);
        // unaligned path
        let expect_3offset = [0x59u8; 7];
        let mut cursor = LaylaDecompressorCursor::new(
            unsafe { stream.as_ptr().add(stream.len() - 1) }, 3);
        let actual = std::array::from_fn::<u8, 7, _>(|_| cursor.read_8());
        assert_eq!(expect_3offset, actual);
        Ok(())
    }

    #[test]
    fn cursor_read_stream_max_8bit() -> Result<(), Box<dyn Error>> {
        // read_max_8
        Ok(())
    }

    #[test]
    fn cursor_read_stream_13bit() -> Result<(), Box<dyn Error>> {
        let stream = [ // Random sequence of bytes
            0xcb, 0xa6, 0x69, 0x75, 0x4e, 0x32, 0xb1, 0xfb, 0x3b, 0x53, 0x7d, 0x38, 0x02, 0x7d, 0xd7, 0xe4, 0xed, 0xf0,
            0xa5, 0x2f, 0x57, 0x6d, 0x3b, 0x2c, 0x0c, 0x77, 0x02, 0x9e, 0x45, 0x3d, 0x30, 0x35, 0x6e, 0xed, 0xa7, 0x8d,
            0x5c, 0x91, 0x0c, 0xc9, 0x90, 0x59, 0x4d, 0x76, 0xe6, 0xe1, 0x68, 0x00, 0x03, 0x69, 0xd7, 0x3b, 0x41, 0xe4,
            0x11, 0xd4, 0x7f, 0x60, 0x70u8
        ];
        let expected = [
            3596, 511, 2568, 7748, 631, 5594, 2072, 104, 7228, 6617, 1708, 6412, 4633, 1111, 1133,
            2029, 3526, 5312, 7842, 6624, 1262, 779, 475, 3415, 1524, 6083, 5874, 3447, 6660, 3615,
            2713, 7163, 5670, 2361, 6836, 6764u32
        ];
        let mut cursor = LaylaDecompressorCursor::new(
            unsafe { stream.as_ptr().add(stream.len()) }, 0);
        let actual = std::array::from_fn::<u32, 36, _>(|_| cursor.read_13());
        assert_eq!(expected, actual);
        Ok(())
    }

    #[test]
    fn layla_read_test() -> Result<(), Box<dyn Error>> {
        let layla_table = "E:/PersonaMultiplayer/CriFsV2Lib/CriFsV2Lib.Tests/Assets/Compressed3dModel.crilayla";
        let expected = "E:/PersonaMultiplayer/CriFsV2Lib/CriFsV2Lib.Tests/Assets/Uncompressed3DModel.dff";
        if !std::fs::exists(layla_table)? || !std::fs::exists(expected)? {
            return Ok(());
        }
        let mut layla_data = vec![];
        File::open(layla_table)?.read_to_end(&mut layla_data)?;
        let mut allocator = FreeList::new();
        let result = LaylaDecompressor::decompress(&layla_data, &mut allocator);
        let mut expected_data = vec![];
        File::open(expected)?.read_to_end(&mut expected_data)?;
        assert_eq!(&result, &expected_data);
        Ok(())
    }
}