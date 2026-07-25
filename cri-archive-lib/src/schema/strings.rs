use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Read, Seek, SeekFrom};

use encoding_rs::SHIFT_JIS;

use crate::schema::header::{StringEncoding, TableHeader};

pub trait StringPool {
    fn get_string(&self, offset: u32) -> Option<&str>;
}

#[derive(Debug)]
struct StringPoolError(&'static str);

impl Display for StringPoolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.write_str(self.0) }
}
impl Error for StringPoolError {}

#[derive(Debug)]
pub struct StringPoolImpl {
    strings: HashMap<usize, String>,
}

impl StringPoolImpl {
    pub fn new<C: Read + Seek>(handle: &mut C, header: &TableHeader)
        -> Result<Self, Box<dyn Error>> {
        let string_pool_offset = header.string_pool_offset();
        let data_pool_offset = header.data_pool_offset();
        if data_pool_offset < string_pool_offset {
            return Err(Box::new(StringPoolError("invalid string/data pool offsets")));
        }
        handle.seek(SeekFrom::Start(string_pool_offset as u64))?;
        let mut alloc = vec![0u8; (data_pool_offset - string_pool_offset) as usize];
        handle.read_exact(&mut alloc)?;
        Ok(Self { strings: parse_strings(&alloc, header.encoding())? })
    }
}

impl StringPool for StringPoolImpl {
    fn get_string(&self, offset: u32) -> Option<&str> {
        self.strings.get(&(offset as usize)).map(String::as_str)
    }
}

#[derive(Debug)]
pub struct StringPoolFast(HashMap<usize, String>);

impl StringPoolFast {
    pub fn new<C: Read + Seek>(handle: &mut C, header: &TableHeader)
        -> Result<Self, Box<dyn Error>> {
        let string_pool_offset = header.string_pool_offset();
        let data_pool_offset = header.data_pool_offset();
        if data_pool_offset < string_pool_offset {
            return Err(Box::new(StringPoolError("invalid string/data pool offsets")));
        }
        handle.seek(SeekFrom::Start(string_pool_offset as u64))?;
        let mut alloc = vec![0u8; (data_pool_offset - string_pool_offset) as usize];
        handle.read_exact(&mut alloc)?;
        Self::new_borrowed(&alloc, header)
    }

    // Assumes that this slice begins at string_pool_offset.
    pub(crate) fn new_borrowed(stream: &[u8], header: &TableHeader)
        -> Result<Self, Box<dyn Error>> {
        Ok(Self(parse_strings(stream, header.encoding())?))
    }
}

impl StringPool for StringPoolFast {
    fn get_string(&self, offset: u32) -> Option<&str> {
        self.0.get(&(offset as usize)).map(String::as_str)
    }
}

fn parse_strings(stream: &[u8], encoding: StringEncoding)
    -> Result<HashMap<usize, String>, Box<dyn Error>> {
    let mut offset = 0usize;
    let mut strings = HashMap::new();
    while offset < stream.len() {
        let tail = &stream[offset..];
        let length = tail.iter().position(|byte| *byte == 0)
            .ok_or_else(|| Box::new(StringPoolError("unterminated CRI string")) as Box<dyn Error>)?;
        let bytes = &tail[..length];
        let value = match encoding {
            StringEncoding::ShiftJIS => {
                let (decoded, _, _) = SHIFT_JIS.decode(bytes);
                decoded.into_owned()
            }
            StringEncoding::UTF8 => std::str::from_utf8(bytes)?.to_owned(),
        };
        strings.insert(offset, value);
        offset += length + 1;
    }
    Ok(strings)
}

#[cfg(test)]
pub mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use crate::schema::header::{TableHeader, HEADER_SIZE};
    use crate::schema::strings::{StringPoolFast, StringPoolImpl};

    #[test]
    fn parse_strings_fastpool_utf8() -> Result<(), Box<dyn Error>> {
        let target_table = "E:/Metaphor/base_cpk/COMMON/sound/bgm.acb";
        if !std::fs::exists(target_table)? { return Ok(()); }
        let mut handle = BufReader::new(File::open(target_table)?);
        let mut header_serial = [0u8; HEADER_SIZE];
        handle.read_exact(&mut header_serial)?;
        let header = TableHeader::new(&header_serial);
        let _ = StringPoolFast::new(&mut handle, &header)?;
        Ok(())
    }

    #[test]
    fn parse_strings_standard_utf8() -> Result<(), Box<dyn Error>> {
        let target_table = "E:/Metaphor/base_cpk/COMMON/sound/bgm.acb";
        if !std::fs::exists(target_table)? { return Ok(()); }
        let mut handle = BufReader::new(File::open(target_table)?);
        let mut header_serial = [0u8; HEADER_SIZE];
        handle.read_exact(&mut header_serial)?;
        let header = TableHeader::new(&header_serial);
        let _ = StringPoolImpl::new(&mut handle, &header)?;
        Ok(())
    }
}
