use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::io::{Read, Seek, SeekFrom};
use bitflags::bitflags;
use crate::from_slice;
use crate::schema::header::TableHeader;
use crate::schema::rows::{Row, RowValue};
use crate::utils::slice::FromSlice;
use crate::utils::endianness::BigEndian;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ColumnFlag : u8 {
        const NAME = 1 << 4;
        const DEFAULT_VALUE = 1 << 5;
        const ROW_STORAGE = 1 << 6;
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Byte = 0,
    SByte = 1,
    UInt16 = 2,
    Int16 = 3,
    UInt32 = 4,
    Int32 = 5,
    UInt64 = 6,
    Int64 = 7,
    Single = 8,
    Double = 9,
    String = 10,
    Data = 11,
    Guid = 12,
    Invalid = 0xff,
}

impl ColumnType {
    pub fn get_size(&self) -> u32 {
        match self {
            Self::Byte | Self::SByte => 1,
            Self::UInt16 | Self::Int16 => 2,
            Self::UInt32 | Self::Int32 | Self::Single | Self::String => 4,
            Self::UInt64 | Self::Int64 | Self::Double | Self::Data => 8,
            Self::Guid => 16,
            Self::Invalid => 0,
        }
    }
}

const TYPE_MASK: u8 = 0xf;

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ColumnValue(u8);

impl ColumnValue {
    pub const fn get_flags(&self) -> ColumnFlag {
        ColumnFlag::from_bits_retain(self.0 & !TYPE_MASK)
    }
    pub const fn get_type(&self) -> ColumnType {
        match self.0 & TYPE_MASK {
            0 => ColumnType::Byte,
            1 => ColumnType::SByte,
            2 => ColumnType::UInt16,
            3 => ColumnType::Int16,
            4 => ColumnType::UInt32,
            5 => ColumnType::Int32,
            6 => ColumnType::UInt64,
            7 => ColumnType::Int64,
            8 => ColumnType::Single,
            9 => ColumnType::Double,
            10 => ColumnType::String,
            11 => ColumnType::Data,
            12 => ColumnType::Guid,
            _ => ColumnType::Invalid,
        }
    }
}

impl Debug for ColumnValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ColumnFlag {{ Type: {:?}, Flags: {:?} }}", self.get_type(), self.get_flags())
    }
}

#[derive(Debug)]
pub struct Column {
    flag: ColumnValue,
    string_offset: u32,
    default: Option<RowValue>
}

impl Column {
    pub(crate) fn new(flag: ColumnValue, string_offset: u32, default: Option<RowValue>) -> Self {
        Self { flag, string_offset, default }
    }

    pub fn get_value(&self) -> ColumnValue {
        self.flag
    }
    pub fn get_string_offset(&self) -> u32 {
        self.string_offset
    }

    pub fn get_default_value(&self) -> Option<&RowValue> {
        self.default.as_ref()
    }

    pub fn new_list<C: Read + Seek>(handle: &mut C, header: &TableHeader) -> Result<Vec<Self>, Box<dyn Error>> {
        handle.seek(SeekFrom::Start(crate::schema::header::HEADER_SIZE as u64))?;
        let mut columns: Vec<Self> = Vec::with_capacity(header.column_count() as usize);
        let mut default_bytes = [0u8; 0x10];
        for _ in 0..header.column_count() as usize {
            let mut flag_byte = [0u8; 1];
            handle.read_exact(&mut flag_byte)?;
            let flag = ColumnValue(flag_byte[0]);
            let string_offset = if flag.get_flags().contains(ColumnFlag::NAME) {
                let mut name_bytes = [0u8; 4];
                handle.read_exact(&mut name_bytes)?;
                from_slice!(&name_bytes, u32)
            } else {
                u32::MAX
            };
            let default = if flag.get_flags().contains(ColumnFlag::DEFAULT_VALUE) {
                let ctype = flag.get_type();
                let size = ctype.get_size() as usize;
                if size == 0 {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unsupported CRI UTF column type",
                    )));
                }
                handle.read_exact(&mut default_bytes[..size])?;
                Some(Row::row_value(ctype, &default_bytes))
            } else {
                None
            };
            columns.push(Self::new(flag, string_offset, default));
        }
        Ok(columns)
    }
}

#[cfg(test)]
pub mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use crate::schema::columns::{Column, ColumnFlag, ColumnType};
    use crate::schema::header::{TableHeader, HEADER_SIZE};
    use crate::schema::strings::{StringPool, StringPoolImpl};

    #[test]
    fn read_columns_acb() -> Result<(), Box<dyn Error>> {
        let target_table = "E:/Metaphor/base_cpk/COMMON/sound/bgm.acb";
        if !std::fs::exists(target_table)? {
            return Ok(());
        }
        let mut handle = BufReader::new(File::open(target_table)?);
        let mut header_serial = [0u8; HEADER_SIZE];
        handle.read_exact(&mut header_serial)?;
        let header = TableHeader::new(&header_serial);
        let columns = Column::new_list(&mut handle, &header)?;
        let string_pool = StringPoolImpl::new(&mut handle, &header)?;

        let v0 = columns[0].get_value();
        assert_eq!(v0.get_type(), ColumnType::UInt32);
        assert_eq!(v0.get_flags(), ColumnFlag::NAME | ColumnFlag::ROW_STORAGE);
        assert_eq!(string_pool.get_string(columns[0].string_offset).unwrap(), "FileIdentifier");

        let v3 = columns[3].get_value();
        assert_eq!(v3.get_type(), ColumnType::Byte);
        assert_eq!(v3.get_flags(), ColumnFlag::NAME | ColumnFlag::ROW_STORAGE);
        assert_eq!(string_pool.get_string(columns[3].string_offset).unwrap(), "Type");

        let v5 = columns[5].get_value();
        assert_eq!(v5.get_type(), ColumnType::Data);
        assert_eq!(v5.get_flags(), ColumnFlag::NAME | ColumnFlag::ROW_STORAGE);
        assert_eq!(string_pool.get_string(columns[5].string_offset).unwrap(), "AcfMd5Hash");
        /*
        for c in &mut columns {
            println!("{:?} ({})", c, string_pool.get_string(c.string_offset).unwrap());
        }
        */
        Ok(())
    }
}