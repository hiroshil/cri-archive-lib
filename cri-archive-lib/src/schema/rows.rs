use std::error::Error;
use std::io::{Read, Seek, SeekFrom};
use std::ops::{Deref, DerefMut, Index};
use crate::schema::columns::{Column, ColumnFlag, ColumnType};
use crate::schema::header::TableHeader;
use crate::utils::endianness::BigEndian;
use crate::utils::slice::FromSlice;
use crate::from_slice;

#[derive(Debug, PartialEq)]
pub enum RowValue {
    None,
    Byte(u8),
    SByte(i8),
    UInt16(u16),
    Int16(i16),
    UInt32(u32),
    Int32(i32),
    UInt64(u64),
    Int64(i64),
    Single(f32),
    Double(f64),
    String(u32),
    Data(DataValue),
    Guid([u32; 4])
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct DataValue {
    offset: u32,
    length: u32
}

impl DataValue {
    pub fn is_none(&self) -> bool {
        self.length == 0
    }

    pub fn get_offset(&self) -> u32 {
        self.offset
    }

    pub fn get_length(&self) -> u32 {
        self.length
    }
}

#[derive(Debug)]
pub struct Row(Vec<RowValue>);

impl Deref for Row {
    type Target = Vec<RowValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Row {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Row {
    pub fn new_list<C: Read + Seek>(handle: &mut C, header: &TableHeader, column_def: &[Column])
        -> Result<Vec<Self>, Box<dyn Error>> {
        let rows_offset = header.rows_offset() as u64;
        let row_size = header.row_size() as u64;
        let mut rows = Vec::with_capacity(header.row_count() as usize);
        for row_index in 0..header.row_count() as u64 {
            // CRI tables may include padding in each row. Seeking by RowSize
            // keeps subsequent rows aligned even when the schema occupies fewer bytes.
            let row_position = row_index
                .checked_mul(row_size)
                .and_then(|offset| rows_offset.checked_add(offset))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "CRI UTF row offset overflow",
                    )
                })?;
            handle.seek(SeekFrom::Start(row_position))?;
            rows.push(Self::create_row(handle, column_def)?);
        }
        Ok(rows)
    }

    fn create_row<C: Read + Seek>(handle: &mut C, column_def: &[Column]) -> Result<Self, Box<dyn Error>> {
        let mut column_data = vec![];
        let mut field = [0u8; 0x10];
        for c in column_def {
            let ctype = c.get_value().get_type();
            if ctype == ColumnType::Invalid {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported CRI UTF column type",
                )));
            }
            // Handle null objects
            if !c.get_value().get_flags().contains(ColumnFlag::ROW_STORAGE) {
                column_data.push(RowValue::None);
                continue;
            }
            let slice = &mut field[..ctype.get_size() as usize];
            handle.read_exact(slice)?;
            column_data.push(Self::row_value(ctype, &field));
        }
        Ok(Self(column_data))
    }

    pub fn row_value(ctype: ColumnType, slice: &[u8]) -> RowValue {
        match ctype {
            ColumnType::Byte => RowValue::Byte(slice[0]),
            ColumnType::SByte => RowValue::SByte(slice[0] as i8),
            ColumnType::UInt16 => RowValue::UInt16(from_slice!(&slice[0..2], u16)),
            ColumnType::Int16 => RowValue::Int16(from_slice!(&slice[0..2], i16)),
            ColumnType::UInt32 => RowValue::UInt32(from_slice!(&slice[0..4], u32)),
            ColumnType::Int32 => RowValue::Int32(from_slice!(&slice[0..4], i32)),
            ColumnType::Single => RowValue::Single(from_slice!(&slice[0..4], f32)),
            ColumnType::String => RowValue::String(from_slice!(&slice[0..4], u32)),
            ColumnType::UInt64 => RowValue::UInt64(from_slice!(&slice[0..8], u64)),
            ColumnType::Int64 => RowValue::Int64(from_slice!(&slice[0..8], i64)),
            ColumnType::Double => RowValue::Double(from_slice!(&slice[0..8], f64)),
            ColumnType::Data => RowValue::Data(DataValue {
                offset: from_slice!(&slice[0..4], u32),
                length: from_slice!(&slice[4..8], u32),
            }),
            ColumnType::Guid => RowValue::Guid([
                from_slice!(&slice[0..4], u32),
                from_slice!(&slice[4..8], u32),
                from_slice!(&slice[8..12], u32),
                from_slice!(&slice[12..16], u32),
            ]),
            ColumnType::Invalid => RowValue::None,
        }
    }
}

impl Index<usize> for Row {
    type Output = RowValue;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

#[cfg(test)]
pub mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::io::{BufReader, Read, Seek, SeekFrom};
    use crate::schema::columns::Column;
    use crate::schema::header::{TableHeader, HEADER_SIZE};
    use crate::schema::rows::{DataValue, Row, RowValue};
    use crate::schema::strings::{StringPool, StringPoolImpl};

    struct OffsetedLowCpkReader(File);

    impl OffsetedLowCpkReader {
        fn new(file: File) -> Self {
            Self(file)
        }
    }

    impl Read for OffsetedLowCpkReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Seek for OffsetedLowCpkReader {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            // Add + 0x10 to everything
            let pos = match pos {
                SeekFrom::Start(v) => SeekFrom::Start(v + 0x10),
                v => v,
            };
            self.0.seek(pos)
        }
    }

    #[test]
    fn read_rows_acb() -> Result<(), Box<dyn Error>> {
        let target_table = "E:/Metaphor/base_cpk/COMMON/sound/bgm.acb";
        if !std::fs::exists(target_table)? {
            return Ok(());
        }
        let mut handle = BufReader::new(File::open(target_table)?);
        let mut header_serial = [0u8; HEADER_SIZE];
        handle.read_exact(&mut header_serial)?;
        let header = TableHeader::new(&header_serial);
        let columns = Column::new_list(&mut handle, &header)?;

        let rows = Row::new_list(&mut handle, &header, &columns)?;
        let acb_row = &rows[0];
        assert_eq!(RowValue::UInt32(0), acb_row[0]); // FileIdentifier
        assert_eq!(RowValue::UInt32(20382208), acb_row[2]); // Version
        assert_eq!(RowValue::Data(DataValue { offset: 0, length: 16 }), acb_row[5]); // AcfMd5Hash
        assert_eq!(RowValue::Data(DataValue { offset: 32, length: 1704 }), acb_row[7]); // CueTable
        Ok(())
    }

    #[test]
    fn read_rows_cpk() -> Result<(), Box<dyn Error>> {
        let target_table = "E:/PersonaMultiplayer/CriFsV2Lib/CriFsV2Lib.Tests/Assets/SampleData.cpk";
        if !std::fs::exists(target_table)? {
            return Ok(());
        }
        let mut handle = OffsetedLowCpkReader::new(File::open(target_table)?);
        handle.seek(SeekFrom::Start(0))?; // go to first table (this will actually go to 0x10)
        let mut first_header = [0u8; HEADER_SIZE];
        handle.read_exact(&mut first_header)?;
        let header = TableHeader::new(&first_header);
        let columns = Column::new_list(&mut handle, &header)?;
        let rows = Row::new_list(&mut handle, &header, &columns)?;
        let cpk_row = &rows[0];
        assert_eq!(RowValue::UInt64(1), cpk_row[0]); // UpdateDateTime
        assert_eq!(RowValue::None, cpk_row[1]); // FileSize
        assert_eq!(RowValue::UInt64(0x800), cpk_row[2]); // ContentOffset
        assert_eq!(RowValue::UInt64(0x2a000), cpk_row[3]); // ContentSize
        assert_eq!(RowValue::UInt32(1), cpk_row[35]); // CpkMode
        Ok(())
    }

    #[test]
    fn readme_example() -> Result<(), Box<dyn Error>> {
        let path = "E:/Metaphor/base_cpk/COMMON/sound/bgm.acb";
        if !std::fs::exists(path)? {
            return Ok(());
        }
        let mut handle = BufReader::new(File::open(path)?);
        let mut header_serial = [0u8; HEADER_SIZE];
        // Read the table header at 0x0 (ACB, ACF, AWB)
        handle.read_exact(&mut header_serial)?;
        let header = TableHeader::new(&header_serial);
        // Read columns/rows
        let columns = Column::new_list(&mut handle, &header)?;
        let string_pool = StringPoolImpl::new(&mut handle, &header)?;
        let rows = Row::new_list(&mut handle, &header, &columns)?;
        let acb_row = &rows[0]; // ACB header has only one row
        // find the column for "AcfMd5Hash"
        let mut acf_md5_hash: Option<usize> = None;
        for (i, c) in columns.iter().enumerate() {
            if let Some(str) = string_pool.get_string(c.get_string_offset()) {
                if str == "AcfMd5Hash" {
                    acf_md5_hash = Some(i);
                    break;
                }
            }
        }
        if let Some(acf_col) = acf_md5_hash {
            if let RowValue::Data(hash) = &acb_row[acf_col] {
                // read the ACF MD5 hash
                handle.seek(SeekFrom::Start((header.data_pool_offset() + hash.offset) as u64))?;
                let mut acf_md5 = Vec::with_capacity(hash.length as usize);
                unsafe { acf_md5.set_len(acf_md5.capacity()) };
                handle.read_exact(&mut acf_md5)?;
                assert_eq!(acf_md5, &[236, 103, 97, 106, 90, 25, 172, 164, 161, 234, 209, 75, 242, 34, 227, 209]);
            }
        }
        Ok(())
    }
}