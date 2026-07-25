use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::schema::columns::Column;
use crate::schema::header::{TableHeader, HEADER_SIZE};
use crate::schema::rows::{DataValue, Row, RowValue};
use crate::schema::strings::{StringPool, StringPoolFast};

pub const CPK_CHUNK_HEADER_SIZE: usize = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpkChunkKind {
    Cpk,
    Toc,
    Itoc,
    Etoc,
    Gtoc,
    Unknown([u8; 4]),
}

impl CpkChunkKind {
    pub fn from_magic(magic: [u8; 4]) -> Self {
        match &magic {
            b"CPK " => Self::Cpk,
            b"TOC " => Self::Toc,
            b"ITOC" => Self::Itoc,
            b"ETOC" => Self::Etoc,
            b"GTOC" => Self::Gtoc,
            _ => Self::Unknown(magic),
        }
    }

    pub fn magic(self) -> [u8; 4] {
        match self {
            Self::Cpk => *b"CPK ",
            Self::Toc => *b"TOC ",
            Self::Itoc => *b"ITOC",
            Self::Etoc => *b"ETOC",
            Self::Gtoc => *b"GTOC",
            Self::Unknown(magic) => magic,
        }
    }
}

#[derive(Debug)]
struct CpkTableError(String);

impl Display for CpkTableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}

impl Error for CpkTableError {}

#[derive(Debug)]
pub(crate) struct TableContainer {
    kind: CpkChunkKind,
    table: Vec<u8>,
}

impl TableContainer {
    pub fn new<R: Read + Seek>(stream: &mut R) -> Result<Self, Box<dyn Error>> {
        let mut chunk_header = [0u8; CPK_CHUNK_HEADER_SIZE];
        stream.read_exact(&mut chunk_header)?;

        let kind = CpkChunkKind::from_magic(chunk_header[0..4].try_into().unwrap());
        let table_size_u64 = u64::from_le_bytes(chunk_header[8..16].try_into().unwrap());
        let table_size = usize::try_from(table_size_u64).map_err(|_| {
            Box::new(CpkTableError(format!(
                "CPK table is too large for this platform: {table_size_u64} bytes"
            ))) as Box<dyn Error>
        })?;
        if table_size < HEADER_SIZE {
            return Err(Box::new(CpkTableError(format!(
                "invalid {:?} table size: {table_size:#x}", kind
            ))));
        }
        if kind == CpkChunkKind::Cpk
            && table_size_u64
                .checked_add(CPK_CHUNK_HEADER_SIZE as u64)
                .is_none_or(|size| size > 0x800)
        {
            return Err(Box::new(CpkTableError(format!(
                "CPK header exceeds the engine's 0x800-byte header area: {table_size:#x}"
            ))));
        }

        let table_start = stream.stream_position()?;
        let stream_end = stream.seek(SeekFrom::End(0))?;
        stream.seek(SeekFrom::Start(table_start))?;
        let remaining = stream_end.saturating_sub(table_start);
        if table_size_u64 > remaining {
            return Err(Box::new(CpkTableError(format!(
                "truncated {:?} table: declares {table_size_u64:#x} bytes, only {remaining:#x} remain",
                kind
            ))));
        }

        let mut table = vec![0u8; table_size];
        stream.read_exact(&mut table)?;

        // CRI's engine marks encrypted table chunks with a zero byte at +4.
        // The XOR stream starts at the first byte of the embedded @UTF table.
        if chunk_header[4] == 0 {
            decrypt_utf_scalar(&mut table);
        }
        if !table.starts_with(b"@UTF") {
            return Err(Box::new(CpkTableError(format!(
                "{:?} chunk does not contain a valid @UTF table", kind
            ))));
        }

        Ok(Self { kind, table })
    }

    pub fn kind(&self) -> CpkChunkKind { self.kind }
    pub fn into_table(self) -> Vec<u8> { self.table }
}

fn decrypt_utf_scalar(input: &mut [u8]) {
    let mut key = 0x5fu8;
    for byte in input {
        *byte ^= key;
        key = key.wrapping_mul(0x15);
    }
}

#[derive(Debug)]
pub(crate) struct HighTable<S: StringPool> {
    alloc: Vec<u8>,
    header: TableHeader,
    columns: Vec<Column>,
    strings: S,
    rows: Vec<Row>,
}

impl HighTable<StringPoolFast> {
    pub fn new(mut alloc: Vec<u8>) -> Result<Self, Box<dyn Error>> {
        if alloc.len() < HEADER_SIZE || !alloc.starts_with(b"@UTF") {
            return Err(Box::new(CpkTableError("invalid or truncated @UTF table".to_owned())));
        }
        let header = TableHeader::new(&alloc);
        let declared_size = (header.size() as usize)
            .checked_add(8)
            .ok_or_else(|| Box::new(CpkTableError("@UTF size overflow".to_owned())) as Box<dyn Error>)?;
        if declared_size > alloc.len() {
            return Err(Box::new(CpkTableError(format!(
                "truncated @UTF table: header declares {declared_size:#x}, buffer has {:#x}",
                alloc.len()
            ))));
        }
        let rows_start = header.rows_offset() as usize;
        let string_start = header.string_pool_offset() as usize;
        let data_start = header.data_pool_offset() as usize;
        if rows_start < HEADER_SIZE
            || rows_start > string_start
            || string_start > data_start
            || data_start > declared_size
        {
            return Err(Box::new(CpkTableError("invalid @UTF section offsets".to_owned())));
        }
        let rows_bytes = (header.row_size() as usize)
            .checked_mul(header.row_count() as usize)
            .ok_or_else(|| Box::new(CpkTableError("@UTF row size overflow".to_owned())) as Box<dyn Error>)?;
        let rows_end = rows_start.checked_add(rows_bytes)
            .ok_or_else(|| Box::new(CpkTableError("@UTF row offset overflow".to_owned())) as Box<dyn Error>)?;
        if rows_end > string_start {
            return Err(Box::new(CpkTableError("@UTF rows overlap the string pool".to_owned())));
        }

        if declared_size < alloc.len() {
            alloc.truncate(declared_size);
        }

        let mut cursor = Cursor::new(alloc.as_slice());
        let columns = Column::new_list(&mut cursor, &header)?;
        if cursor.position() as usize > rows_start {
            return Err(Box::new(CpkTableError("@UTF columns overlap row data".to_owned())));
        }
        let row_width = columns.iter()
            .filter(|column| column.get_value().get_flags().contains(crate::schema::columns::ColumnFlag::ROW_STORAGE))
            .try_fold(0usize, |total, column| {
                total.checked_add(column.get_value().get_type().get_size() as usize)
            })
            .ok_or_else(|| Box::new(CpkTableError("@UTF row schema overflow".to_owned())) as Box<dyn Error>)?;
        if row_width > header.row_size() as usize {
            return Err(Box::new(CpkTableError("@UTF row schema exceeds RowSize".to_owned())));
        }
        let rows = Row::new_list(&mut cursor, &header, columns.as_ref())?;
        let strings = StringPoolFast::new_borrowed(&alloc[string_start..data_start], &header)?;
        Ok(Self { alloc, header, columns, strings, rows })
    }
}

impl<S: StringPool> HighTable<S> {
    pub fn get_strings(&self) -> &S { &self.strings }
    pub fn get_rows(&self) -> &[Row] { &self.rows }

    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|column| {
            self.strings.get_string(column.get_string_offset()) == Some(name)
        })
    }

    pub fn value(&self, row_index: usize, column_index: usize) -> Option<&RowValue> {
        let row = self.rows.get(row_index)?;
        let value = row.get(column_index)?;
        match value {
            RowValue::None => self.columns.get(column_index)?.get_default_value(),
            _ => Some(value),
        }
    }

    pub fn value_by_name(&self, row_index: usize, name: &str) -> Option<&RowValue> {
        let index = self.column_index(name)?;
        self.value(row_index, index)
    }


    pub fn u64_by_name(&self, row_index: usize, name: &str) -> Option<u64> {
        row_value_to_u64(self.value_by_name(row_index, name)?)
    }

    pub fn data_by_name(&self, row_index: usize, name: &str) -> Option<&[u8]> {
        match self.value_by_name(row_index, name)? {
            RowValue::Data(value) if !value.is_none() => self.data(value),
            _ => None,
        }
    }

    pub fn data(&self, value: &DataValue) -> Option<&[u8]> {
        let start = (self.header.data_pool_offset() as usize)
            .checked_add(value.get_offset() as usize)?;
        let end = start.checked_add(value.get_length() as usize)?;
        self.alloc.get(start..end)
    }
}

pub(crate) fn row_value_to_u64(value: &RowValue) -> Option<u64> {
    match value {
        RowValue::Byte(v) => Some(*v as u64),
        RowValue::SByte(v) if *v >= 0 => Some(*v as u64),
        RowValue::UInt16(v) => Some(*v as u64),
        RowValue::Int16(v) if *v >= 0 => Some(*v as u64),
        RowValue::UInt32(v) => Some(*v as u64),
        RowValue::Int32(v) if *v >= 0 => Some(*v as u64),
        RowValue::UInt64(v) => Some(*v),
        RowValue::Int64(v) if *v >= 0 => Some(*v as u64),
        _ => None,
    }
}
