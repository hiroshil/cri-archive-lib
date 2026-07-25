use std::collections::HashMap;
use std::error::Error;
use std::io::Cursor;
use std::ptr::NonNull;
use crate::schema::columns::Column;
use crate::schema::header::TableHeader;
use crate::schema::rows::{Row, RowValue};
use crate::schema::strings::{StringPool, StringPoolFast};

#[derive(Debug)]
pub(crate) struct HighTable<S: StringPool> {
    alloc: NonNull<[u8]>,
    header: TableHeader,
    strings: S,
    rows: Vec<Row>,
    indices: HashMap<&'static str, usize>
}

impl HighTable<StringPoolFast> {
    pub fn new(alloc: &[u8]) -> Result<Self, Box<dyn Error>> {
        let header = TableHeader::new(alloc);
        let mut cursor = Cursor::new(alloc);
        cursor.set_position(crate::schema::header::HEADER_SIZE as u64);
        let columns = Column::new_list(&mut cursor, &header)?;
        let str_raw = &alloc[header.string_pool_offset() as usize..header.data_pool_offset() as usize];
        let rows = Row::new_list(&mut cursor, &header, columns.as_ref())?;
        let strings = StringPoolFast::new_borrowed(str_raw, &header)?;
        let alloc = unsafe { NonNull::new_unchecked(&raw const *alloc as _) };


        let indices = HashMap::from_iter(
            columns.iter().enumerate()
                .filter_map(|(i, col)| strings.get_string(
                    col.get_string_offset()).map(|str| (
                    unsafe { std::str::from_utf8_unchecked(
                        std::slice::from_raw_parts(str.as_ptr(), str.len())) }, i))
                )
        );
        Ok(Self { alloc, header, strings, rows, indices })
    }
}

impl<S: StringPool> HighTable<S> {
    pub fn get_header(&self) -> &TableHeader { &self.header }
    pub fn get_strings(&self) -> &S { &self.strings }
    pub fn get_rows(&self) -> &[Row] { &self.rows }
    pub fn get_slice(&self) -> &[u8] { unsafe { self.alloc.as_ref() } }
    pub fn get_value_header(&self, name: &str) -> Option<&RowValue> {
        let row = &self.rows[0];
        self.indices.get(&name).map(|i| &row[*i])
    }
    pub fn get_value<'a>(&'a self, row: &'a Row, name: &'a str) -> Option<&'a RowValue> {
        self.indices.get(&name).map(|i| &row[*i])
    }
}