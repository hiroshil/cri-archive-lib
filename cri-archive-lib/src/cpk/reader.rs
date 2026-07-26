use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;

#[cfg(feature = "cpk_compression_layla")]
use crate::cpk::compress::layla::LaylaDecompressor;
use crate::cpk::encrypt::data::{DummyDecryptor, FileDecryptor};
use crate::cpk::file::CpkFile;
#[cfg(feature = "cpk_compression_layla")]
use crate::cpk::free_list::FreeList;
use crate::cpk::header::{row_value_to_u64, CpkChunkKind, HighTable, TableContainer};
use crate::schema::rows::RowValue;
use crate::schema::strings::{StringPool, StringPoolFast};

const ENGINE_TOC_FILE_BASE: u64 = 0x800;

#[derive(Debug)]
pub enum CpkReaderError {
    InvalidHeaderChunk,
    MissingContentOffset,
    MissingFileName,
    MissingFileSize,
    MissingFileOffset,
    MissingTocAndItoc,
    InvalidTocColumn(&'static str),
    InvalidItoc,
    ItocContentOffsetTooLarge(u64),
    FileTooLarge(u64),
    GetFilesNotCalled,
}

impl Error for CpkReaderError {}

impl Display for CpkReaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeaderChunk => f.write_str("archive does not start with a CPK chunk"),
            Self::MissingContentOffset => f.write_str("CPK header has no ContentOffset"),
            Self::MissingFileName => f.write_str("TOC row has no FileName"),
            Self::MissingFileSize => f.write_str("file row has no valid FileSize"),
            Self::MissingFileOffset => f.write_str("TOC row has no valid FileOffset"),
            Self::MissingTocAndItoc => f.write_str("CPK contains neither a TOC nor an ITOC"),
            Self::InvalidTocColumn(name) => write!(f, "TOC is missing required column {name}"),
            Self::InvalidItoc => f.write_str("invalid ITOC DataL/DataH structure"),
            Self::ItocContentOffsetTooLarge(offset) => write!(
                f,
                "ITOC ContentOffset exceeds the target engine's 32-bit base: {offset:#x}"
            ),
            Self::FileTooLarge(size) => write!(f, "file size does not fit the CPK format: {size}"),
            Self::GetFilesNotCalled => f.write_str("get_files must be called before extract_file"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CpkMetadata {
    pub file_size: u64,
    pub content_offset: u64,
    pub content_size: u64,
    pub toc_offset: u64,
    pub toc_size: u64,
    pub itoc_offset: u64,
    pub itoc_size: u64,
    pub etoc_offset: u64,
    pub etoc_size: u64,
    pub gtoc_offset: u64,
    pub gtoc_size: u64,
    pub version: u16,
    pub revision: u16,
    pub align: u16,
    pub sorted: bool,
    pub eid: u16,
    pub files: u32,
    pub cpk_mode: u32,
    pub enable_file_name: bool,
    pub update_date_time: u64,
    pub codec: u32,
    pub dpk_itoc: u32,
    pub enable_toc_crc: bool,
    pub enable_file_crc: bool,
}

#[derive(Debug)]
pub struct CpkReader<R: Read + Seek, E: FileDecryptor = DummyDecryptor> {
    stream: R,
    start_pos: u64,
    metadata: Option<CpkMetadata>,
    #[cfg(feature = "cpk_compression_layla")]
    free_list: FreeList,
    decryption: PhantomData<E>,
}

impl<R: Read + Seek> CpkReader<R> {
    pub fn new(stream: R) -> Result<Self, Box<dyn Error>> {
        Self::new_with_encryption(stream)
    }
}

impl<R: Read + Seek, E: FileDecryptor> CpkReader<R, E> {
    pub fn new_with_encryption(mut stream: R) -> Result<Self, Box<dyn Error>> {
        let start_pos = stream.stream_position()?;
        Ok(Self {
            stream,
            start_pos,
            metadata: None,
            #[cfg(feature = "cpk_compression_layla")]
            free_list: FreeList::new(),
            decryption: PhantomData,
        })
    }

    pub fn metadata(&self) -> Option<&CpkMetadata> { self.metadata.as_ref() }

    pub fn get_files(&mut self) -> Result<Vec<CpkFile>, Box<dyn Error>> {
        self.stream.seek(SeekFrom::Start(self.start_pos))?;
        let container = TableContainer::new(&mut self.stream)?;
        if container.kind() != CpkChunkKind::Cpk {
            return Err(Box::new(CpkReaderError::InvalidHeaderChunk));
        }
        let cpk_table = HighTable::<StringPoolFast>::new(container.into_table())?;
        if cpk_table.get_rows().is_empty() {
            return Err(Box::new(CpkReaderError::InvalidHeaderChunk));
        }

        let metadata = parse_metadata(&cpk_table);
        self.metadata = Some(metadata);

        if metadata.toc_offset != 0 {
            return self.read_toc(metadata);
        }
        if metadata.itoc_offset != 0 {
            return self.read_itoc(metadata);
        }
        Err(Box::new(CpkReaderError::MissingTocAndItoc))
    }

    pub fn read_packed_file(&mut self, file: &CpkFile) -> Result<Vec<u8>, Box<dyn Error>> {
        if self.metadata.is_none() {
            return Err(Box::new(CpkReaderError::GetFilesNotCalled));
        }
        self.stream.seek(SeekFrom::Start(
            self.start_pos
                .checked_add(file.absolute_offset())
                .ok_or(CpkReaderError::MissingFileOffset)?,
        ))?;
        let packed_size = usize::try_from(file.file_size())
            .map_err(|_| CpkReaderError::FileTooLarge(u64::from(file.file_size())))?;
        let mut output = vec![0u8; packed_size];
        self.stream.read_exact(&mut output)?;
        Ok(output)
    }

    pub fn extract_file_with_packed(
        &mut self,
        file: &CpkFile,
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let packed = self.read_packed_file(file)?;
        let mut output = packed.clone();
        if E::is_encrypted(file, &output) {
            E::decrypt_in_place(&mut output);
        }
        #[cfg(feature = "cpk_compression_layla")]
        if LaylaDecompressor::is_compressed(&output) {
            output = LaylaDecompressor::decompress(&output, &mut self.free_list);
        }
        Ok((packed, output))
    }

    pub fn extract_file(&mut self, file: &CpkFile) -> Result<Vec<u8>, Box<dyn Error>> {
        self.extract_file_with_packed(file).map(|(_, extracted)| extracted)
    }

    pub fn into_inner(self) -> R { self.stream }

    fn read_toc(&mut self, metadata: CpkMetadata) -> Result<Vec<CpkFile>, Box<dyn Error>> {
        let toc_position = self.start_pos.checked_add(metadata.toc_offset)
            .ok_or(CpkReaderError::MissingFileOffset)?;
        self.stream.seek(SeekFrom::Start(toc_position))?;
        let container = TableContainer::new(&mut self.stream)?;
        if container.kind() != CpkChunkKind::Toc {
            return Err(Box::new(CpkReaderError::InvalidHeaderChunk));
        }
        let toc = HighTable::<StringPoolFast>::new(container.into_table())?;

        let file_name_col = toc.column_index("FileName")
            .ok_or(CpkReaderError::InvalidTocColumn("FileName"))?;
        let file_size_col = toc.column_index("FileSize")
            .ok_or(CpkReaderError::InvalidTocColumn("FileSize"))?;
        let file_offset_col = toc.column_index("FileOffset")
            .ok_or(CpkReaderError::InvalidTocColumn("FileOffset"))?;
        let dir_name_col = toc.column_index("DirName");
        let extract_size_col = toc.column_index("ExtractSize");
        let id_col = toc.column_index("ID");
        let user_string_col = toc.column_index("UserString");
        let file_crc_col = toc.column_index("FileCrc");

        // The analyzed engine resolves every TOC FileOffset from a fixed
        // archive-relative base of 0x800, independently of ContentOffset.
        let toc_base = ENGINE_TOC_FILE_BASE;

        let mut files = Vec::with_capacity(toc.get_rows().len());
        for row_index in 0..toc.get_rows().len() {
            let file_name = string_at(&toc, row_index, file_name_col)
                .ok_or(CpkReaderError::MissingFileName)?;
            let directory = dir_name_col
                .and_then(|index| string_at(&toc, row_index, index))
                .unwrap_or("");
            let user_string = user_string_col
                .and_then(|index| string_at(&toc, row_index, index))
                .unwrap_or("");
            let file_size_u64 = numeric_at(&toc, row_index, file_size_col)
                .ok_or(CpkReaderError::MissingFileSize)?;
            let file_size = u32::try_from(file_size_u64)
                .map_err(|_| CpkReaderError::FileTooLarge(file_size_u64))?;
            let extract_size_u64 = extract_size_col
                .and_then(|index| numeric_at(&toc, row_index, index))
                .unwrap_or(file_size_u64);
            let extract_size = u32::try_from(extract_size_u64)
                .map_err(|_| CpkReaderError::FileTooLarge(extract_size_u64))?;
            let file_offset = numeric_at(&toc, row_index, file_offset_col)
                .ok_or(CpkReaderError::MissingFileOffset)?;
            let id = id_col
                .and_then(|index| numeric_at(&toc, row_index, index))
                .and_then(|value| u32::try_from(value).ok());
            let file_crc = file_crc_col
                .and_then(|index| numeric_at(&toc, row_index, index))
                .and_then(|value| u32::try_from(value).ok());
            let absolute_offset = toc_base.checked_add(file_offset)
                .ok_or(CpkReaderError::MissingFileOffset)?;

            files.push(CpkFile::new(
                directory,
                file_name,
                file_offset,
                absolute_offset,
                file_size,
                extract_size,
                id,
                user_string,
                file_crc,
            ));
        }
        Ok(files)
    }

    fn read_itoc(&mut self, metadata: CpkMetadata) -> Result<Vec<CpkFile>, Box<dyn Error>> {
        if metadata.content_offset == 0 {
            return Err(Box::new(CpkReaderError::MissingContentOffset));
        }
        if metadata.content_offset > u64::from(u32::MAX) {
            return Err(Box::new(CpkReaderError::ItocContentOffsetTooLarge(
                metadata.content_offset,
            )));
        }
        let itoc_position = self.start_pos.checked_add(metadata.itoc_offset)
            .ok_or(CpkReaderError::MissingFileOffset)?;
        self.stream.seek(SeekFrom::Start(itoc_position))?;
        let container = TableContainer::new(&mut self.stream)?;
        if container.kind() != CpkChunkKind::Itoc {
            return Err(Box::new(CpkReaderError::InvalidHeaderChunk));
        }
        let itoc = HighTable::<StringPoolFast>::new(container.into_table())?;
        let alignment = u64::from(metadata.align.max(1));
        let mut rows = Vec::new();

        if metadata.eid != 0 {
            // Direct/EID ITOC stores the high-width rows in the outer table.
            collect_itoc_rows(&itoc, &mut rows)?;
        } else {
            // FUN_81066c36 always constructs both nested parsers when EID is
            // zero. A missing DataL or DataH is invalid for this target even
            // when the corresponding group has no rows.
            let data_l = itoc.data_by_name(0, "DataL").ok_or(CpkReaderError::InvalidItoc)?;
            let data_h = itoc.data_by_name(0, "DataH").ok_or(CpkReaderError::InvalidItoc)?;
            let low = HighTable::<StringPoolFast>::new(data_l.to_vec())?;
            let high = HighTable::<StringPoolFast>::new(data_h.to_vec())?;
            collect_itoc_rows(&low, &mut rows)?;
            collect_itoc_rows(&high, &mut rows)?;
        }

        // FUN_8106706C searches DataL and DataH independently, converts the
        // opposite table's failed search into an insertion index, then asks
        // FUN_81066ED2 to sum both prefixes. Consequently payloads are laid
        // out as the stable merge of both tables by ID, not DataL followed by
        // DataH. This distinction is essential whenever low/high-width rows
        // interleave, as they do in this engine's SC/BK/BSF/PT archives.
        rows.sort_by_key(|row| row.id);
        if rows.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(Box::new(CpkReaderError::InvalidItoc));
        }
        materialize_itoc_rows(&rows, metadata.content_offset, alignment)
    }
}

fn parse_metadata(table: &HighTable<StringPoolFast>) -> CpkMetadata {
    let get = |name| table.u64_by_name(0, name).unwrap_or(0);
    CpkMetadata {
        file_size: get("FileSize"),
        content_offset: get("ContentOffset"),
        content_size: get("ContentSize"),
        toc_offset: get("TocOffset"),
        toc_size: get("TocSize"),
        itoc_offset: get("ItocOffset"),
        itoc_size: get("ItocSize"),
        etoc_offset: get("EtocOffset"),
        etoc_size: get("EtocSize"),
        gtoc_offset: get("GtocOffset"),
        gtoc_size: get("GtocSize"),
        version: u16::try_from(get("Version")).unwrap_or(0),
        revision: u16::try_from(get("Revision")).unwrap_or(0),
        align: u16::try_from(get("Align")).unwrap_or(0),
        sorted: get("Sorted") != 0,
        eid: u16::try_from(get("EID")).unwrap_or(0),
        files: u32::try_from(get("Files")).unwrap_or(0),
        cpk_mode: u32::try_from(get("CpkMode")).unwrap_or(0),
        enable_file_name: get("EnableFileName") != 0,
        update_date_time: get("UpdateDateTime"),
        codec: u32::try_from(get("Codec")).unwrap_or(0),
        dpk_itoc: u32::try_from(get("DpkItoc")).unwrap_or(0),
        enable_toc_crc: get("EnableTocCrc") != 0,
        enable_file_crc: get("EnableFileCrc") != 0,
    }
}

fn string_at<'a>(table: &'a HighTable<StringPoolFast>, row: usize, column: usize) -> Option<&'a str> {
    match table.value(row, column)? {
        // CRI uses string offset zero as a null pointer. Pools commonly keep
        // the literal marker "<NULL>" there, but the engine does not expose
        // that marker as a directory or UserString value.
        RowValue::String(0) => None,
        RowValue::String(offset) => table.get_strings().get_string(*offset),
        _ => None,
    }
}

fn numeric_at(table: &HighTable<StringPoolFast>, row: usize, column: usize) -> Option<u64> {
    row_value_to_u64(table.value(row, column)?)
}

#[derive(Debug, Clone, Copy)]
struct ItocRow {
    id: u32,
    file_size: u32,
    extract_size: u32,
    file_crc: Option<u32>,
}

fn collect_itoc_rows(
    table: &HighTable<StringPoolFast>,
    rows: &mut Vec<ItocRow>,
) -> Result<(), Box<dyn Error>> {
    let id_col = table.column_index("ID").unwrap_or(0);
    let file_size_col = table.column_index("FileSize").unwrap_or(1);
    let extract_size_col = table.column_index("ExtractSize").unwrap_or(2);
    let crc_col = table.column_index("FileCrc");

    rows.reserve(table.get_rows().len());
    for row in 0..table.get_rows().len() {
        let id_u64 = numeric_at(table, row, id_col).ok_or(CpkReaderError::InvalidItoc)?;
        let id = u32::try_from(id_u64).map_err(|_| CpkReaderError::InvalidItoc)?;
        let file_size_u64 = numeric_at(table, row, file_size_col)
            .ok_or(CpkReaderError::MissingFileSize)?;
        let file_size = u32::try_from(file_size_u64)
            .map_err(|_| CpkReaderError::FileTooLarge(file_size_u64))?;
        let extract_size_u64 = numeric_at(table, row, extract_size_col).unwrap_or(file_size_u64);
        let extract_size = u32::try_from(extract_size_u64)
            .map_err(|_| CpkReaderError::FileTooLarge(extract_size_u64))?;
        let file_crc = crc_col
            .and_then(|column| numeric_at(table, row, column))
            .and_then(|value| u32::try_from(value).ok());
        rows.push(ItocRow {
            id,
            file_size,
            extract_size,
            file_crc,
        });
    }
    Ok(())
}

fn materialize_itoc_rows(
    rows: &[ItocRow],
    content_offset: u64,
    alignment: u64,
) -> Result<Vec<CpkFile>, Box<dyn Error>> {
    let mut relative_offset = 0u64;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        let absolute_offset = content_offset
            .checked_add(relative_offset)
            .ok_or(CpkReaderError::MissingFileOffset)?;
        let file_name = format!("{:05}.bin", row.id);
        files.push(CpkFile::new(
            "",
            file_name,
            relative_offset,
            absolute_offset,
            row.file_size,
            row.extract_size,
            Some(row.id),
            "",
            row.file_crc,
        ));
        let padded_size = align_up(u64::from(row.file_size), alignment)
            .ok_or(CpkReaderError::MissingFileOffset)?;
        relative_offset = relative_offset
            .checked_add(padded_size)
            .ok_or(CpkReaderError::MissingFileOffset)?;
    }
    Ok(files)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment <= 1 { return Some(value); }
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}
