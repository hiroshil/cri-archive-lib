use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(feature = "cpk_encryption_p5r")]
use crate::cpk::encrypt::data::FileDecryptor;
#[cfg(feature = "cpk_encryption_p5r")]
use crate::cpk::encrypt::p5r::P5RDecryptor;
use crate::cpk::header::{CpkChunkKind, CPK_CHUNK_HEADER_SIZE};

const ENGINE_INDEX_BASE: u64 = 0x800;
const COPYRIGHT_MARKER_OFFSET: u64 = ENGINE_INDEX_BASE - 6;

#[derive(Debug)]
pub enum CpkWriterError {
    InvalidAlignment(u32),
    EmptyInput,
    HeaderTooLarge(usize),
    FileTooLarge(PathBuf, u64),
    TooManyFiles(usize),
    NonUtf8Path(PathBuf),
    UnsupportedP5rEncryption,
    ArithmeticOverflow,
    DuplicateItocId(u32),
    ItocIdTooLarge(u32),
    ItocContentOffsetTooLarge(u64),
    InvalidRawPayload(PathBuf),
}

impl Display for CpkWriterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAlignment(value) => {
                write!(f, "alignment must be a power of two in 1..=65535, got {value}")
            }
            Self::EmptyInput => f.write_str("input directory contains no files"),
            Self::HeaderTooLarge(size) => {
                write!(f, "CPK header does not fit before 0x800 ({size:#x} bytes)")
            }
            Self::FileTooLarge(path, size) => write!(
                f,
                "{} is too large for a CPK FileSize field ({size} bytes)",
                path.display()
            ),
            Self::TooManyFiles(count) => write!(f, "file count does not fit in u32: {count}"),
            Self::NonUtf8Path(path) => {
                write!(f, "path is not valid UTF-8: {}", path.display())
            }
            Self::UnsupportedP5rEncryption => {
                f.write_str("P5R encryption requires feature cpk_encryption_p5r")
            }
            Self::ArithmeticOverflow => f.write_str("CPK size calculation overflowed"),
            Self::DuplicateItocId(id) => write!(f, "duplicate ITOC ID: {id}"),
            Self::ItocIdTooLarge(id) => {
                write!(f, "ITOC IDs are 16-bit in the target engine, got {id}")
            }
            Self::ItocContentOffsetTooLarge(offset) => write!(
                f,
                "ITOC ContentOffset must fit the target engine's 32-bit offset state, got {offset:#x}"
            ),
            Self::InvalidRawPayload(path) => write!(
                f,
                "raw payload source is truncated or unreadable: {}",
                path.display()
            ),
        }
    }
}
impl Error for CpkWriterError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpkIndexMode {
    Toc,
    Itoc,
    TocAndItoc,
}

impl CpkIndexMode {
    fn has_toc(self) -> bool {
        matches!(self, Self::Toc | Self::TocAndItoc)
    }

    fn has_itoc(self) -> bool {
        matches!(self, Self::Itoc | Self::TocAndItoc)
    }

    fn cpk_mode(self) -> u32 {
        match self {
            Self::Itoc => 0,
            Self::Toc => 1,
            Self::TocAndItoc => 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CpkWriterOptions {
    pub alignment: u16,
    /// Reapply Persona 5 Royal's symmetric file transform to rebuilt entries
    /// marked with `CRI_CFATTR:ENCRYPT`. Raw-reused entries are copied as-is.
    pub p5r_encryption: bool,
}

impl Default for CpkWriterOptions {
    fn default() -> Self {
        Self {
            alignment: 0x800,
            p5r_encryption: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CpkWriterProfile {
    pub index_mode: CpkIndexMode,
    /// Direct/EID ITOC stores the high-width rows directly in the ITOC table.
    /// Standard ITOC stores nested DataL/DataH tables.
    pub direct_itoc: bool,
    pub version: u16,
    pub revision: u16,
    pub update_date_time: u64,
    pub tvers: String,
    pub comment: String,
}

impl Default for CpkWriterProfile {
    fn default() -> Self {
        Self {
            index_mode: CpkIndexMode::Toc,
            direct_itoc: false,
            version: 7,
            revision: 0,
            update_date_time: 0,
            tvers: "7.0.0".to_owned(),
            comment: "Created by cri-cpk-cli".to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CpkRawPayload {
    pub archive_path: PathBuf,
    pub absolute_offset: u64,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct CpkInputFile {
    pub directory: String,
    pub file_name: String,
    /// Extracted file used by normal rebuild mode.
    pub source_path: PathBuf,
    /// Packed size written to FileSize. For a rebuilt entry this equals the
    /// extracted file length; for an optional raw-reused entry it is the
    /// original packed length.
    pub size: u32,
    pub extract_size: u32,
    pub id: u32,
    pub user_string: String,
    /// Optional original packed payload. This is an optimization only: all CPK
    /// headers and index tables are still rebuilt from the structural model.
    pub raw_payload: Option<CpkRawPayload>,
}

#[derive(Debug, Clone, Copy)]
pub struct CpkWriteReport {
    pub files: u32,
    pub toc_offset: u64,
    pub itoc_offset: u64,
    pub content_offset: u64,
    pub archive_size: u64,
}

pub struct CpkWriter;

impl CpkWriter {
    pub fn pack_directory<P: AsRef<Path>, Q: AsRef<Path>>(
        input_directory: P,
        output_file: Q,
        options: CpkWriterOptions,
    ) -> Result<CpkWriteReport, Box<dyn Error>> {
        validate_alignment(options.alignment)?;
        let input_directory = input_directory.as_ref();
        let output_file = output_file.as_ref();
        let files = collect_files(input_directory, output_file)?;
        if files.is_empty() {
            return Err(Box::new(CpkWriterError::EmptyInput));
        }
        Self::pack_files(output_file, &files, options)
    }

    pub fn pack_files<P: AsRef<Path>>(
        output_file: P,
        files: &[CpkInputFile],
        options: CpkWriterOptions,
    ) -> Result<CpkWriteReport, Box<dyn Error>> {
        Self::pack_files_with_profile(output_file, files, options, &CpkWriterProfile::default())
    }

    pub fn pack_files_with_profile<P: AsRef<Path>>(
        output_file: P,
        files: &[CpkInputFile],
        options: CpkWriterOptions,
        profile: &CpkWriterProfile,
    ) -> Result<CpkWriteReport, Box<dyn Error>> {
        let output_file = output_file.as_ref();
        if let Some(parent) = output_file.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = File::create(output_file)?;
        let mut output = BufWriter::new(file);
        let report = Self::write_with_profile(&mut output, files, options, profile)?;
        output.flush()?;
        Ok(report)
    }

    pub fn write<W: Write + Seek>(
        output: &mut W,
        files: &[CpkInputFile],
        options: CpkWriterOptions,
    ) -> Result<CpkWriteReport, Box<dyn Error>> {
        Self::write_with_profile(output, files, options, &CpkWriterProfile::default())
    }

    /// Rebuild a complete CPK structure. `raw_payload` only changes where an
    /// entry's packed bytes come from; it never bypasses header/TOC/ITOC
    /// serialization.
    pub fn write_with_profile<W: Write + Seek>(
        output: &mut W,
        files: &[CpkInputFile],
        options: CpkWriterOptions,
        profile: &CpkWriterProfile,
    ) -> Result<CpkWriteReport, Box<dyn Error>> {
        validate_alignment(options.alignment)?;
        if files.is_empty() {
            return Err(Box::new(CpkWriterError::EmptyInput));
        }
        let file_count = u32::try_from(files.len())
            .map_err(|_| CpkWriterError::TooManyFiles(files.len()))?;
        let alignment = u64::from(options.alignment);

        let physical_order = build_physical_order(files, profile)?;
        let zero_offsets = vec![0u64; files.len()];
        let toc_probe = if profile.index_mode.has_toc() {
            Some(build_toc_table(files, &zero_offsets)?)
        } else {
            None
        };
        let itoc_probe = if profile.index_mode.has_itoc() {
            Some(build_itoc_table(files, &physical_order, profile.direct_itoc)?)
        } else {
            None
        };

        let mut metadata_cursor = ENGINE_INDEX_BASE;
        let toc_offset = if let Some(table) = toc_probe.as_ref() {
            let offset = metadata_cursor;
            metadata_cursor = align_up(
                metadata_cursor
                    .checked_add(chunk_size(table)?)
                    .ok_or(CpkWriterError::ArithmeticOverflow)?,
                alignment,
            )?;
            offset
        } else {
            0
        };
        let itoc_offset = if let Some(table) = itoc_probe.as_ref() {
            let offset = metadata_cursor;
            metadata_cursor = align_up(
                metadata_cursor
                    .checked_add(chunk_size(table)?)
                    .ok_or(CpkWriterError::ArithmeticOverflow)?,
                alignment,
            )?;
            offset
        } else {
            0
        };
        let content_offset = align_up(metadata_cursor, alignment)?;
        // FUN_81066c36 copies only the low 32 bits of ContentOffset into the
        // ITOC state used by FUN_81066ed2. Reject a structurally unaddressable
        // archive instead of emitting offsets that wrap in the target engine.
        if profile.index_mode.has_itoc() && content_offset > u64::from(u32::MAX) {
            return Err(Box::new(CpkWriterError::ItocContentOffsetTooLarge(
                content_offset,
            )));
        }

        let mut absolute_offsets = vec![0u64; files.len()];
        let mut absolute_cursor = content_offset;
        for &index in &physical_order {
            absolute_offsets[index] = absolute_cursor;
            absolute_cursor = absolute_cursor
                .checked_add(u64::from(files[index].size))
                .ok_or(CpkWriterError::ArithmeticOverflow)?;
            absolute_cursor = align_up(absolute_cursor, alignment)?;
        }
        let archive_size = absolute_cursor;
        let content_size = archive_size
            .checked_sub(content_offset)
            .ok_or(CpkWriterError::ArithmeticOverflow)?;

        let toc_table = if profile.index_mode.has_toc() {
            let offsets = absolute_offsets
                .iter()
                .map(|offset| {
                    offset
                        .checked_sub(ENGINE_INDEX_BASE)
                        .ok_or(CpkWriterError::ArithmeticOverflow)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some(build_toc_table(files, &offsets)?)
        } else {
            None
        };
        let itoc_table = if profile.index_mode.has_itoc() {
            Some(build_itoc_table(files, &physical_order, profile.direct_itoc)?)
        } else {
            None
        };
        if toc_probe.as_ref().map(Vec::len) != toc_table.as_ref().map(Vec::len)
            || itoc_probe.as_ref().map(Vec::len) != itoc_table.as_ref().map(Vec::len)
        {
            return Err(Box::new(CpkWriterError::ArithmeticOverflow));
        }

        let toc_chunk = toc_table
            .as_ref()
            .map(|table| build_chunk(CpkChunkKind::Toc, table));
        let itoc_chunk = itoc_table
            .as_ref()
            .map(|table| build_chunk(CpkChunkKind::Itoc, table));
        let header_table = build_header_table(
            archive_size,
            content_offset,
            content_size,
            toc_offset,
            toc_chunk.as_ref().map_or(0, |chunk| chunk.len() as u64),
            itoc_offset,
            itoc_chunk.as_ref().map_or(0, |chunk| chunk.len() as u64),
            options.alignment,
            file_count,
            profile,
        )?;
        let header_chunk = build_chunk(CpkChunkKind::Cpk, &header_table);
        if header_chunk.len() > COPYRIGHT_MARKER_OFFSET as usize {
            return Err(Box::new(CpkWriterError::HeaderTooLarge(header_chunk.len())));
        }

        output.seek(SeekFrom::Start(0))?;
        output.write_all(&header_chunk)?;
        write_zeros(
            output,
            COPYRIGHT_MARKER_OFFSET
                .checked_sub(header_chunk.len() as u64)
                .ok_or(CpkWriterError::ArithmeticOverflow)?,
        )?;
        output.write_all(b"(c)CRI")?;

        if let Some(chunk) = toc_chunk.as_ref() {
            write_at(output, toc_offset, chunk)?;
        }
        if let Some(chunk) = itoc_chunk.as_ref() {
            write_at(output, itoc_offset, chunk)?;
        }
        let current = output.stream_position()?;
        if current < content_offset {
            write_zeros(output, content_offset - current)?;
        }

        for &index in &physical_order {
            let file = &files[index];
            let target = absolute_offsets[index];
            let current = output.stream_position()?;
            if current > target {
                return Err(Box::new(CpkWriterError::ArithmeticOverflow));
            }
            if current < target {
                write_zeros(output, target - current)?;
            }
            let copied = write_file_payload(output, file, options.p5r_encryption)?;
            if copied != u64::from(file.size) {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "{} changed packed size while packing (expected {}, wrote {copied})",
                        file.source_path.display(),
                        file.size
                    ),
                )));
            }
        }
        let current = output.stream_position()?;
        if current < archive_size {
            write_zeros(output, archive_size - current)?;
        }

        Ok(CpkWriteReport {
            files: file_count,
            toc_offset,
            itoc_offset,
            content_offset,
            archive_size,
        })
    }
}

fn collect_files(root: &Path, output_file: &Path) -> Result<Vec<CpkInputFile>, Box<dyn Error>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = Vec::new();
    let output_absolute = output_file.canonicalize().ok();

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if matches!(
                path.file_name().and_then(|value| value.to_str()),
                Some(".cri-cpk-manifest-v1") | Some(".cri-cpk-manifest-v2")
            ) {
                continue;
            }
            if let (Some(output), Ok(candidate)) = (output_absolute.as_ref(), path.canonicalize()) {
                if &candidate == output {
                    continue;
                }
            }
            let relative = path.strip_prefix(root)?;
            let file_name = relative
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| CpkWriterError::NonUtf8Path(path.clone()))?
                .to_owned();
            let directory = relative
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(path_to_cri_string)
                .transpose()?
                .unwrap_or_default();
            let size_u64 = entry.metadata()?.len();
            let size = u32::try_from(size_u64)
                .map_err(|_| CpkWriterError::FileTooLarge(path.clone(), size_u64))?;
            result.push(CpkInputFile {
                directory,
                file_name,
                source_path: path,
                size,
                extract_size: size,
                id: 0,
                user_string: String::new(),
                raw_payload: None,
            });
        }
    }
    result.sort_by(|a, b| {
        engine_path_key(a)
            .cmp(&engine_path_key(b))
            .then_with(|| a.id.cmp(&b.id))
    });
    let file_count = result.len();
    for (index, file) in result.iter_mut().enumerate() {
        file.id = u32::try_from(index).map_err(|_| CpkWriterError::TooManyFiles(file_count))?;
    }
    Ok(result)
}

fn engine_path_key(file: &CpkInputFile) -> String {
    let mut key = String::with_capacity(file.directory.len() + file.file_name.len() + 1);
    if !file.directory.is_empty() {
        key.push_str(&file.directory.replace('\\', "/"));
        key.push('/');
    }
    key.push_str(&file.file_name.replace('\\', "/"));
    key.make_ascii_uppercase();
    key
}

fn path_to_cri_string(path: &Path) -> Result<String, CpkWriterError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let value = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| CpkWriterError::NonUtf8Path(path.to_path_buf()))?;
        parts.push(value);
    }
    Ok(parts.join("/"))
}

fn validate_alignment(alignment: u16) -> Result<(), Box<dyn Error>> {
    let value = u32::from(alignment);
    if value == 0 || !value.is_power_of_two() {
        return Err(Box::new(CpkWriterError::InvalidAlignment(value)));
    }
    Ok(())
}

fn build_physical_order(
    files: &[CpkInputFile],
    profile: &CpkWriterProfile,
) -> Result<Vec<usize>, Box<dyn Error>> {
    if !profile.index_mode.has_itoc() {
        return Ok((0..files.len()).collect());
    }

    let mut used_ids = HashSet::with_capacity(files.len());
    for file in files {
        if file.id > u16::MAX as u32 {
            return Err(Box::new(CpkWriterError::ItocIdTooLarge(file.id)));
        }
        if !used_ids.insert(file.id) {
            return Err(Box::new(CpkWriterError::DuplicateItocId(file.id)));
        }
    }

    // Direct and standard ITOC use the same physical payload order: IDs
    // ascending across the union of DataL and DataH. FUN_8106706C obtains the
    // insertion index in the opposite table and FUN_81066ED2 sums both ID
    // prefixes, which is exactly a stable merge rather than low-then-high.
    let mut order = (0..files.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| files[*index].id);
    Ok(order)
}

#[allow(clippy::too_many_arguments)]
fn build_header_table(
    archive_size: u64,
    content_offset: u64,
    content_size: u64,
    toc_offset: u64,
    toc_size: u64,
    itoc_offset: u64,
    itoc_size: u64,
    alignment: u16,
    file_count: u32,
    profile: &CpkWriterProfile,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let columns = vec![
        UtfColumn::new("UpdateDateTime", UtfType::UInt64),
        UtfColumn::new("FileSize", UtfType::UInt64),
        UtfColumn::new("ContentOffset", UtfType::UInt64),
        UtfColumn::new("ContentSize", UtfType::UInt64),
        UtfColumn::new("TocOffset", UtfType::UInt64),
        UtfColumn::new("TocSize", UtfType::UInt64),
        UtfColumn::new("EtocOffset", UtfType::UInt64),
        UtfColumn::new("EtocSize", UtfType::UInt64),
        UtfColumn::new("ItocOffset", UtfType::UInt64),
        UtfColumn::new("ItocSize", UtfType::UInt64),
        UtfColumn::new("GtocOffset", UtfType::UInt64),
        UtfColumn::new("GtocSize", UtfType::UInt64),
        UtfColumn::new("Files", UtfType::UInt32),
        UtfColumn::new("Version", UtfType::UInt16),
        UtfColumn::new("Revision", UtfType::UInt16),
        UtfColumn::new("Align", UtfType::UInt16),
        UtfColumn::new("Sorted", UtfType::UInt16),
        UtfColumn::new("EID", UtfType::UInt16),
        UtfColumn::new("EnableFileName", UtfType::UInt16),
        UtfColumn::new("CpkMode", UtfType::UInt32),
        UtfColumn::new("Tvers", UtfType::String),
        UtfColumn::new("Comment", UtfType::String),
        UtfColumn::new("Codec", UtfType::UInt32),
        UtfColumn::new("DpkItoc", UtfType::UInt32),
        UtfColumn::new("EnableTocCrc", UtfType::UInt16),
        UtfColumn::new("EnableFileCrc", UtfType::UInt16),
    ];
    let row = vec![
        UtfValue::UInt64(profile.update_date_time),
        UtfValue::UInt64(archive_size),
        UtfValue::UInt64(content_offset),
        UtfValue::UInt64(content_size),
        UtfValue::UInt64(toc_offset),
        UtfValue::UInt64(toc_size),
        UtfValue::UInt64(0),
        UtfValue::UInt64(0),
        UtfValue::UInt64(itoc_offset),
        UtfValue::UInt64(itoc_size),
        UtfValue::UInt64(0),
        UtfValue::UInt64(0),
        UtfValue::UInt32(file_count),
        UtfValue::UInt16(profile.version),
        UtfValue::UInt16(profile.revision),
        UtfValue::UInt16(alignment),
        // The TOC is deliberately advertised as unsorted. The engine then uses
        // linear lookup and does not require the proprietary path comparator.
        UtfValue::UInt16(0),
        UtfValue::UInt16(if profile.index_mode.has_itoc() && profile.direct_itoc { 1 } else { 0 }),
        UtfValue::UInt16(if profile.index_mode.has_toc() { 1 } else { 0 }),
        UtfValue::UInt32(profile.index_mode.cpk_mode()),
        UtfValue::String(profile.tvers.clone()),
        UtfValue::String(profile.comment.clone()),
        UtfValue::UInt32(0),
        UtfValue::UInt32(0),
        UtfValue::UInt16(0),
        UtfValue::UInt16(0),
    ];
    UtfTableBuilder::new("CpkHeader", columns, vec![row]).build()
}

fn build_toc_table(files: &[CpkInputFile], offsets: &[u64]) -> Result<Vec<u8>, Box<dyn Error>> {
    let columns = vec![
        UtfColumn::new("DirName", UtfType::String),
        UtfColumn::new("FileName", UtfType::String),
        UtfColumn::new("FileSize", UtfType::UInt32),
        UtfColumn::new("ExtractSize", UtfType::UInt32),
        UtfColumn::new("FileOffset", UtfType::UInt64),
        UtfColumn::new("ID", UtfType::UInt32),
        UtfColumn::new("UserString", UtfType::String),
    ];
    let mut rows = Vec::with_capacity(files.len());
    for (file, offset) in files.iter().zip(offsets.iter()) {
        rows.push(vec![
            UtfValue::String(file.directory.clone()),
            UtfValue::String(file.file_name.clone()),
            UtfValue::UInt32(file.size),
            UtfValue::UInt32(file.extract_size),
            UtfValue::UInt64(*offset),
            UtfValue::UInt32(file.id),
            UtfValue::String(file.user_string.clone()),
        ]);
    }
    UtfTableBuilder::new("CpkTocInfo", columns, rows).build()
}

fn build_itoc_table(
    files: &[CpkInputFile],
    physical_order: &[usize],
    direct: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if direct {
        return build_itoc_rows(files, physical_order, false, "CpkExtendId");
    }

    // The nested tables remain independent ID-sorted indexes, but their rows
    // do not define two contiguous payload regions. The engine merges their
    // prefixes by ID when calculating each physical offset.
    let mut low = Vec::new();
    let mut high = Vec::new();
    for &index in physical_order {
        if files[index].size <= u16::MAX as u32
            && files[index].extract_size <= u16::MAX as u32
        {
            low.push(index);
        } else {
            high.push(index);
        }
    }

    // The target engine unconditionally constructs both nested parsers when
    // EID is zero. Omitting DataL or DataH makes it call the UTF parser with a
    // null pointer and a 0xffff_ffff length, so even an empty group must be
    // represented by a valid zero-row table.
    let columns = vec![
        UtfColumn::new("DataL", UtfType::Data),
        UtfColumn::new("DataH", UtfType::Data),
    ];
    let row = vec![
        UtfValue::Data(build_itoc_rows(files, &low, true, "CpkItocL")?),
        UtfValue::Data(build_itoc_rows(files, &high, false, "CpkItocH")?),
    ];
    UtfTableBuilder::new("CpkItocInfo", columns, vec![row]).build()
}

fn build_itoc_rows(
    files: &[CpkInputFile],
    indices: &[usize],
    low_width: bool,
    table_name: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let size_type = if low_width {
        UtfType::UInt16
    } else {
        UtfType::UInt32
    };
    let columns = vec![
        UtfColumn::new("ID", UtfType::UInt16),
        UtfColumn::new("FileSize", size_type),
        UtfColumn::new("ExtractSize", size_type),
    ];
    let mut rows = Vec::with_capacity(indices.len());
    for &index in indices {
        let file = &files[index];
        let id = u16::try_from(file.id).map_err(|_| CpkWriterError::ItocIdTooLarge(file.id))?;
        if low_width {
            rows.push(vec![
                UtfValue::UInt16(id),
                UtfValue::UInt16(
                    u16::try_from(file.size)
                        .map_err(|_| CpkWriterError::ArithmeticOverflow)?,
                ),
                UtfValue::UInt16(
                    u16::try_from(file.extract_size)
                        .map_err(|_| CpkWriterError::ArithmeticOverflow)?,
                ),
            ]);
        } else {
            rows.push(vec![
                UtfValue::UInt16(id),
                UtfValue::UInt32(file.size),
                UtfValue::UInt32(file.extract_size),
            ]);
        }
    }
    UtfTableBuilder::new(table_name, columns, rows).build()
}

fn build_chunk(kind: CpkChunkKind, table: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(CPK_CHUNK_HEADER_SIZE + table.len());
    output.extend_from_slice(&kind.magic());
    // Nonzero means the embedded @UTF table is stored in plaintext.
    output.extend_from_slice(&[0xff; 4]);
    output.extend_from_slice(&(table.len() as u64).to_le_bytes());
    output.extend_from_slice(table);
    output
}

fn chunk_size(table: &[u8]) -> Result<u64, CpkWriterError> {
    (CPK_CHUNK_HEADER_SIZE as u64)
        .checked_add(u64::try_from(table.len()).map_err(|_| CpkWriterError::ArithmeticOverflow)?)
        .ok_or(CpkWriterError::ArithmeticOverflow)
}

fn write_at<W: Write + Seek>(output: &mut W, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let current = output.stream_position()?;
    if current < offset {
        write_zeros(output, offset - current)?;
    } else if current > offset {
        output.seek(SeekFrom::Start(offset))?;
    }
    output.write_all(bytes)
}

fn write_file_payload<W: Write>(
    output: &mut W,
    file: &CpkInputFile,
    p5r_encryption: bool,
) -> Result<u64, Box<dyn Error>> {
    if let Some(raw) = file.raw_payload.as_ref() {
        if raw.size != file.size {
            return Err(Box::new(CpkWriterError::InvalidRawPayload(
                raw.archive_path.clone(),
            )));
        }
        let mut input = BufReader::new(File::open(&raw.archive_path)?);
        input.seek(SeekFrom::Start(raw.absolute_offset))?;
        let mut limited = input.take(u64::from(raw.size));
        let copied = io::copy(&mut limited, output)?;
        if copied != u64::from(raw.size) {
            return Err(Box::new(CpkWriterError::InvalidRawPayload(
                raw.archive_path.clone(),
            )));
        }
        return Ok(copied);
    }

    if p5r_encryption && file.user_string == "CRI_CFATTR:ENCRYPT" {
        #[cfg(feature = "cpk_encryption_p5r")]
        {
            let mut data = fs::read(&file.source_path)?;
            P5RDecryptor::decrypt_in_place(&mut data);
            output.write_all(&data)?;
            return Ok(data.len() as u64);
        }
        #[cfg(not(feature = "cpk_encryption_p5r"))]
        return Err(Box::new(CpkWriterError::UnsupportedP5rEncryption));
    }

    let mut input = BufReader::new(File::open(&file.source_path)?);
    Ok(io::copy(&mut input, output)?)
}

fn write_zeros<W: Write>(output: &mut W, mut count: u64) -> io::Result<()> {
    const ZEROES: [u8; 0x2000] = [0; 0x2000];
    while count != 0 {
        let write = usize::try_from(count.min(ZEROES.len() as u64)).unwrap();
        output.write_all(&ZEROES[..write])?;
        count -= write as u64;
    }
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Result<u64, CpkWriterError> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(CpkWriterError::ArithmeticOverflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UtfType {
    UInt16 = 2,
    UInt32 = 4,
    UInt64 = 6,
    String = 10,
    Data = 11,
}

impl UtfType {
    fn size(self) -> usize {
        match self {
            Self::UInt16 => 2,
            Self::UInt32 | Self::String => 4,
            Self::UInt64 | Self::Data => 8,
        }
    }
}

#[derive(Debug, Clone)]
struct UtfColumn {
    name: String,
    value_type: UtfType,
}

impl UtfColumn {
    fn new(name: &str, value_type: UtfType) -> Self {
        Self {
            name: name.to_owned(),
            value_type,
        }
    }
}

#[derive(Debug, Clone)]
enum UtfValue {
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    String(String),
    Data(Vec<u8>),
}

impl UtfValue {
    fn value_type(&self) -> UtfType {
        match self {
            Self::UInt16(_) => UtfType::UInt16,
            Self::UInt32(_) => UtfType::UInt32,
            Self::UInt64(_) => UtfType::UInt64,
            Self::String(_) => UtfType::String,
            Self::Data(_) => UtfType::Data,
        }
    }
}

struct UtfTableBuilder {
    name: String,
    columns: Vec<UtfColumn>,
    rows: Vec<Vec<UtfValue>>,
}

impl UtfTableBuilder {
    fn new(name: &str, columns: Vec<UtfColumn>, rows: Vec<Vec<UtfValue>>) -> Self {
        Self {
            name: name.to_owned(),
            columns,
            rows,
        }
    }

    fn build(self) -> Result<Vec<u8>, Box<dyn Error>> {
        let column_count = u16::try_from(self.columns.len())
            .map_err(|_| CpkWriterError::ArithmeticOverflow)?;
        let row_count =
            u32::try_from(self.rows.len()).map_err(|_| CpkWriterError::ArithmeticOverflow)?;
        let row_size_usize = self
            .columns
            .iter()
            .map(|column| column.value_type.size())
            .sum::<usize>();
        let row_size =
            u16::try_from(row_size_usize).map_err(|_| CpkWriterError::ArithmeticOverflow)?;
        for row in &self.rows {
            if row.len() != self.columns.len() {
                return Err(Box::new(CpkWriterError::ArithmeticOverflow));
            }
            for (value, column) in row.iter().zip(self.columns.iter()) {
                if value.value_type() != column.value_type {
                    return Err(Box::new(CpkWriterError::ArithmeticOverflow));
                }
            }
        }

        let mut strings = Vec::<u8>::new();
        let mut string_offsets = HashMap::<String, u32>::new();
        // Offset zero is CRI's null string reference. Keeping a NUL byte there
        // means an empty Rust string serializes as null without exposing the
        // literal "<NULL>" to the engine.
        strings.push(0);
        string_offsets.insert(String::new(), 0);
        let table_name_offset = intern_string(&self.name, &mut strings, &mut string_offsets)?;
        let mut column_name_offsets = Vec::with_capacity(self.columns.len());
        for column in &self.columns {
            column_name_offsets.push(intern_string(
                &column.name,
                &mut strings,
                &mut string_offsets,
            )?);
        }
        for row in &self.rows {
            for value in row {
                if let UtfValue::String(value) = value {
                    let _ = intern_string(value, &mut strings, &mut string_offsets)?;
                }
            }
        }

        let mut data_pool = Vec::new();
        let mut data_locations = HashMap::<(usize, usize), (u32, u32)>::new();
        for (row_index, row) in self.rows.iter().enumerate() {
            for (column_index, value) in row.iter().enumerate() {
                if let UtfValue::Data(value) = value {
                    let offset = u32::try_from(data_pool.len())
                        .map_err(|_| CpkWriterError::ArithmeticOverflow)?;
                    let length = u32::try_from(value.len())
                        .map_err(|_| CpkWriterError::ArithmeticOverflow)?;
                    data_pool.extend_from_slice(value);
                    data_locations.insert((row_index, column_index), (offset, length));
                }
            }
        }

        let rows_start = 0x20usize
            .checked_add(
                self.columns
                    .len()
                    .checked_mul(5)
                    .ok_or(CpkWriterError::ArithmeticOverflow)?,
            )
            .ok_or(CpkWriterError::ArithmeticOverflow)?;
        let rows_bytes = row_size_usize
            .checked_mul(self.rows.len())
            .ok_or(CpkWriterError::ArithmeticOverflow)?;
        let string_pool_start = rows_start
            .checked_add(rows_bytes)
            .ok_or(CpkWriterError::ArithmeticOverflow)?;
        let data_pool_start = string_pool_start
            .checked_add(strings.len())
            .ok_or(CpkWriterError::ArithmeticOverflow)?;
        let total_size = data_pool_start
            .checked_add(data_pool.len())
            .ok_or(CpkWriterError::ArithmeticOverflow)?;
        let table_size_field = u32::try_from(
            total_size
                .checked_sub(8)
                .ok_or(CpkWriterError::ArithmeticOverflow)?,
        )
        .map_err(|_| CpkWriterError::ArithmeticOverflow)?;

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(b"@UTF");
        output.extend_from_slice(&table_size_field.to_be_bytes());
        // The target runtime uses its engine-specific 24-byte UTF header:
        // marker, encoding selector, u16 RowsOffset, then three u32 offsets.
        output.push(0);
        output.push(1); // UTF-8
        output.extend_from_slice(
            &u16::try_from(rows_start - 8)
                .map_err(|_| CpkWriterError::ArithmeticOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(string_pool_start - 8)
                .map_err(|_| CpkWriterError::ArithmeticOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(data_pool_start - 8)
                .map_err(|_| CpkWriterError::ArithmeticOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&table_name_offset.to_be_bytes());
        output.extend_from_slice(&column_count.to_be_bytes());
        output.extend_from_slice(&row_size.to_be_bytes());
        output.extend_from_slice(&row_count.to_be_bytes());

        for (column, name_offset) in self.columns.iter().zip(column_name_offsets.iter()) {
            output.push(0x50 | column.value_type as u8); // named + row storage
            output.extend_from_slice(&name_offset.to_be_bytes());
        }
        for (row_index, row) in self.rows.iter().enumerate() {
            for (column_index, value) in row.iter().enumerate() {
                match value {
                    UtfValue::UInt16(value) => output.extend_from_slice(&value.to_be_bytes()),
                    UtfValue::UInt32(value) => output.extend_from_slice(&value.to_be_bytes()),
                    UtfValue::UInt64(value) => output.extend_from_slice(&value.to_be_bytes()),
                    UtfValue::String(value) => {
                        let offset = *string_offsets
                            .get(value)
                            .ok_or(CpkWriterError::ArithmeticOverflow)?;
                        output.extend_from_slice(&offset.to_be_bytes());
                    }
                    UtfValue::Data(_) => {
                        let (offset, length) = data_locations
                            .get(&(row_index, column_index))
                            .copied()
                            .ok_or(CpkWriterError::ArithmeticOverflow)?;
                        output.extend_from_slice(&offset.to_be_bytes());
                        output.extend_from_slice(&length.to_be_bytes());
                    }
                }
            }
        }
        output.extend_from_slice(&strings);
        output.extend_from_slice(&data_pool);
        debug_assert_eq!(output.len(), total_size);
        Ok(output)
    }
}

fn intern_string(
    value: &str,
    pool: &mut Vec<u8>,
    offsets: &mut HashMap<String, u32>,
) -> Result<u32, Box<dyn Error>> {
    if let Some(offset) = offsets.get(value) {
        return Ok(*offset);
    }
    let offset = u32::try_from(pool.len()).map_err(|_| CpkWriterError::ArithmeticOverflow)?;
    pool.extend_from_slice(value.as_bytes());
    pool.push(0);
    offsets.insert(value.to_owned(), offset);
    Ok(offset)
}
