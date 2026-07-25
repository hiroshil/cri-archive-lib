#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpkFile {
    /// Directory in which the file is contained (`DirName` in a TOC table).
    directory: String,
    /// File name (`FileName` in a TOC table). ITOC-only archives do not store
    /// names; in that case this is a deterministic `<ID>.bin` fallback.
    file_name: String,
    /// Offset stored by the table, relative to the table-specific data base.
    file_offset: u64,
    /// Absolute offset from the beginning of the CPK stream.
    absolute_offset: u64,
    /// Packed size stored in the archive.
    file_size: u32,
    /// Size after extraction/decompression.
    extract_size: u32,
    /// Optional numeric ID used by TOC/ITOC lookup.
    id: Option<u32>,
    /// Optional developer-defined metadata.
    user_string: String,
    /// Optional CRC value carried by TOC/ITOC. The reader exposes it for
    /// diagnostics, but rebuilt archives disable file CRC unless a writer can
    /// recompute the engine's exact CRC policy.
    file_crc: Option<u32>,
}

impl CpkFile {
    pub fn directory(&self) -> &str {
        &self.directory
    }
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }
    pub fn absolute_offset(&self) -> u64 {
        self.absolute_offset
    }
    pub fn file_size(&self) -> u32 {
        self.file_size
    }
    pub fn extract_size(&self) -> u32 {
        self.extract_size
    }
    pub fn id(&self) -> Option<u32> {
        self.id
    }
    pub fn user_string(&self) -> &str {
        &self.user_string
    }
    pub fn file_crc(&self) -> Option<u32> {
        self.file_crc
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        directory: impl Into<String>,
        file_name: impl Into<String>,
        file_offset: u64,
        absolute_offset: u64,
        file_size: u32,
        extract_size: u32,
        id: Option<u32>,
        user_string: impl Into<String>,
        file_crc: Option<u32>,
    ) -> Self {
        Self {
            directory: directory.into(),
            file_name: file_name.into(),
            file_offset,
            absolute_offset,
            file_size,
            extract_size: if extract_size == 0 {
                file_size
            } else {
                extract_size
            },
            id,
            user_string: user_string.into(),
            file_crc,
        }
    }
}
