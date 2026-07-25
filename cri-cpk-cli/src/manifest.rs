use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

use cri_archive_lib::cpk::writer::{
    CpkIndexMode, CpkInputFile, CpkRawPayload, CpkWriterProfile,
};

pub const MANIFEST_FILE_NAME: &str = ".cri-cpk-manifest-v2";
const LEGACY_MANIFEST_FILE_NAME: &str = ".cri-cpk-manifest-v1";
const MANIFEST_MAGIC: &str = "CRI_CPK_MANIFEST_V2";
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub directory: String,
    pub file_name: String,
    pub id: u32,
    pub user_string: String,
    pub extracted_size: u64,
    pub extracted_hash: u64,
    pub packed_size: u32,
    pub packed_offset: u64,
    pub packed_hash: u64,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub source_archive: PathBuf,
    pub archive_size: u64,
    pub archive_hash: u64,
    pub alignment: u16,
    pub has_toc: bool,
    pub has_itoc: bool,
    pub direct_itoc: bool,
    pub p5r: bool,
    pub version: u16,
    pub revision: u16,
    pub update_date_time: u64,
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn path(root: &Path) -> PathBuf {
        root.join(MANIFEST_FILE_NAME)
    }

    pub fn read(root: &Path) -> Result<Option<Self>, Box<dyn Error>> {
        let path = Self::path(root);
        if !path.is_file() {
            return Ok(None);
        }
        let text = fs::read_to_string(path)?;
        let mut lines = text.lines();
        if lines.next() != Some(MANIFEST_MAGIC) {
            return Err(invalid_data("unsupported CPK manifest version"));
        }

        let source_archive = PathBuf::from(decode_field(required_value(&mut lines, "source")?)?);
        let archive_size = parse_u64(required_value(&mut lines, "archive_size")?, "archive_size")?;
        let archive_hash =
            parse_hex_u64(required_value(&mut lines, "archive_hash")?, "archive_hash")?;
        let alignment_u64 = parse_u64(required_value(&mut lines, "alignment")?, "alignment")?;
        let alignment = u16::try_from(alignment_u64)
            .map_err(|_| invalid_data("manifest alignment exceeds u16"))?;
        let has_toc = parse_bool(required_value(&mut lines, "has_toc")?, "has_toc")?;
        let has_itoc = parse_bool(required_value(&mut lines, "has_itoc")?, "has_itoc")?;
        let direct_itoc =
            parse_bool(required_value(&mut lines, "direct_itoc")?, "direct_itoc")?;
        let p5r = parse_bool(required_value(&mut lines, "p5r")?, "p5r")?;
        let version_u64 = parse_u64(required_value(&mut lines, "version")?, "version")?;
        let revision_u64 = parse_u64(required_value(&mut lines, "revision")?, "revision")?;
        let version =
            u16::try_from(version_u64).map_err(|_| invalid_data("manifest version exceeds u16"))?;
        let revision = u16::try_from(revision_u64)
            .map_err(|_| invalid_data("manifest revision exceeds u16"))?;
        let update_date_time = parse_u64(
            required_value(&mut lines, "update_date_time")?,
            "update_date_time",
        )?;

        let mut entries = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split('\t');
            if fields.next() != Some("entry") {
                return Err(invalid_data("unknown CPK manifest record"));
            }
            let id = parse_u64(next_field(&mut fields, "entry ID")?, "entry ID")?;
            let extracted_size =
                parse_u64(next_field(&mut fields, "extracted size")?, "extracted size")?;
            let extracted_hash = parse_hex_u64(
                next_field(&mut fields, "extracted hash")?,
                "extracted hash",
            )?;
            let packed_size_u64 =
                parse_u64(next_field(&mut fields, "packed size")?, "packed size")?;
            let packed_offset =
                parse_u64(next_field(&mut fields, "packed offset")?, "packed offset")?;
            let packed_hash =
                parse_hex_u64(next_field(&mut fields, "packed hash")?, "packed hash")?;
            let directory = decode_field(next_field(&mut fields, "entry directory")?)?;
            let file_name = decode_field(next_field(&mut fields, "entry file name")?)?;
            let user_string = decode_field(next_field(&mut fields, "entry user string")?)?;
            if fields.next().is_some() {
                return Err(invalid_data("too many fields in CPK manifest entry"));
            }
            entries.push(ManifestEntry {
                directory,
                file_name,
                id: u32::try_from(id)
                    .map_err(|_| invalid_data("manifest entry ID exceeds u32"))?,
                user_string,
                extracted_size,
                extracted_hash,
                packed_size: u32::try_from(packed_size_u64)
                    .map_err(|_| invalid_data("manifest packed size exceeds u32"))?,
                packed_offset,
                packed_hash,
            });
        }

        if !has_toc && !has_itoc {
            return Err(invalid_data("manifest contains neither TOC nor ITOC"));
        }
        if direct_itoc && !has_itoc {
            return Err(invalid_data("direct ITOC flag without ITOC"));
        }

        Ok(Some(Self {
            source_archive,
            archive_size,
            archive_hash,
            alignment,
            has_toc,
            has_itoc,
            direct_itoc,
            p5r,
            version,
            revision,
            update_date_time,
            entries,
        }))
    }

    pub fn write(&self, root: &Path) -> Result<(), Box<dyn Error>> {
        let path = Self::path(root);
        let temporary = path.with_extension("tmp");
        let mut output = File::create(&temporary)?;
        writeln!(output, "{MANIFEST_MAGIC}")?;
        writeln!(
            output,
            "source\t{}",
            encode_field(&self.source_archive.to_string_lossy())
        )?;
        writeln!(output, "archive_size\t{}", self.archive_size)?;
        writeln!(output, "archive_hash\t{:016x}", self.archive_hash)?;
        writeln!(output, "alignment\t{}", self.alignment)?;
        writeln!(output, "has_toc\t{}", u8::from(self.has_toc))?;
        writeln!(output, "has_itoc\t{}", u8::from(self.has_itoc))?;
        writeln!(output, "direct_itoc\t{}", u8::from(self.direct_itoc))?;
        writeln!(output, "p5r\t{}", u8::from(self.p5r))?;
        writeln!(output, "version\t{}", self.version)?;
        writeln!(output, "revision\t{}", self.revision)?;
        writeln!(output, "update_date_time\t{}", self.update_date_time)?;
        for entry in &self.entries {
            writeln!(
                output,
                "entry\t{}\t{}\t{:016x}\t{}\t{}\t{:016x}\t{}\t{}\t{}",
                entry.id,
                entry.extracted_size,
                entry.extracted_hash,
                entry.packed_size,
                entry.packed_offset,
                entry.packed_hash,
                encode_field(&entry.directory),
                encode_field(&entry.file_name),
                encode_field(&entry.user_string),
            )?;
        }
        output.flush()?;
        drop(output);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn writer_profile(&self) -> CpkWriterProfile {
        let index_mode = match (self.has_toc, self.has_itoc) {
            (true, true) => CpkIndexMode::TocAndItoc,
            (true, false) => CpkIndexMode::Toc,
            (false, true) => CpkIndexMode::Itoc,
            (false, false) => unreachable!("manifest validation rejects empty index mode"),
        };
        CpkWriterProfile {
            index_mode,
            direct_itoc: self.direct_itoc,
            version: self.version,
            revision: self.revision,
            update_date_time: self.update_date_time,
            ..CpkWriterProfile::default()
        }
    }

    pub fn source_is_original(&self) -> Result<bool, Box<dyn Error>> {
        if !self.source_archive.is_file() {
            return Ok(false);
        }
        let (size, hash) = hash_file(&self.source_archive)?;
        Ok(size == self.archive_size && hash == self.archive_hash)
    }

    pub fn build_inputs(
        &self,
        root: &Path,
        output_archive: &Path,
        reuse_raw_entries: bool,
    ) -> Result<Vec<CpkInputFile>, Box<dyn Error>> {
        if reuse_raw_entries && !self.source_is_original()? {
            return Err(invalid_data(
                "--reuse-raw-entries requires the original source CPK to exist unchanged",
            ));
        }

        let mut files = Vec::new();
        let mut known_paths = HashSet::with_capacity(self.entries.len());
        let mut used_ids = HashSet::with_capacity(self.entries.len());

        for entry in &self.entries {
            let relative = safe_relative_path(&entry.directory, &entry.file_name)?;
            known_paths.insert(relative.clone());
            let source_path = root.join(relative);
            if !source_path.is_file() {
                continue;
            }
            let (current_size, current_hash) = hash_file(&source_path)?;
            let current_size_u32 = u32::try_from(current_size).map_err(|_| {
                invalid_data(format!("{} is too large for CPK", source_path.display()))
            })?;
            let unchanged =
                current_size == entry.extracted_size && current_hash == entry.extracted_hash;
            let raw_payload = if reuse_raw_entries && unchanged {
                Some(CpkRawPayload {
                    archive_path: self.source_archive.clone(),
                    absolute_offset: entry.packed_offset,
                    size: entry.packed_size,
                })
            } else {
                None
            };
            used_ids.insert(entry.id);
            files.push(CpkInputFile {
                directory: entry.directory.clone(),
                file_name: entry.file_name.clone(),
                source_path,
                size: raw_payload
                    .as_ref()
                    .map_or(current_size_u32, |raw| raw.size),
                extract_size: if raw_payload.is_some() {
                    u32::try_from(entry.extracted_size).map_err(|_| {
                        invalid_data("manifest extracted size exceeds CPK u32 range")
                    })?
                } else {
                    current_size_u32
                },
                id: entry.id,
                user_string: entry.user_string.clone(),
                raw_payload,
            });
        }

        let mut new_paths = collect_relative_files(root, output_archive)?
            .into_iter()
            .filter(|relative| !known_paths.contains(relative))
            .collect::<Vec<_>>();
        new_paths.sort();

        let mut free_ids = if self.has_itoc {
            (0..=u16::MAX as u32)
                .filter(|id| !used_ids.contains(id))
                .collect::<VecDeque<_>>()
        } else {
            VecDeque::new()
        };
        let mut next_toc_id = used_ids.iter().copied().max().unwrap_or(0);
        if !used_ids.is_empty() && !self.has_itoc {
            next_toc_id = next_toc_id
                .checked_add(1)
                .ok_or_else(|| invalid_data("no free CPK IDs"))?;
        }

        for relative in new_paths {
            let id = if self.has_itoc {
                free_ids
                    .pop_front()
                    .ok_or_else(|| invalid_data("ITOC has no free 16-bit IDs"))?
            } else {
                while used_ids.contains(&next_toc_id) {
                    next_toc_id = next_toc_id
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("no free CPK IDs"))?;
                }
                let id = next_toc_id;
                if next_toc_id != u32::MAX {
                    next_toc_id += 1;
                }
                id
            };
            let source_path = root.join(&relative);
            let size_u64 = source_path.metadata()?.len();
            let size = u32::try_from(size_u64).map_err(|_| {
                invalid_data(format!("{} is too large for CPK", source_path.display()))
            })?;
            let file_name = relative
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| invalid_data(format!("non-UTF-8 path: {}", relative.display())))?
                .to_owned();
            let directory = relative
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(path_to_cri_string)
                .transpose()?
                .unwrap_or_default();
            files.push(CpkInputFile {
                directory,
                file_name,
                source_path,
                size,
                extract_size: size,
                id,
                user_string: String::new(),
                raw_payload: None,
            });
            used_ids.insert(id);
        }

        Ok(files)
    }
}

pub fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub fn hash_file(path: &Path) -> Result<(u64, u64), Box<dyn Error>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut input = BufReader::new(file);
    let mut hash = FNV_OFFSET_BASIS;
    let mut buffer = [0u8; 0x10000];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    Ok((size, hash))
}

pub fn absolute_path(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if let Ok(path) = path.canonicalize() {
        return Ok(path);
    }
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

pub fn same_path(left: &Path, right: &Path) -> Result<bool, Box<dyn Error>> {
    if left.exists() && right.exists() {
        return Ok(left.canonicalize()? == right.canonicalize()?);
    }
    Ok(absolute_path(left)? == absolute_path(right)?)
}

fn collect_relative_files(
    root: &Path,
    output_archive: &Path,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = Vec::new();
    let manifest_path = absolute_path(&Manifest::path(root))?;
    let legacy_manifest_path = absolute_path(&root.join(LEGACY_MANIFEST_FILE_NAME))?;
    let output_path = absolute_path(output_archive)?;

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
            let absolute = absolute_path(&path)?;
            if absolute == manifest_path
                || absolute == legacy_manifest_path
                || absolute == output_path
            {
                continue;
            }
            result.push(path.strip_prefix(root)?.to_path_buf());
        }
    }
    Ok(result)
}

fn safe_relative_path(directory: &str, file_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let normalized_directory = directory.replace('\\', "/");
    let normalized_file_name = file_name.replace('\\', "/");
    let mut output = PathBuf::new();
    for component in Path::new(&normalized_directory)
        .components()
        .chain(Path::new(&normalized_file_name).components())
    {
        match component {
            Component::Normal(value) => output.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_data(format!(
                    "unsafe path in CPK manifest: {directory}/{file_name}"
                )));
            }
        }
    }
    if output.as_os_str().is_empty() {
        return Err(invalid_data("empty path in CPK manifest"));
    }
    Ok(output)
}

fn path_to_cri_string(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(invalid_data(format!(
                "unsafe input path: {}",
                path.display()
            )));
        };
        let value = value
            .to_str()
            .ok_or_else(|| invalid_data(format!("non-UTF-8 path: {}", path.display())))?;
        parts.push(value);
    }
    Ok(parts.join("/"))
}

fn required_value<'a, I>(lines: &mut I, key: &str) -> Result<&'a str, Box<dyn Error>>
where
    I: Iterator<Item = &'a str>,
{
    let line = lines
        .next()
        .ok_or_else(|| invalid_data(format!("manifest is missing {key}")))?;
    let mut fields = line.splitn(2, '\t');
    if fields.next() != Some(key) {
        return Err(invalid_data(format!("manifest expected {key}")));
    }
    fields
        .next()
        .ok_or_else(|| invalid_data(format!("manifest {key} has no value")))
}

fn next_field<'a, I>(fields: &mut I, name: &str) -> Result<&'a str, Box<dyn Error>>
where
    I: Iterator<Item = &'a str>,
{
    fields
        .next()
        .ok_or_else(|| invalid_data(format!("manifest is missing {name}")))
}

fn parse_u64(value: &str, name: &str) -> Result<u64, Box<dyn Error>> {
    value
        .parse::<u64>()
        .map_err(|_| invalid_data(format!("invalid manifest {name}")))
}

fn parse_hex_u64(value: &str, name: &str) -> Result<u64, Box<dyn Error>> {
    u64::from_str_radix(value, 16)
        .map_err(|_| invalid_data(format!("invalid manifest {name}")))
}

fn parse_bool(value: &str, name: &str) -> Result<bool, Box<dyn Error>> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(invalid_data(format!("invalid manifest {name}"))),
    }
}

fn encode_field(value: &str) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_field(value: &str) -> Result<String, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err(invalid_data("invalid hex string in CPK manifest"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16)
            .map_err(|_| invalid_data("invalid hex string in CPK manifest"))?;
        bytes.push(byte);
    }
    String::from_utf8(bytes).map_err(|_| invalid_data("manifest string is not UTF-8"))
}

fn invalid_data(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}
