#![cfg(feature = "cpk")]

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cri_archive_lib::cpk::reader::CpkReader;
use cri_archive_lib::cpk::writer::{
    CpkIndexMode, CpkInputFile, CpkWriter, CpkWriterOptions, CpkWriterProfile,
};

fn unique_temp_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cri-archive-lib-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn write_input(
    root: &Path,
    relative: &str,
    payload: &[u8],
    id: u32,
) -> Result<CpkInputFile, Box<dyn Error>> {
    let source_path = root.join(relative);
    if let Some(parent) = source_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&source_path, payload)?;
    let relative_path = Path::new(relative);
    let file_name = relative_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "test path has no UTF-8 file name",
            )
        })?
        .to_owned();
    let directory = relative_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    let size = u32::try_from(payload.len())?;
    Ok(CpkInputFile {
        directory,
        file_name,
        source_path,
        size,
        extract_size: size,
        id,
        user_string: String::new(),
        raw_payload: None,
    })
}

fn profile(index_mode: CpkIndexMode, direct_itoc: bool) -> CpkWriterProfile {
    CpkWriterProfile {
        index_mode,
        direct_itoc,
        ..CpkWriterProfile::default()
    }
}

fn assert_itoc_payloads(
    archive: &Path,
    expected: &[(u32, &[u8])],
) -> Result<(), Box<dyn Error>> {
    let mut reader = CpkReader::new(BufReader::new(File::open(archive)?))?;
    let files = reader.get_files()?;
    assert_eq!(files.len(), expected.len());
    let ids = files
        .iter()
        .map(|file| file.id().expect("ITOC row must have an ID"))
        .collect::<Vec<_>>();
    let mut expected_ids = expected.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    expected_ids.sort_unstable();
    assert_eq!(ids, expected_ids);
    for file in &files {
        let id = file.id().unwrap();
        let payload = expected
            .iter()
            .find_map(|(expected_id, payload)| (*expected_id == id).then_some(*payload))
            .expect("unexpected ITOC ID");
        assert_eq!(reader.extract_file(file)?.as_slice(), payload);
    }
    Ok(())
}

#[test]
fn toc_writer_reader_roundtrip() -> Result<(), Box<dyn Error>> {
    let root = unique_temp_path("toc-roundtrip");
    let input = root.join("input");
    let archive = root.join("test.cpk");
    fs::create_dir_all(input.join("nested"))?;
    fs::write(input.join("root.bin"), b"root payload")?;
    fs::write(input.join("nested").join("child.bin"), b"nested payload")?;

    let report = CpkWriter::pack_directory(
        &input,
        &archive,
        CpkWriterOptions {
            alignment: 0x800,
            ..CpkWriterOptions::default()
        },
    )?;
    assert_eq!(report.files, 2);
    assert_eq!(report.toc_offset, 0x800);
    assert_eq!(report.itoc_offset, 0);
    assert_eq!(report.content_offset % 0x800, 0);
    assert_eq!(report.archive_size % 0x800, 0);

    let mut archive_bytes = Vec::new();
    File::open(&archive)?.read_to_end(&mut archive_bytes)?;
    assert_eq!(&archive_bytes[0x7fa..0x800], b"(c)CRI");
    // This target engine uses marker/encoding bytes at @UTF +8/+9 and a
    // big-endian u16 RowsOffset at +0x0a.
    assert_eq!(&archive_bytes[0x18..0x1a], &[0, 1]);
    let header_rows_offset =
        u16::from_be_bytes(archive_bytes[0x1a..0x1c].try_into()?) as u32 + 8;
    assert!(header_rows_offset < 0x800);

    let mut reader = CpkReader::new(BufReader::new(File::open(&archive)?))?;
    let mut files = reader.get_files()?;
    let metadata = reader.metadata().copied().unwrap();
    assert!(!metadata.sorted);
    assert_eq!(metadata.cpk_mode, 1);
    assert!(metadata.enable_file_name);
    files.sort_by(|a, b| a.file_name().cmp(b.file_name()));
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].directory(), "nested");
    assert_eq!(files[0].file_name(), "child.bin");
    assert_eq!(reader.extract_file(&files[0])?.as_slice(), b"nested payload");
    assert_eq!(files[1].directory(), "");
    assert_eq!(files[1].file_name(), "root.bin");
    assert_eq!(files[1].user_string(), "");
    assert_eq!(reader.extract_file(&files[1])?.as_slice(), b"root payload");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn standard_itoc_low_only_keeps_both_nested_tables() -> Result<(), Box<dyn Error>> {
    let root = unique_temp_path("itoc-low");
    let input = root.join("input");
    let archive = root.join("low.cpk");
    fs::create_dir_all(&input)?;
    let files = vec![
        write_input(&input, "seven.bin", b"seven", 7)?,
        write_input(&input, "two.bin", b"two", 2)?,
    ];

    let report = CpkWriter::pack_files_with_profile(
        &archive,
        &files,
        CpkWriterOptions::default(),
        &profile(CpkIndexMode::Itoc, false),
    )?;
    assert_eq!(report.toc_offset, 0);
    assert_eq!(report.itoc_offset, 0x800);
    assert_itoc_payloads(&archive, &[(7, b"seven"), (2, b"two")])?;

    let mut reader = CpkReader::new(BufReader::new(File::open(&archive)?))?;
    let _ = reader.get_files()?;
    let metadata = reader.metadata().copied().unwrap();
    assert_eq!(metadata.cpk_mode, 0);
    assert_eq!(metadata.eid, 0);
    assert!(!metadata.enable_file_name);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn standard_itoc_high_only_keeps_both_nested_tables() -> Result<(), Box<dyn Error>> {
    let root = unique_temp_path("itoc-high");
    let input = root.join("input");
    let archive = root.join("high.cpk");
    fs::create_dir_all(&input)?;
    let payload = vec![0x5a; 70_000];
    let files = vec![write_input(&input, "large.bin", &payload, 5)?];

    CpkWriter::pack_files_with_profile(
        &archive,
        &files,
        CpkWriterOptions::default(),
        &profile(CpkIndexMode::Itoc, false),
    )?;
    assert_itoc_payloads(&archive, &[(5, payload.as_slice())])?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn standard_itoc_merges_low_and_high_rows_by_id() -> Result<(), Box<dyn Error>> {
    let root = unique_temp_path("itoc-mixed");
    let input = root.join("input");
    let archive = root.join("mixed.cpk");
    fs::create_dir_all(&input)?;
    let large = vec![0x3c; 70_000];
    let files = vec![
        write_input(&input, "seven.bin", b"seven", 7)?,
        write_input(&input, "one-large.bin", &large, 1)?,
        write_input(&input, "two.bin", b"two", 2)?,
    ];

    CpkWriter::pack_files_with_profile(
        &archive,
        &files,
        CpkWriterOptions::default(),
        &profile(CpkIndexMode::Itoc, false),
    )?;

    let mut reader = CpkReader::new(BufReader::new(File::open(&archive)?))?;
    let rows = reader.get_files()?;
    let ids = rows
        .iter()
        .map(|file| file.id().expect("ITOC row must have an ID"))
        .collect::<Vec<_>>();
    // FUN_8106706C combines each table's binary-search position and
    // FUN_81066ED2 sums both prefixes, so physical payloads are globally
    // ID-sorted even when low/high-width rows interleave.
    assert_eq!(ids, vec![1, 2, 7]);
    for file in &rows {
        let expected = match file.id().unwrap() {
            1 => large.as_slice(),
            2 => &b"two"[..],
            7 => &b"seven"[..],
            id => panic!("unexpected ID {id}"),
        };
        assert_eq!(reader.extract_file(file)?.as_slice(), expected);
    }

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn direct_itoc_is_sorted_by_id_and_uses_eid() -> Result<(), Box<dyn Error>> {
    let root = unique_temp_path("itoc-direct");
    let input = root.join("input");
    let archive = root.join("direct.cpk");
    fs::create_dir_all(&input)?;
    let files = vec![
        write_input(&input, "nine.bin", b"nine", 9)?,
        write_input(&input, "one.bin", b"one", 1)?,
        write_input(&input, "four.bin", b"four", 4)?,
    ];

    CpkWriter::pack_files_with_profile(
        &archive,
        &files,
        CpkWriterOptions::default(),
        &profile(CpkIndexMode::Itoc, true),
    )?;
    assert_itoc_payloads(&archive, &[(9, b"nine"), (1, b"one"), (4, b"four")])?;

    let mut reader = CpkReader::new(BufReader::new(File::open(&archive)?))?;
    let _ = reader.get_files()?;
    assert_eq!(reader.metadata().unwrap().eid, 1);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn toc_and_itoc_share_the_same_physical_payload_plan() -> Result<(), Box<dyn Error>> {
    let root = unique_temp_path("toc-itoc");
    let input = root.join("input");
    let archive = root.join("both.cpk");
    fs::create_dir_all(&input)?;
    let large = vec![0xa5; 70_000];
    let files = vec![
        write_input(&input, "dir/seven.bin", b"seven", 7)?,
        write_input(&input, "two.bin", b"two", 2)?,
        write_input(&input, "large/five.bin", &large, 5)?,
    ];

    let report = CpkWriter::pack_files_with_profile(
        &archive,
        &files,
        CpkWriterOptions::default(),
        &profile(CpkIndexMode::TocAndItoc, false),
    )?;
    assert_eq!(report.toc_offset, 0x800);
    assert!(report.itoc_offset > report.toc_offset);

    let mut reader = CpkReader::new(BufReader::new(File::open(&archive)?))?;
    let toc_files = reader.get_files()?;
    let metadata = reader.metadata().copied().unwrap();
    assert_eq!(metadata.cpk_mode, 2);
    assert!(metadata.enable_file_name);
    assert_eq!(metadata.eid, 0);
    for file in &toc_files {
        let expected = match file.id().unwrap() {
            2 => &b"two"[..],
            5 => large.as_slice(),
            7 => &b"seven"[..],
            id => panic!("unexpected ID {id}"),
        };
        assert_eq!(reader.extract_file(file)?.as_slice(), expected);
    }

    fs::remove_dir_all(root)?;
    Ok(())
}


#[test]
fn raw_entry_reuse_still_rebuilds_the_container() -> Result<(), Box<dyn Error>> {
    use cri_archive_lib::cpk::writer::CpkRawPayload;

    let root = unique_temp_path("raw-reuse");
    let input = root.join("input");
    let source_archive = root.join("source.cpk");
    let rebuilt_archive = root.join("rebuilt.cpk");
    fs::create_dir_all(&input)?;
    let source_files = vec![write_input(&input, "payload.bin", b"raw payload", 3)?];
    CpkWriter::pack_files_with_profile(
        &source_archive,
        &source_files,
        CpkWriterOptions::default(),
        &profile(CpkIndexMode::Toc, false),
    )?;

    let mut reader = CpkReader::new(BufReader::new(File::open(&source_archive)?))?;
    let source_rows = reader.get_files()?;
    let source_row = source_rows
        .first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing TOC row"))?;
    let source_offset = source_row.absolute_offset();
    let source_size = source_row.file_size();

    let reused = CpkInputFile {
        directory: String::new(),
        file_name: "payload.bin".to_owned(),
        source_path: input.join("payload.bin"),
        size: source_size,
        extract_size: source_row.extract_size(),
        id: source_row.id().unwrap_or(3),
        user_string: source_row.user_string().to_owned(),
        raw_payload: Some(CpkRawPayload {
            archive_path: source_archive.clone(),
            absolute_offset: source_offset,
            size: source_size,
        }),
    };
    let mut rebuilt_profile = profile(CpkIndexMode::Toc, false);
    rebuilt_profile.comment = "container rebuilt around a raw entry".to_owned();
    CpkWriter::pack_files_with_profile(
        &rebuilt_archive,
        &[reused],
        CpkWriterOptions {
            alignment: 0x400,
            ..CpkWriterOptions::default()
        },
        &rebuilt_profile,
    )?;

    let source_bytes = fs::read(&source_archive)?;
    let rebuilt_bytes = fs::read(&rebuilt_archive)?;
    assert_ne!(source_bytes, rebuilt_bytes, "raw reuse must not copy the archive");

    let mut rebuilt_reader = CpkReader::new(BufReader::new(File::open(&rebuilt_archive)?))?;
    let rebuilt_rows = rebuilt_reader.get_files()?;
    assert_eq!(rebuilt_rows.len(), 1);
    assert_eq!(
        rebuilt_reader.extract_file(&rebuilt_rows[0])?.as_slice(),
        b"raw payload"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}
