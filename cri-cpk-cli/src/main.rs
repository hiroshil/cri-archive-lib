mod manifest;
mod progress;

use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use cri_archive_lib::cpk::encrypt::data::{DummyDecryptor, FileDecryptor};
use cri_archive_lib::cpk::encrypt::p5r::P5RDecryptor;
use cri_archive_lib::cpk::reader::CpkReader;
use cri_archive_lib::cpk::writer::{CpkWriter, CpkWriterOptions};

use crate::manifest::{absolute_path, hash_bytes, hash_file, same_path, Manifest, ManifestEntry};
use crate::progress::Progress;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "unpack" => run_unpack(&args[1..]),
        "pack" => run_pack(&args[1..]),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        legacy_input if legacy_input.to_ascii_lowercase().ends_with(".cpk") => run_unpack(&args),
        _ => {
            print_usage();
            Err("expected 'unpack' or 'pack'".into())
        }
    }
}

fn run_unpack(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut positional = Vec::new();
    let mut p5r = false;
    for argument in args {
        match argument.as_str() {
            "--p5r" => p5r = true,
            value if value.starts_with('-') => {
                return Err(format!("unknown unpack option: {value}").into());
            }
            _ => positional.push(argument.as_str()),
        }
    }
    if positional.is_empty() || positional.len() > 2 {
        return Err("usage: cri-cpk-cli unpack <input.cpk> [output-dir] [--p5r]".into());
    }
    let input = Path::new(positional[0]);
    let output = positional
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| default_unpack_directory(input));
    if p5r {
        unpack_with::<P5RDecryptor>(input, &output, true)
    } else {
        unpack_with::<DummyDecryptor>(input, &output, false)
    }
}

fn run_pack(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut positional = Vec::new();
    let mut alignment_override = None;
    let mut p5r = false;
    let mut reuse_raw_entries = false;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--align" => {
                index += 1;
                let value = args.get(index).ok_or("--align requires a value")?;
                alignment_override = Some(parse_u16(value)?);
            }
            value if value.starts_with("--align=") => {
                alignment_override = Some(parse_u16(&value[8..])?);
            }
            "--p5r" => p5r = true,
            "--reuse-raw-entries" => reuse_raw_entries = true,
            value if value.starts_with('-') => {
                return Err(format!("unknown pack option: {value}").into());
            }
            _ => positional.push(args[index].as_str()),
        }
        index += 1;
    }
    if positional.is_empty() || positional.len() > 2 {
        return Err(
            "usage: cri-cpk-cli pack <input-dir> [output.cpk] [--align 0x800] [--p5r] [--reuse-raw-entries]"
                .into(),
        );
    }

    let input = Path::new(positional[0]);
    let output = positional
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| default_pack_file(input));
    let started = Instant::now();

    if let Some(manifest) = Manifest::read(input)? {
        if reuse_raw_entries && same_path(&manifest.source_archive, &output)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--reuse-raw-entries cannot overwrite the source CPK because raw entry bytes are read from it",
            )
            .into());
        }
        let files = manifest.build_inputs(input, &output, reuse_raw_entries)?;
        if files.is_empty() {
            return Err("input directory contains no packable files".into());
        }
        let alignment = alignment_override.unwrap_or(manifest.alignment.max(1));
        let profile = manifest.writer_profile();
        let report = CpkWriter::pack_files_with_profile(
            &output,
            &files,
            CpkWriterOptions {
                alignment,
                p5r_encryption: manifest.p5r || p5r,
            },
            &profile,
        )?;
        println!(
            "Rebuilt {} files to {} ({:#x} bytes, content at {:#x}, TOC {:#x}, ITOC {:#x}) in {:.2}s{}",
            report.files,
            output.display(),
            report.archive_size,
            report.content_offset,
            report.toc_offset,
            report.itoc_offset,
            started.elapsed().as_secs_f64(),
            if reuse_raw_entries {
                " using raw packed payloads only for unchanged entries"
            } else {
                ""
            },
        );
        return Ok(());
    }

    if reuse_raw_entries {
        return Err(
            "--reuse-raw-entries requires a .cri-cpk-manifest-v2 generated by unpack".into(),
        );
    }
    eprintln!(
        "warning: no .cri-cpk-manifest-v2 found; packing a new TOC CPK without original IDs/profile metadata",
    );
    let report = CpkWriter::pack_directory(
        input,
        &output,
        CpkWriterOptions {
            alignment: alignment_override.unwrap_or(0x800),
            p5r_encryption: p5r,
        },
    )?;
    println!(
        "Packed {} files to {} ({:#x} bytes, content at {:#x}) in {:.2}s",
        report.files,
        output.display(),
        report.archive_size,
        report.content_offset,
        started.elapsed().as_secs_f64(),
    );
    Ok(())
}

fn unpack_with<E: FileDecryptor>(
    input: &Path,
    output: &Path,
    p5r: bool,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output)?;
    let source_archive = absolute_path(input)?;
    let (archive_size, archive_hash) = hash_file(input)?;
    let mut cpk = CpkReader::<_, E>::new_with_encryption(BufReader::new(File::open(input)?))?;
    let files = cpk.get_files()?;
    let metadata = *cpk.metadata().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "CPK metadata unavailable after reading file table",
        )
    })?;
    let progress = Progress::new(files.len() as u64);
    let mut entries = Vec::with_capacity(files.len());

    for (index, file) in files.iter().enumerate() {
        progress.set_current_file(file);
        let (packed, extracted) = cpk.extract_file_with_packed(file)?;
        let destination = safe_output_path(output, file.directory(), file.file_name())?;
        if destination == Manifest::path(output) {
            return Err(format!(
                "CPK entry conflicts with reserved manifest name: {}",
                destination.display()
            )
            .into());
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination, &extracted)?;
        entries.push(ManifestEntry {
            directory: file.directory().to_owned(),
            file_name: file.file_name().to_owned(),
            id: file.id().unwrap_or(u32::try_from(index).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "too many CPK files")
            })?),
            user_string: file.user_string().to_owned(),
            extracted_size: extracted.len() as u64,
            extracted_hash: hash_bytes(&extracted),
            packed_size: file.file_size(),
            packed_offset: file.absolute_offset(),
            packed_hash: hash_bytes(&packed),
        });
        progress.read_one();
    }
    progress.finish();

    Manifest {
        source_archive,
        archive_size,
        archive_hash,
        alignment: metadata.align.max(1),
        has_toc: metadata.toc_offset != 0,
        has_itoc: metadata.itoc_offset != 0,
        direct_itoc: metadata.itoc_offset != 0 && metadata.eid != 0,
        p5r,
        version: metadata.version,
        revision: metadata.revision,
        update_date_time: metadata.update_date_time,
        entries,
    }
    .write(output)?;

    println!("Unpacked {} files to {}", files.len(), output.display());
    Ok(())
}

fn safe_output_path(
    root: &Path,
    directory: &str,
    file_name: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    // CRI archives may use either slash style regardless of the host OS.
    let normalized_directory = directory.replace('\\', "/");
    let normalized_file_name = file_name.replace('\\', "/");
    let mut output = root.to_path_buf();
    for component in Path::new(&normalized_directory)
        .components()
        .chain(Path::new(&normalized_file_name).components())
    {
        match component {
            Component::Normal(value) => output.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("unsafe path in CPK: {directory}/{file_name}").into());
            }
        }
    }
    Ok(output)
}

fn default_unpack_directory(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .unwrap_or_else(|| std::ffi::OsStr::new("unpacked"));
    input
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(stem)
}

fn default_pack_file(input: &Path) -> PathBuf {
    let name = input
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("archive"));
    input
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
        .with_extension("cpk")
}

fn parse_u16(value: &str) -> Result<u16, Box<dyn Error>> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16)?
    } else {
        value.parse::<u16>()?
    };
    Ok(parsed)
}

fn print_usage() {
    println!("cri-cpk-cli\n");
    println!("  Unpack: cri-cpk-cli unpack <input.cpk> [output-dir] [--p5r]");
    println!(
        "  Pack:   cri-cpk-cli pack <input-dir> [output.cpk] [--align 0x800] [--p5r] [--reuse-raw-entries]",
    );
    println!(
        "\nPack always rebuilds the CPK header and TOC/ITOC structures. By default every entry payload is rebuilt from the extracted file.",
    );
    println!(
        "--reuse-raw-entries is optional and reuses only the original packed bytes of entries whose extracted content is unchanged.",
    );
    println!("A bare .cpk path is accepted as the legacy unpack syntax.");
}
