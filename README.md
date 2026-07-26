# cri-archive-lib

Rust support for CRI `@UTF` tables and CPK archives. The CPK reader handles named TOC archives, standard `DataL`/`DataH` ITOC archives, direct/EID ITOC archives, encrypted table chunks, Shift-JIS string pools, and CriLAYLA extraction when `cpk_compression_layla` is enabled.

The workspace contains `cri-cpk-cli`, a combined unpack/pack command-line tool.

## CLI

### Unpack

```text
cri-cpk-cli unpack <input.cpk> [output-dir]
```

For Persona 5 Royal's file-level transform:

```text
cri-cpk-cli unpack <input.cpk> [output-dir] --p5r
```

The old drag-and-drop/bare-path form remains accepted:

```text
cri-cpk-cli <input.cpk> [output-dir]
```

### Pack

```text
cri-cpk-cli pack <input-dir> [output.cpk] [--align 0x800] [--p5r] [--reuse-raw-entries]
```

`unpack` writes `.cri-cpk-manifest-v2`. The manifest records the source archive profile and per-entry metadata required to rebuild the same index model: TOC, standard ITOC, direct/EID ITOC, or TOC+ITOC; row order; IDs; `UserString`; packed and extracted sizes; original packed offsets; alignment; and P5R mode.

`pack` always serializes a new CPK header and new TOC/ITOC tables. By default it also rebuilds every entry payload from the extracted file, including an unchanged unpack/pack cycle. It never copies the complete original CPK as a round-trip shortcut.

`--reuse-raw-entries` is an explicit optimization. For each unchanged entry only, it copies that entry's original packed byte range from the source CPK. The containing CPK header, TOC, ITOC, offsets, sizes, padding, and content plan are still rebuilt. Changed and newly added entries are always rebuilt from extracted files.

Without a manifest, `pack` creates a new TOC archive and assigns deterministic IDs.

## Writer layout used by the target engine

- canonical plaintext chunk marker `ff ff ff ff` and the engine-specific `@UTF` header: marker at `+0x08`, encoding at `+0x09`, big-endian `u16 RowsOffset` at `+0x0a`;
- CPK header at `0x0000`, entirely before `0x0800`;
- TOC at `0x0800` when present;
- TOC `FileOffset` stored relative to `0x0800`;
- ITOC payload offsets computed from `ContentOffset` by aligned cumulative packed sizes; ITOC output is rejected when `ContentOffset > 0xffffffff` because this engine stores the base in a 32-bit state field;
- standard ITOC physical order: stable merge of `DataL` and `DataH` rows by ascending ID; the nested tables are separate indexes, not separate payload regions;
- each ITOC table sorted by ascending 16-bit ID because the engine binary-searches it;
- both `DataL` and `DataH` are emitted in standard ITOC, using a valid zero-row nested table when a group is empty;
- content, every payload start, and final archive size aligned to `Align`;
- TOC columns emitted in the fixed order used by the engine;
- `Sorted = 0`, forcing linear pathname lookup and avoiding an incompatible proprietary TOC sort order;
- rebuilt payloads stored uncompressed with `ExtractSize == FileSize`;
- optional P5R re-encryption for rebuilt entries marked `CRI_CFATTR:ENCRYPT`.

The writer does not currently generate CriLAYLA compression, ETOC, GTOC, or CRC tables. It disables the corresponding header flags instead of leaving stale metadata.

## Basic library usage

```rust
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use cri_archive_lib::cpk::reader::CpkReader;

fn extract_first(path: &str) -> Result<(), Box<dyn Error>> {
    let mut reader = CpkReader::new(BufReader::new(File::open(path)?))?;
    let files = reader.get_files()?;
    let data = reader.extract_file(&files[0])?;
    std::fs::write(files[0].file_name(), data)?;
    Ok(())
}
```

```rust
use std::error::Error;
use cri_archive_lib::cpk::writer::{CpkWriter, CpkWriterOptions};

fn pack(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    CpkWriter::pack_directory(input, output, CpkWriterOptions::default())?;
    Ok(())
}
```

See [`ENGINE_ANALYSIS.md`](ENGINE_ANALYSIS.md) for the engine functions and structural conclusions.

## Credits

The original reader/decompression work was based on CriFsV2Lib by Sewer56 and the CRI format research credited by the upstream project.
