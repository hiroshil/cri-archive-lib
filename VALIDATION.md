# Validation status

The implementation was reviewed against the uploaded ARM engine output and checked with `tools/validate_cpk_layout.py`, which independently constructs and parses CPK bytes without calling the Rust reader or writer.

Completed in this environment:

- parsed all Cargo TOML files;
- confirmed there is no `cri-archive-lib/examples` directory or example target;
- removed the reported unused CPK accessors;
- checked source delimiter balance and workspace/module references;
- independently generated and parsed TOC-only, standard ITOC, direct/EID ITOC, and TOC+ITOC archives;
- verified CPK header containment before `0x800`, canonical plaintext chunk marker `ff ff ff ff`, and `(c)CRI` at `0x7fa`;
- verified TOC at `0x800` and payload lookup as `0x800 + FileOffset`;
- verified ITOC payload lookup from `ContentOffset` using aligned cumulative packed sizes and added a reader/writer guard for the engine's 32-bit ITOC content base;
- verified standard ITOC physical order is low rows followed by high rows;
- verified each low/high/direct ITOC table is sorted by ascending 16-bit ID;
- verified standard ITOC always contains both `DataL` and `DataH`, including valid zero-row nested tables for empty groups;
- verified the engine-specific `@UTF` marker, encoding byte, big-endian `u16 RowsOffset`, section offsets, row widths, string references, and nested data-table offsets;
- verified TOC+ITOC uses one shared physical payload plan and consistent TOC offsets;
- verified rebuilt metadata uses `Sorted = 0`, correct `CpkMode`, correct `EID`, and zeroed unsupported ETOC/GTOC/CRC fields;
- verified the CLI contains no whole-archive copy path and makes raw packed-entry reuse opt-in through `--reuse-raw-entries`;
- added a Rust regression test whose raw-entry path changes alignment and header metadata, proving the container is serialized again rather than copied (the test source was statically checked here but could not be executed without Rust).

The environment does not contain `cargo`, `rustc`, or `rustfmt`, and external toolchain installation is unavailable. Consequently these commands could not be run here and remain required before merge:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
```

Target-engine validation should cover at least:

```text
cri-cpk-cli unpack source.cpk unpacked
cri-cpk-cli pack unpacked rebuilt-default.cpk
```

The default output is expected to differ at the byte level because all payloads and structures are rebuilt, while extracted file data and runtime lookup results must match. Then test the explicit optimization separately:

```text
cri-cpk-cli pack unpacked rebuilt-reuse.cpk --reuse-raw-entries
```

That mode may preserve original packed bytes for unchanged entries but still produces a newly serialized container.
