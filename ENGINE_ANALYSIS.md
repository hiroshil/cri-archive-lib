# Engine CPK analysis

Target: `eboot.bin.elf`, 32-bit little-endian ARM EABI5. The supplied `rz/output.c` and `rz/output.asm` were used to map the runtime's CPK and `@UTF` behavior to the Rust implementation.

## Outer chunks and header

`FUN_81068420` (`0x81068420`) validates `CPK `, reads the embedded table length from chunk offset `+0x08`, and rejects a header whose `0x10 + table_size` exceeds `0x800`. When chunk byte `+0x04` is zero, the embedded table is XOR-decoded starting with key `0x5f`, multiplying the key by `0x15` for each byte. Plaintext chunks are emitted with the canonical four-byte marker `ff ff ff ff`; this engine branches only on byte `+0x04`, but using the canonical marker avoids relying on ignored reserved bytes.

The runtime obtains CPK header fields by name. Relevant fields include `ContentOffset`, `ContentSize`, TOC/ETOC/ITOC/GTOC offsets and sizes, `Files`, `Version`, `Revision`, `Align`, `Sorted`, `EID`, `EnableFileName`, `CpkMode`, codec fields, and CRC fields. A rebuilt archive may omit unsupported optional structures only when all corresponding offsets, sizes, and enable flags are consistently zero.

The inferred `CpkMode` values are:

- `0`: ITOC only;
- `1`: TOC only;
- `2`: TOC + ITOC;
- `3`: TOC + GTOC;
- `4`: TOC + ITOC + GTOC.

The writer emits only modes `0`, `1`, or `2` and zeros ETOC/GTOC/CRC metadata.

## TOC behavior

`FUN_810668b6` parses the TOC chunk. `FUN_81066a26` reads each row by fixed column index:

| Index | Field | Runtime accessor |
|---:|---|---|
| 0 | `DirName` | string |
| 1 | `FileName` | string |
| 2 | `FileSize` | u32 |
| 3 | `ExtractSize` | u32 |
| 4 | `FileOffset` | u64 |
| 5 | `ID` | u32 |
| 6 | `UserString` | string |
| 7 | optional `FileCrc` | u32 |

The physical offset is calculated directly in `FUN_81066a26`:

```text
absolute_file_offset = 0x800 + FileOffset
```

The writer therefore keeps TOC at `0x800` and stores every TOC offset relative to that fixed base.

`FUN_81066ae8` performs linear pathname lookup. `FUN_81066b66` performs binary lookup when `Sorted` is nonzero. Its comparator is ASCII case-insensitive and normalizes slash direction, so Rust's normal path ordering is not a valid substitute. Rebuilt archives advertise `Sorted = 0` and use the runtime's linear path lookup.

## Standard and direct ITOC behavior

`FUN_81066c36` handles two representations:

1. `EID == 0`: the outer ITOC row contains `DataL` and `DataH`, each holding a nested `@UTF` table;
2. `EID != 0`: the outer ITOC table itself is the direct/high-width ID table.

Low rows use:

```text
ID          u16
FileSize    u16
ExtractSize u16
[FileCrc    u32, optional]
```

High/direct rows use:

```text
ID          u16
FileSize    u32
ExtractSize u32
[FileCrc    u32, optional]
```

### Both standard nested tables are mandatory

For `EID == 0`, `FUN_81066c36` looks up `DataL` and `DataH`, then unconditionally invokes the nested UTF constructor for both. If either column is missing, the decompiled fallback arguments become pointer `0` and length `0xffff_ffff`; `FUN_810e0898` subsequently dereferences the supplied table pointer. Therefore an empty low or high group cannot be represented by omitting its column. The writer emits both fields and places a valid zero-row nested `@UTF` table in an empty group.

### ID ordering and physical ordering

`FUN_81066e32` binary-searches each nested/direct table by 16-bit ID. Rows in each group must be sorted by ascending ID.

`FUN_81066c36` copies only the low 32 bits of `ContentOffset` into the ITOC state. The reader and writer therefore reject ITOC archives whose content base exceeds `0xffffffff` instead of allowing engine-side wraparound.

`FUN_8106706c` binary-searches both nested tables for the requested ID. When the ID exists in one table, the negative result from the other table is converted into that table's insertion index. It then calls `FUN_81066ed2` with both prefix lengths. `FUN_81066ed2` sums the aligned sizes of the first `low_prefix` DataL rows and the first `high_prefix` DataH rows.

This proves that the physical stream is the stable merge of both tables by ascending ID:

```text
absolute_offset(id) = ContentOffset
                    + sum(align_up(FileSize(row), Align)
                          for row in merge_by_id(DataL, DataH)
                          before id)
```

It is **not** `DataL` followed by `DataH`. The distinction is observable in the target archives: SC, BK, BSF, and PT all contain interleaved low/high IDs. Applying low-then-high offsets shifts every payload after the first high-width ID and makes valid scenario/image records appear malformed.

Direct ITOC uses the same ascending-ID physical order through its single table. The writer builds one merged physical payload plan first and uses that same plan for ITOC rows and, when present, TOC `FileOffset` values.

## `@UTF` layout

`FUN_810e07de`, `FUN_810e0812`, and the typed accessors confirm the engine-specific header layout:

```text
+0x00  "@UTF"
+0x04  u32 table size minus 8, big-endian
+0x08  marker byte
+0x09  encoding byte (1 = UTF-8)
+0x0a  u16 RowsOffset, big-endian, relative to +8
+0x0c  u32 StringPoolOffset, big-endian, relative to +8
+0x10  u32 DataPoolOffset, big-endian, relative to +8
+0x14  u32 table-name string offset
+0x18  u16 column count
+0x1a  u16 row size
+0x1c  u32 row count
```

Column flags use bit `0x10` for a name, bit `0x20` for constant/default storage, bit `0x40` for row storage, and the low nibble for the value type. Writer columns use `0x50 | type`.

## Rebuild policy

The CLI manifest is a structural input, not a copy-original fallback. It records index mode, direct/EID mode, TOC row order, IDs, strings, packed/extracted metadata, original packed ranges, alignment, and relevant header version fields.

Default `pack` behavior:

1. read every extracted file;
2. represent rebuilt payloads as uncompressed data (`FileSize == ExtractSize`);
3. reapply P5R transformation where requested and marked;
4. recalculate low/high ITOC membership from rebuilt sizes;
5. sort ITOC groups by ID;
6. create a new physical payload plan;
7. serialize new header, TOC/ITOC, padding, and all payloads.

`--reuse-raw-entries` only changes step 1 for unchanged entries: their original packed byte ranges may be used as payload input. The complete container and index structures are still serialized again. There is no whole-archive copy path.

## Reader and safety changes

- Reads TOC, standard ITOC, and direct/EID ITOC. Standard ITOC parsing requires both `DataL` and `DataH`, matching the runtime rather than accepting a structurally invalid fallback.
- Resolves row-stored and default-column values.
- Honors UTF `RowSize` and validates section boundaries.
- Uses owned strings and extraction buffers.
- Requires mutable reader access for seek/decrypt/decompress operations.
- Bounds string pools and chunk allocations.
- Avoids unchecked type transmutation and raw-pointer-backed CPK metadata.

## Current writer limitations

- Rebuilt payloads are uncompressed; CriLAYLA encoding is not implemented.
- ETOC, GTOC, and CRC table generation are not implemented and are disabled in rebuilt metadata.
- ITOC-only archives have no stored paths; extraction uses deterministic ID-based names.
