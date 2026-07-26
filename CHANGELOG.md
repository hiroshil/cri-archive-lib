# Changelog

## Unreleased

- Added full CPK structure rebuilding for TOC, standard ITOC, direct/EID ITOC, and TOC+ITOC profiles.
- Made `cri-cpk-cli pack` rebuild the header, indexes, offset plan, and every payload by default; removed the whole-archive copy shortcut.
- Added explicit `--reuse-raw-entries`, which may reuse only unchanged packed entry byte ranges while still rebuilding the complete CPK container.
- Made standard ITOC always contain valid `DataL` and `DataH` nested tables, including zero-row tables for empty groups, matching the target engine's unconditional parser construction; the reader now rejects missing groups as invalid.
- Corrected standard ITOC payload offsets to use the ascending-ID merge of DataL/DataH. The previous low-group-then-high-group assumption corrupted mixed-width archives such as SC/BK/BSF/PT.
- Preserved TOC order, IDs, `UserString`, alignment, index mode, direct/EID mode, version, revision, update time, and P5R mode through the unpack manifest.
- Forced rebuilt TOCs to `Sorted = 0`, avoiding binary search with an incompatible pathname ordering.
- Confirmed and preserved the target engine's marker/encoding/`u16 RowsOffset` `@UTF` layout and canonical `ff ff ff ff` plaintext chunk marker.
- Rejected ITOC content bases above `0xffffffff`, which the target engine would truncate while initializing its offset state.
- Removed the temporary `cri-archive-lib/examples` programs and unused accessors that triggered `dead_code` warnings.
- Added standard and direct/EID ITOC reading, safe owned file metadata, bounded table/string parsing, and owned extraction buffers.
- Renamed `cri-cpk-extractor-cli` to `cri-cpk-cli`; added `pack` and `unpack` commands.

## 0.1.1

- **[CPK Extractor]** Fixed issue where files stored at the root of a CPK file are saved to the root of the computer's drive.

## 0.1.0

Initial release
