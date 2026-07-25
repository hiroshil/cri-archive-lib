import struct
import sys
from dataclasses import dataclass
from pathlib import Path

TYPE_CODE = {"u16": 2, "u32": 4, "u64": 6, "str": 10, "data": 11}
TYPE_SIZE = {"u16": 2, "u32": 4, "u64": 8, "str": 4, "data": 8}
INDEX_BASE = 0x800


@dataclass
class Entry:
    directory: str
    name: str
    payload: bytes
    entry_id: int
    extract_size: int | None = None
    user: str = ""

    @property
    def packed_size(self):
        return len(self.payload)

    @property
    def unpacked_size(self):
        return self.extract_size if self.extract_size is not None else len(self.payload)


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def build_utf(name, columns, rows):
    strings = bytearray(b"\0")
    string_offsets = {"": 0}

    def intern(value):
        if value in string_offsets:
            return string_offsets[value]
        offset = len(strings)
        strings.extend(value.encode("utf-8"))
        strings.append(0)
        string_offsets[value] = offset
        return offset

    name_offset = intern(name)
    column_offsets = [intern(column_name) for column_name, _ in columns]
    for row in rows:
        for (_, value_type), value in zip(columns, row):
            if value_type == "str":
                intern(value)

    data_pool = bytearray()
    data_locations = {}
    for row_index, row in enumerate(rows):
        for column_index, ((_, value_type), value) in enumerate(zip(columns, row)):
            if value_type == "data":
                data_locations[(row_index, column_index)] = (len(data_pool), len(value))
                data_pool.extend(value)

    row_size = sum(TYPE_SIZE[value_type] for _, value_type in columns)
    rows_start = 0x20 + 5 * len(columns)
    string_start = rows_start + row_size * len(rows)
    data_start = string_start + len(strings)
    total_size = data_start + len(data_pool)

    output = bytearray(b"@UTF")
    output += struct.pack(">I", total_size - 8)
    output += bytes([0, 1])
    output += struct.pack(">H", rows_start - 8)
    output += struct.pack(">I", string_start - 8)
    output += struct.pack(">I", data_start - 8)
    output += struct.pack(">I", name_offset)
    output += struct.pack(">H", len(columns))
    output += struct.pack(">H", row_size)
    output += struct.pack(">I", len(rows))

    for (_, value_type), offset in zip(columns, column_offsets):
        output.append(0x50 | TYPE_CODE[value_type])
        output += struct.pack(">I", offset)

    for row_index, row in enumerate(rows):
        for column_index, ((_, value_type), value) in enumerate(zip(columns, row)):
            if value_type == "u16":
                output += struct.pack(">H", value)
            elif value_type == "u32":
                output += struct.pack(">I", value)
            elif value_type == "u64":
                output += struct.pack(">Q", value)
            elif value_type == "str":
                output += struct.pack(">I", string_offsets[value])
            elif value_type == "data":
                offset, length = data_locations[(row_index, column_index)]
                output += struct.pack(">II", offset, length)
            else:
                raise AssertionError(value_type)

    output += strings
    output += data_pool
    assert len(output) == total_size
    return bytes(output)


def chunk(magic, table):
    return magic + bytes([0xFF] * 4) + struct.pack("<Q", len(table)) + table


def c_string(pool, offset):
    if offset == 0:
        return None
    return pool[offset : pool.index(0, offset)].decode("utf-8")


def parse_utf(data):
    assert data[:4] == b"@UTF"
    size = struct.unpack_from(">I", data, 4)[0] + 8
    assert data[8] == 0 and data[9] == 1
    rows_offset = struct.unpack_from(">H", data, 10)[0] + 8
    string_offset = struct.unpack_from(">I", data, 12)[0] + 8
    data_offset = struct.unpack_from(">I", data, 16)[0] + 8
    columns = struct.unpack_from(">H", data, 24)[0]
    row_size = struct.unpack_from(">H", data, 26)[0]
    row_count = struct.unpack_from(">I", data, 28)[0]
    assert 0x20 <= rows_offset <= string_offset <= data_offset <= size == len(data)

    position = 0x20
    schema = []
    string_pool = data[string_offset:data_offset]
    data_pool = data[data_offset:size]
    for _ in range(columns):
        flag = data[position]
        name_offset = struct.unpack_from(">I", data, position + 1)[0]
        position += 5
        assert flag & 0x50 == 0x50
        schema.append((c_string(string_pool, name_offset), flag & 0x0F))

    values = []
    sizes = {2: 2, 4: 4, 6: 8, 10: 4, 11: 8}
    for row_index in range(row_count):
        position = rows_offset + row_index * row_size
        row = {}
        for name, value_type in schema:
            if value_type == 2:
                value = struct.unpack_from(">H", data, position)[0]
            elif value_type == 4:
                value = struct.unpack_from(">I", data, position)[0]
            elif value_type == 6:
                value = struct.unpack_from(">Q", data, position)[0]
            elif value_type == 10:
                value = c_string(string_pool, struct.unpack_from(">I", data, position)[0])
            elif value_type == 11:
                offset, length = struct.unpack_from(">II", data, position)
                value = data_pool[offset : offset + length]
                assert len(value) == length
            else:
                raise AssertionError(value_type)
            position += sizes[value_type]
            row[name] = value
        assert position <= rows_offset + (row_index + 1) * row_size
        values.append(row)
    return values


def itoc_order(entries, direct):
    assert len({entry.entry_id for entry in entries}) == len(entries)
    assert all(0 <= entry.entry_id <= 0xFFFF for entry in entries)
    if direct:
        return sorted(range(len(entries)), key=lambda index: entries[index].entry_id)
    low = [
        index
        for index, entry in enumerate(entries)
        if entry.packed_size <= 0xFFFF and entry.unpacked_size <= 0xFFFF
    ]
    high = [index for index in range(len(entries)) if index not in low]
    low.sort(key=lambda index: entries[index].entry_id)
    high.sort(key=lambda index: entries[index].entry_id)
    return low + high


def build_itoc_rows(entries, indices, low, name):
    size_type = "u16" if low else "u32"
    columns = [("ID", "u16"), ("FileSize", size_type), ("ExtractSize", size_type)]
    rows = [
        [entries[index].entry_id, entries[index].packed_size, entries[index].unpacked_size]
        for index in indices
    ]
    return build_utf(name, columns, rows)


def build_itoc(entries, order, direct):
    if direct:
        return build_itoc_rows(entries, order, False, "CpkExtendId")
    split = next(
        (
            i
            for i, index in enumerate(order)
            if entries[index].packed_size > 0xFFFF or entries[index].unpacked_size > 0xFFFF
        ),
        len(order),
    )
    low = order[:split]
    high = order[split:]
    # EID=0 makes the analyzed engine instantiate both nested tables without
    # checking whether either column is absent. Empty groups therefore remain
    # valid zero-row @UTF tables instead of omitted columns.
    columns = [("DataL", "data"), ("DataH", "data")]
    row = [
        build_itoc_rows(entries, low, True, "CpkItocL"),
        build_itoc_rows(entries, high, False, "CpkItocH"),
    ]
    return build_utf("CpkItocInfo", columns, [row])


def build_archive(entries, has_toc, has_itoc, direct=False, alignment=0x800):
    assert has_toc or has_itoc
    order = itoc_order(entries, direct) if has_itoc else list(range(len(entries)))

    toc_columns = [
        ("DirName", "str"),
        ("FileName", "str"),
        ("FileSize", "u32"),
        ("ExtractSize", "u32"),
        ("FileOffset", "u64"),
        ("ID", "u32"),
        ("UserString", "str"),
    ]
    zero_offsets = [0] * len(entries)
    toc_probe = (
        build_utf(
            "CpkTocInfo",
            toc_columns,
            [
                [
                    entry.directory,
                    entry.name,
                    entry.packed_size,
                    entry.unpacked_size,
                    zero_offsets[index],
                    entry.entry_id,
                    entry.user,
                ]
                for index, entry in enumerate(entries)
            ],
        )
        if has_toc
        else None
    )
    itoc_probe = build_itoc(entries, order, direct) if has_itoc else None

    cursor = INDEX_BASE
    toc_offset = cursor if toc_probe is not None else 0
    if toc_probe is not None:
        cursor = align(cursor + 0x10 + len(toc_probe), alignment)
    itoc_offset = cursor if itoc_probe is not None else 0
    if itoc_probe is not None:
        cursor = align(cursor + 0x10 + len(itoc_probe), alignment)
    content_offset = align(cursor, alignment)

    absolute_offsets = [0] * len(entries)
    cursor = content_offset
    for index in order:
        absolute_offsets[index] = cursor
        cursor = align(cursor + entries[index].packed_size, alignment)
    archive_size = cursor

    toc = None
    if has_toc:
        toc = build_utf(
            "CpkTocInfo",
            toc_columns,
            [
                [
                    entry.directory,
                    entry.name,
                    entry.packed_size,
                    entry.unpacked_size,
                    absolute_offsets[index] - INDEX_BASE,
                    entry.entry_id,
                    entry.user,
                ]
                for index, entry in enumerate(entries)
            ],
        )
        assert len(toc) == len(toc_probe)
    itoc = build_itoc(entries, order, direct) if has_itoc else None
    if itoc is not None:
        assert len(itoc) == len(itoc_probe)

    toc_chunk = chunk(b"TOC ", toc) if toc is not None else None
    itoc_chunk = chunk(b"ITOC", itoc) if itoc is not None else None
    cpk_mode = 2 if has_toc and has_itoc else 1 if has_toc else 0
    header_columns = [
        ("UpdateDateTime", "u64"),
        ("FileSize", "u64"),
        ("ContentOffset", "u64"),
        ("ContentSize", "u64"),
        ("TocOffset", "u64"),
        ("TocSize", "u64"),
        ("EtocOffset", "u64"),
        ("EtocSize", "u64"),
        ("ItocOffset", "u64"),
        ("ItocSize", "u64"),
        ("GtocOffset", "u64"),
        ("GtocSize", "u64"),
        ("Files", "u32"),
        ("Version", "u16"),
        ("Revision", "u16"),
        ("Align", "u16"),
        ("Sorted", "u16"),
        ("EID", "u16"),
        ("EnableFileName", "u16"),
        ("CpkMode", "u32"),
        ("Tvers", "str"),
        ("Comment", "str"),
        ("Codec", "u32"),
        ("DpkItoc", "u32"),
        ("EnableTocCrc", "u16"),
        ("EnableFileCrc", "u16"),
    ]
    header_row = [
        0,
        archive_size,
        content_offset,
        archive_size - content_offset,
        toc_offset,
        len(toc_chunk) if toc_chunk else 0,
        0,
        0,
        itoc_offset,
        len(itoc_chunk) if itoc_chunk else 0,
        0,
        0,
        len(entries),
        7,
        0,
        alignment,
        0,
        int(has_itoc and direct),
        int(has_toc),
        cpk_mode,
        "7.0.0",
        "Created by cri-cpk-cli",
        0,
        0,
        0,
        0,
    ]
    header = build_utf("CpkHeader", header_columns, [header_row])
    header_chunk = chunk(b"CPK ", header)
    assert len(header_chunk) <= 0x7FA

    output = bytearray(header_chunk)
    output.extend(b"\0" * (INDEX_BASE - len(output)))
    output[0x7FA:0x800] = b"(c)CRI"
    if toc_chunk:
        output.extend(b"\0" * (toc_offset - len(output)))
        output += toc_chunk
    if itoc_chunk:
        output.extend(b"\0" * (itoc_offset - len(output)))
        output += itoc_chunk
    output.extend(b"\0" * (content_offset - len(output)))
    for index in order:
        output.extend(b"\0" * (absolute_offsets[index] - len(output)))
        output += entries[index].payload
    output.extend(b"\0" * (archive_size - len(output)))
    return bytes(output), absolute_offsets, order


def parse_chunk(archive, offset, magic):
    assert archive[offset : offset + 4] == magic
    assert archive[offset + 4 : offset + 8] == b"\xff" * 4
    size = struct.unpack_from("<Q", archive, offset + 8)[0]
    end = offset + 0x10 + size
    assert end <= len(archive)
    return archive[offset + 0x10 : end]


def validate_archive(archive, entries, expected_toc, expected_itoc, expected_direct):
    header = parse_utf(parse_chunk(archive, 0, b"CPK "))[0]
    assert header["FileSize"] == len(archive)
    assert header["ContentSize"] == len(archive) - header["ContentOffset"]
    assert header["Files"] == len(entries)
    assert header["Sorted"] == 0
    assert bool(header["TocOffset"]) == expected_toc
    assert bool(header["ItocOffset"]) == expected_itoc
    if expected_toc:
        toc_table_size = struct.unpack_from("<Q", archive, header["TocOffset"] + 8)[0]
        assert header["TocSize"] == 0x10 + toc_table_size
    else:
        assert header["TocSize"] == 0
    if expected_itoc:
        assert header["ContentOffset"] <= 0xFFFFFFFF
        itoc_table_size = struct.unpack_from("<Q", archive, header["ItocOffset"] + 8)[0]
        assert header["ItocSize"] == 0x10 + itoc_table_size
    else:
        assert header["ItocSize"] == 0
    assert bool(header["EID"]) == (expected_itoc and expected_direct)
    assert bool(header["EnableFileName"]) == expected_toc
    assert archive[0x7FA:0x800] == b"(c)CRI"

    by_id = {entry.entry_id: entry for entry in entries}
    if expected_toc:
        rows = parse_utf(parse_chunk(archive, header["TocOffset"], b"TOC "))
        assert len(rows) == len(entries)
        for row in rows:
            payload = archive[
                INDEX_BASE + row["FileOffset"] : INDEX_BASE + row["FileOffset"] + row["FileSize"]
            ]
            assert payload == by_id[row["ID"]].payload
            assert row["ExtractSize"] == by_id[row["ID"]].unpacked_size

    if expected_itoc:
        itoc_rows = parse_utf(parse_chunk(archive, header["ItocOffset"], b"ITOC"))
        groups = []
        if expected_direct:
            groups.append((itoc_rows, False))
        else:
            outer = itoc_rows[0]
            assert set(outer) == {"DataL", "DataH"}
            groups.append((parse_utf(outer["DataL"]), True))
            groups.append((parse_utf(outer["DataH"]), False))
        flattened = []
        for rows, low in groups:
            ids = [row["ID"] for row in rows]
            assert ids == sorted(ids), "engine uses binary search in each ITOC table"
            for row in rows:
                if low:
                    assert row["FileSize"] <= 0xFFFF and row["ExtractSize"] <= 0xFFFF
                flattened.append(row)
        cursor = header["ContentOffset"]
        for row in flattened:
            entry = by_id[row["ID"]]
            assert archive[cursor : cursor + row["FileSize"]] == entry.payload
            assert row["ExtractSize"] == entry.unpacked_size
            cursor = align(cursor + row["FileSize"], header["Align"])


entries = [
    Entry("root", "small.bin", b"small", 7),
    Entry("", "compressed-placeholder.bin", b"packed", 2, extract_size=1234),
    Entry("large", "large.bin", bytes((index * 17) & 0xFF for index in range(70000)), 5),
]

results = []
for name, case_entries, has_toc, has_itoc, direct in [
    ("toc", entries, True, False, False),
    ("itoc-standard", entries, False, True, False),
    ("itoc-standard-low-only", entries[:2], False, True, False),
    ("itoc-standard-high-only", entries[2:], False, True, False),
    ("itoc-direct", entries, False, True, True),
    ("toc-and-itoc", entries, True, True, False),
]:
    archive, offsets, order = build_archive(case_entries, has_toc, has_itoc, direct)
    validate_archive(archive, case_entries, has_toc, has_itoc, direct)
    results.append(
        {
            "layout": name,
            "archive_size": len(archive),
            "physical_ids": [case_entries[index].entry_id for index in order],
            "offsets": [hex(offset) for offset in offsets],
        }
    )

output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample-engine-compatible-v3.cpk")
archive, _, _ = build_archive(entries, True, True, False)
output_path.write_bytes(archive)
print({"validated": results, "output": str(output_path)})
