# ys-usn-journal-parser

Yamato Security's maintained fork of [sootmark-usn](https://github.com/Sootmark/usn), the NTFS USN
change journal (`$Extend\$UsnJrnl:$J`) parser used by [Juntei](https://github.com/Yamato-Security/juntei).
The upstream history and the MIT OR Apache-2.0 license are kept; everything below the line is
upstream's README.

sootmark-usn was chosen after running the Rust USN parsers on six real journals (DFIRArtifactMuseum,
1,035,444 records) against dfir_ntfs and a second, independent parser, which agree with each other on
every record, and on damaged copies:

| Crate | V2 / V3 / V4 | Matches the oracles | Damaged journals (4,400) | Notes |
| --- | --- | --- | --- | --- |
| **sootmark-usn 0.1.0** | ✓ / ✓ / ✓ | every record and field | no panics | streams in 1 MiB, keeps unknown flag bits, escapes bad UTF-16; no paths |
| ntfs-core 0.9.8 (usnjrnl-forensic) | ✓ / sequence lost / skipped | all V2 | no panics (stack overflow on long junk in debug) | rewind, carving and $LogFile ideas, but the CLI reads the whole $J into memory |
| usnrs 0.2.1 | ✓ / ✗ / ✗ | unknown reason bits dropped (58,764) | 2,113 panics | hangs on an all-zero input |
| usnjrnl 0.4.5 | ✓ / ✗ / ✗ | 49,912 records missing, times cut to µs | 124 allocation aborts | GPL-3.0 |
| RustyUsn, artemis | V2 | not run (no build on current Rust / part of an application) | | rewind (RustyUsn) and MFT path ideas (artemis) |

What the fork adds and fixes:

| Change | Source |
| --- | --- |
| No dependencies: the byte reader and UTF-16 decoder of sootmark-common are vendored, its time type replaced by `Filetime` (raw value kept) | fork |
| 6–8× faster on real journals (a 64 KiB zero scan ran before every record): 750–1,500 MB/s; a 4 GiB sparse start in 0.3 s | fork (found in review) |
| A false record header near the end of the journal no longer hides the records after it | fork (found in review) |
| `PathBuilder` / `Paths`: each record's directory path as it was when the record was written, by rewinding the journal; reused MFT records told apart by sequence number | idea of RustyUsn, usnjrnl-forensic, CyberCX; written afresh |
| `PathBuilder::seed_from_mft` (feature `mft`, ys-mft-parser): directories from `$MFT`, long names from extension records, deleted directories with the sequence number the journal used | fork |
| `carve(reader)`: V2/V3 records from disk images, unallocated space, pagefiles, with strict layout checks | idea of RustyUsn and ntfs-core's carver; written afresh |
| Tests on real Windows 11 and Server 2012 R2 journals, carving, paths | fork |

Paths: on the six DFIRArtifactMuseum journals seeded from their `$MFT`, the rewound paths equal the
parent paths an independent parser gives for all 1,030,833 records it resolves, and resolve 4,321 of
the records it leaves unresolved, from directories the journal created and deleted.

Carving: every one of the 1,035,437 V2/V3 records of those journals passes the checks and is
found; carving their `$MFT` files (880 MB of other NTFS metadata) and random data finds nothing.

```rust
// paths as they were, seeded from the volume's $MFT (feature "mft")
let mut builder = usn::PathBuilder::new();
builder.seed_from_mft(&mut mft::MftParser::from_path("$MFT")?);
for entry in usn::read(std::io::BufReader::new(std::fs::File::open("$J")?)) {
    if let usn::Entry::Record(record) = entry? {
        builder.observe(&record);
    }
}
let mut paths = builder.finish();
for entry in usn::read(std::io::BufReader::new(std::fs::File::open("$J")?)) {
    if let usn::Entry::Record(record) = entry? {
        println!("{} {}\\{}", record.time, paths.parent_path(&record), record.name);
    }
}
```

Use it from Cargo by commit (the crate is `ys-usn-journal-parser`, named after the repository, and
its library keeps the name `usn`; it is not published, and its versions are the fork's own: 1.0.0
since the rename):

```toml
usn = { package = "ys-usn-journal-parser", git = "https://github.com/Yamato-Security/ys-usn-journal-parser", rev = "<commit>", features = ["mft"] }
```

MSRV: 1.99 (edition 2024). See [CHANGELOG.md](CHANGELOG.md).

---

# usn

The NTFS USN change journal (`$Extend\$UsnJrnl:$J`) as KAPE, Velociraptor and forensic images give it: every record Windows kept of what happened to which file, read straight through the gigabytes of sparse zeros a collected `$J` usually starts with. One dependency, its sibling `sootmark-common` (times, UTF-16).

```toml
[dependencies]
sootmark-usn = "0.1"
```

```rust
let file = std::fs::File::open("$J")?;
for entry in usn::read(std::io::BufReader::new(file)) {
    match entry? {
        usn::Entry::Record(record) => {
            println!("{} {} {} in {}", record.time, record.reasons, record.name, record.parent);
        }
        usn::Entry::Problem(problem) => eprintln!("{problem}"),
        usn::Entry::Ranges(_) => {}
    }
}
```

## What you get

- `read(reader)`: every record and problem in journal order, from any `Read`, holding at most 1 MiB at a time, so a journal of any size streams. `parse(bytes)` does the same for a journal in memory, gathered into `records`, `ranges` and `problems`.
- **V2** records (what NTFS writes by default) and **V3** (128-bit file references) as a `Record`: offset, length, version, USN, time (FILETIME, UTC), file and parent references (MFT entry and sequence number; ReFS identifiers kept whole), reasons (`FILE_CREATE`, `DATA_EXTEND`, `RENAME_OLD_NAME`, `CLOSE`, … with their names, unknown bits kept), source info, security id, file attributes and the name. Invalid UTF-16 in a name is escaped, never replaced.
- **V4** records (range tracking) as a `RangeRecord`: the file, reasons, and every extent (offset and length) written.
- Zeros, before records and padding the end of each 4 KiB page, skipped 64 KiB at a time. Bytes that aren't records are passed 8 at a time to the next record and reported as one problem with their offset and length; so is a record the journal ends in the middle of. Neither stops the reading.

Not here: paths. A record names its file and directory by MFT reference; joining with the volume's MFT (matching sequence numbers) gives them.

## How it's checked

- plaso's USN journal (Apache-2.0, `tests/fixtures/plaso/`, the `$J` of plaso's NTFS test image), against two independent readers of the same volume, in `tests/oracle/` with the script that regenerates them: all 19 records match libfsntfs's `fsntfsinfo -U` (time, USN, reasons, source, name, both references, attributes) and the 11 that The Sleuth Kit's `usnjls -l` reads match it too (version, length, security id and the flag names as well). `usnjls` stops at the first record crossing a 1 KiB block.
- Journals built byte by byte: V3 and V4 records, a sparse start, page padding, garbage between records, a damaged record, a truncated record, a 64 MiB sparse start streamed with records straddling the buffer.
- Property tests: arbitrary bytes and damaged journals never panic, never report overlapping spans, and stream in any chunk size exactly as they parse.

## Licence

MIT or Apache-2.0, at your option. The test journal is plaso's, under the Apache licence 2.0.
