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
