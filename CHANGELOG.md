# Changelog

## 0.2.0 (ys-usn-journal-parser)

First version of Yamato Security's fork, based on sootmark-usn 0.1.0 (Sootmark/usn 605f3a0).

### Added
- `PathBuilder` and `Paths`: the path of each record's directory when the record was written, by
  rewinding the journal (two streaming passes; only directories are kept in memory). Unresolvable
  or looping chains get an `[Unknown <reference>]` component.
- `PathBuilder::seed_from_mft` (feature `mft`, Yamato Security's ys-mft-parser): every directory of
  the volume's `$MFT`, in use or deleted, with long names from extension records and the sequence
  number a deleted directory had.
- `carve(reader)` / `Carved`: V2 and V3 records carved from data that is not a journal, with strict
  layout checks (name right after the header, exact length, a USN inside one journal page, a time
  from 1980 to 2100, known flag bits, a valid name, a parent that can be a directory).
- `Filetime`: record times keep their raw value (`raw()`, `unix_ticks()`, `to_iso8601()`).
- Tests on slices of real Windows 11 and Server 2012 R2 journals (DFIRArtifactMuseum, MIT).

### Changed
- No dependencies: sootmark-common's byte reader and UTF-16 decoder are vendored and its `Ts` type is
  replaced by `Filetime` (`Record::time`).
- Not published (`publish = false`); MSRV 1.85 (1.90 with `mft`); CI on Linux, macOS and Windows
  with the actions pinned by commit; no toolchain pin.

### Fixed
- Every step scanned a 64 KiB chunk for zeros before looking at its first byte, and every short
  run of zeros did the same: parsing is 6–8× faster (750–1,500 MB/s on real journals).
- A false record header less than a record's length before the end of the journal made everything
  after it one truncated record, hiding any whole records there.
