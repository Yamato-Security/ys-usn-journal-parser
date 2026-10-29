//! Journals built byte by byte from Microsoft's record layouts: V3 and V4
//! records, a sparse start, page padding, damage between and after records;
//! streaming in any chunks reads what parsing reads; and no input makes
//! either panic.

use std::io::{self, Read};

use proptest::prelude::*;
use usn::{Entry, Journal, Problem, ProblemKind, Reasons, Reference, carve, parse, read};

const FILE: u64 = 0x0003_0000_0000_0040; // entry 64, sequence 3
const PARENT: u64 = 0x0005_0000_0000_0005; // the root directory
/// 2024-03-01T12:00:00Z.
const FILETIME: u64 = 133_537_680_000_000_000;

fn utf16(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Pad to the 8-byte alignment and write the length in.
fn finish(mut record: Vec<u8>) -> Vec<u8> {
    record.resize(record.len().next_multiple_of(8), 0);
    let length = (record.len() as u32).to_le_bytes();
    record[..4].copy_from_slice(&length);
    record
}

/// A `USN_RECORD_V2` or `_V3`, its name `gap` bytes after the header.
fn change(major: u16, usn: u64, name_units: &[u8], reasons: u32, gap: usize) -> Vec<u8> {
    let mut record = vec![0; 4];
    record.extend(major.to_le_bytes());
    record.extend(0_u16.to_le_bytes());
    if major == 2 {
        record.extend(FILE.to_le_bytes());
        record.extend(PARENT.to_le_bytes());
    } else {
        record.extend((u128::from(FILE) | 0xAB << 64).to_le_bytes());
        record.extend(u128::from(PARENT).to_le_bytes());
    }
    record.extend(usn.to_le_bytes());
    record.extend(FILETIME.to_le_bytes());
    record.extend(reasons.to_le_bytes());
    record.extend(0x2_u32.to_le_bytes()); // auxiliary data
    record.extend(0x104_u32.to_le_bytes());
    record.extend(0x20_u32.to_le_bytes()); // archive
    let name_offset = record.len() + 4 + gap;
    record.extend((name_units.len() as u16).to_le_bytes());
    record.extend((name_offset as u16).to_le_bytes());
    record.resize(name_offset, 0);
    record.extend(name_units);
    finish(record)
}

fn v2(usn: u64, name: &str) -> Vec<u8> {
    change(2, usn, &utf16(name), 0x8000_0100, 0)
}

/// A `USN_RECORD_V4` with these extents.
fn v4(usn: u64, extents: &[(u64, u64)]) -> Vec<u8> {
    let mut record = vec![0; 4];
    record.extend(4_u16.to_le_bytes());
    record.extend(0_u16.to_le_bytes());
    record.extend(u128::from(FILE).to_le_bytes());
    record.extend(u128::from(PARENT).to_le_bytes());
    record.extend(usn.to_le_bytes());
    record.extend(0x0000_0002_u32.to_le_bytes()); // data extended
    record.extend(0_u32.to_le_bytes());
    record.extend(2_u32.to_le_bytes()); // remaining extents
    record.extend((extents.len() as u16).to_le_bytes());
    record.extend(16_u16.to_le_bytes());
    for (offset, length) in extents {
        record.extend(offset.to_le_bytes());
        record.extend(length.to_le_bytes());
    }
    finish(record)
}

/// Gather streamed entries the way [`parse`] does.
fn gather(entries: impl IntoIterator<Item = io::Result<Entry>>) -> Journal {
    let mut journal = Journal::default();
    for entry in entries {
        match entry.unwrap() {
            Entry::Record(record) => journal.records.push(record),
            Entry::Ranges(record) => journal.ranges.push(record),
            Entry::Problem(problem) => journal.problems.push(problem),
        }
    }
    journal
}

/// A reader handing out at most `chunk` bytes per read.
struct Trickle<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.chunk.min(buf.len()).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// `length` zero bytes, as a sparse file reads.
struct Zeros(u64);

impl Read for Zeros {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(usize::try_from(self.0).unwrap_or(usize::MAX));
        buf[..n].fill(0);
        self.0 -= n as u64;
        Ok(n)
    }
}

#[test]
fn v2_fields() {
    let journal = parse(&v2(0, "evil.exe"));
    let record = &journal.records[0];
    assert_eq!(record.version.to_string(), "2.0");
    assert_eq!(record.length, 80);
    assert_eq!(record.file, Reference::new(FILE.into()));
    assert_eq!((record.file.entry(), record.file.sequence()), (64, 3));
    assert_eq!(record.parent.to_string(), "5-5");
    assert_eq!(
        record.time.to_iso8601().as_deref(),
        Some("2024-03-01T12:00:00.0000000Z")
    );
    assert_eq!(record.reasons.to_string(), "FILE_CREATE CLOSE");
    assert_eq!(record.source_info.to_string(), "AUXILIARY_DATA");
    assert_eq!(record.security_id, 0x104);
    assert_eq!(record.attributes.to_string(), "ARCHIVE");
    assert_eq!(record.name, "evil.exe");
    assert!(!record.name_escaped);
}

#[test]
fn v3_has_wide_references() {
    let journal = parse(&change(3, 8, &utf16("wide.txt"), 0x2, 0));
    let record = &journal.records[0];
    assert_eq!((record.version.major, record.length), (3, 96));
    assert_eq!(record.file.raw(), u128::from(FILE) | 0xAB << 64);
    assert!(!record.file.is_ntfs());
    assert!(record.parent.is_ntfs());
    assert_eq!(record.name, "wide.txt");
    assert_eq!(record.reasons, Reasons::DATA_EXTEND);
}

#[test]
fn v4_ranges_follow_their_v3_record() {
    let mut data = change(3, 0, &utf16("big.vhdx"), 0x2, 0);
    let second = data.len() as u64;
    data.extend(v4(second, &[(0, 4096), (1 << 30, 65_536)]));
    let journal = parse(&data);
    assert_eq!(journal.records.len(), 1);
    let ranges = &journal.ranges[0];
    assert_eq!(
        (ranges.offset, ranges.usn, ranges.length),
        (second, second, 96)
    );
    assert_eq!(ranges.file.entry(), 64);
    assert_eq!(ranges.remaining_extents, 2);
    assert_eq!(ranges.extents.len(), 2);
    assert_eq!(
        (ranges.extents[1].offset, ranges.extents[1].length),
        (1 << 30, 65_536)
    );
    assert_eq!(journal.problems, [] as [usn::Problem; 0]);
}

#[test]
fn name_found_by_its_offset() {
    let journal = parse(&change(2, 0, &utf16("later.txt"), 0x100, 4));
    assert_eq!(journal.records[0].name, "later.txt");
}

#[test]
fn invalid_utf16_is_escaped() {
    let mut units = utf16("a");
    units.extend(0xD800_u16.to_le_bytes());
    let journal = parse(&change(2, 0, &units, 0x100, 0));
    assert_eq!(journal.records[0].name, "a\\u{d800}");
    assert!(journal.records[0].name_escaped);
}

#[test]
fn sparse_start_and_page_padding() {
    let start = 3 * 4096;
    let mut data = vec![0; start];
    data.extend(v2(start as u64, "one.txt"));
    // The rest of the page is zeros; the next record starts the next page.
    data.resize(start + 4096, 0);
    data.extend(v2(start as u64 + 4096, "two.txt"));
    data.extend([0; 3]); // a ragged zero tail
    let journal = parse(&data);
    let found: Vec<_> = journal
        .records
        .iter()
        .map(|r| (r.offset, r.usn, r.name.as_str()))
        .collect();
    assert_eq!(
        found,
        [(12_288, 12_288, "one.txt"), (16_384, 16_384, "two.txt")]
    );
    assert_eq!(journal.problems, [] as [usn::Problem; 0]);
}

#[test]
fn record_length_with_a_zero_low_byte() {
    // 256 bytes long: its first byte is zero, so a zero scan must stop on
    // the word, not the byte.
    let name = "n".repeat(98);
    let mut data = vec![0; 64];
    data.extend(v2(64, &name));
    assert_eq!(data[64..68], [0, 1, 0, 0]);
    assert_eq!(parse(&data).records[0].name, name);
}

#[test]
fn garbage_between_records_is_one_problem() {
    let mut data = v2(0, "before.txt");
    let garbage_at = data.len() as u64;
    data.extend([0xA5; 44]);
    data.extend([0; 4]); // keeps the next record aligned
    let after_at = data.len() as u64;
    data.extend(v2(after_at, "after.txt"));
    let journal = parse(&data);
    let names: Vec<_> = journal.records.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["before.txt", "after.txt"]);
    assert_eq!(
        journal.problems,
        [Problem {
            offset: garbage_at,
            length: 48,
            kind: ProblemKind::Unreadable
        }]
    );
    assert_eq!(
        journal.problems[0].to_string(),
        "bytes 80..128: not USN records, skipped"
    );
}

#[test]
fn damaged_record_is_skipped_and_the_next_found() {
    let mut data = v2(0, "first.txt");
    data.extend(v2(80, "second.txt"));
    data.extend(v2(160, "third.txt"));
    // The second record's name runs past its length.
    data[80 + 56] = 0xFF;
    let journal = parse(&data);
    let names: Vec<_> = journal.records.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["first.txt", "third.txt"]);
    assert_eq!(
        (journal.problems[0].offset, journal.problems[0].length),
        (80, 80)
    );
}

#[test]
fn truncated_last_record() {
    let mut data = v2(0, "whole.txt");
    data.extend(&v2(80, "cut.txt")[..40]);
    let journal = parse(&data);
    assert_eq!(journal.records.len(), 1);
    assert_eq!(
        journal.problems,
        [Problem {
            offset: 80,
            length: 40,
            kind: ProblemKind::Truncated
        }]
    );
}

#[test]
fn a_false_header_at_the_end_does_not_hide_the_records_after_it() {
    let mut data = v2(0, "whole.txt");
    // a word that reads as the start of a 4,000-byte V2 record
    data.extend(4000_u32.to_le_bytes());
    data.extend(2_u16.to_le_bytes());
    data.extend(0_u16.to_le_bytes());
    data.extend(v2(88, "after.txt"));
    let journal = parse(&data);
    let names: Vec<&str> = journal.records.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["whole.txt", "after.txt"]);
    assert_eq!(
        journal.problems,
        [Problem {
            offset: 80,
            length: 8,
            kind: ProblemKind::Unreadable
        }]
    );
    assert_eq!(
        gather(read(Trickle {
            data: &data,
            chunk: 7
        })),
        journal
    );
}

/// Carve from `data`, streamed in `chunk`-byte reads: names and offsets.
fn carved(data: &[u8], chunk: usize) -> Vec<(String, u64)> {
    carve(Trickle { data, chunk })
        .map(|r| r.map(|r| (r.name, r.offset)).unwrap())
        .collect()
}

#[test]
fn carving_finds_records_in_other_data_at_their_offsets() {
    // other data, then records whose USNs are not their offsets here
    let mut data: Vec<u8> = (0..4000_u32)
        .flat_map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes())
        .collect();
    data.extend(v2(4096, "one.txt"));
    data.extend([0xA5; 24]);
    data.extend(change(3, 4096 + 80, &utf16("two.txt"), 0x8000_0100, 0));
    data.extend(v4(4096 + 176, &[(0, 4096)]));
    data.extend([0; 40]);
    let want = [
        ("one.txt".to_string(), 16_000),
        ("two.txt".to_string(), 16_104),
    ];
    assert_eq!(carved(&data, 1 << 20), want);
    assert_eq!(carved(&data, 13), want, "the same in any chunks");
}

#[test]
fn carving_rejects_what_ntfs_does_not_write() {
    let mut bad_time = v2(0, "time.txt");
    bad_time[32..40].copy_from_slice(&1_u64.to_le_bytes()); // 1601
    let mut bad_parent = v2(0, "parent.txt");
    bad_parent[16..24].copy_from_slice(&0x0001_0000_0000_0003_u64.to_le_bytes()); // $Volume
    let cases = [
        (
            "a gap before the name",
            change(2, 0, &utf16("gap.txt"), 0x100, 8),
        ),
        ("no reason", change(2, 0, &utf16("none.txt"), 0, 0)),
        (
            "an unknown reason",
            change(2, 0, &utf16("bits.txt"), 0x0200_0100, 0),
        ),
        ("a USN off the word", v2(4, "usn.txt")),
        (
            "a record crossing a journal page",
            v2(4096 - 40, "page.txt"),
        ),
        ("a time in 1601", bad_time),
        ("a parent that is not a directory", bad_parent),
        ("a slash in the name", v2(0, "a/b")),
    ];
    for (what, record) in cases {
        assert!(
            !parse(&record).records.is_empty(),
            "{what}: read as a journal"
        );
        assert!(carved(&record, 1 << 20).is_empty(), "{what}: carved");
    }
    assert_eq!(carved(&v2(0, "ok.txt"), 1 << 20).len(), 1);
}

#[test]
fn garbage_tail() {
    let mut data = v2(0, "whole.txt");
    data.extend([0xFF; 13]);
    let journal = parse(&data);
    assert_eq!(journal.records.len(), 1);
    assert_eq!(
        (journal.problems[0].offset, journal.problems[0].length),
        (80, 13)
    );
}

#[test]
fn streams_through_a_large_sparse_start() {
    // Not a multiple of the stream's buffer, so records straddle refills.
    let zeros = 64 * 1024 * 1024 + 4096 - 40;
    let mut tail = Vec::new();
    for i in 0..200_u64 {
        tail.extend(v2(zeros + i * 80, &format!("f{i:05}.tmp")));
    }
    let journal = gather(read(Zeros(zeros).chain(&tail[..])));
    assert_eq!(journal.records.len(), 200);
    assert_eq!(journal.problems, [] as [usn::Problem; 0]);
    assert!(journal.records.iter().all(|r| r.offset == r.usn));
    assert_eq!(journal.records[199].name, "f00199.tmp");
}

#[test]
fn a_read_error_is_returned_once() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("disk gone"))
        }
    }
    let mut entries = read(Failing);
    assert!(entries.next().unwrap().is_err());
    assert!(entries.next().is_none());
}

/// A journal with every kind of thing in it.
fn mixed() -> Vec<u8> {
    let mut data = vec![0; 4096];
    data.extend(v2(4096, "a.txt"));
    data.extend(change(3, 0, &utf16("b.txt"), 0x2, 0));
    data.extend(v4(0, &[(0, 512)]));
    data.extend([0x5A; 24]);
    data.extend(v2(0, "c.txt"));
    data.extend(&v2(0, "d.txt")[..50]);
    data
}

proptest! {
    /// Streaming in any chunk size reads exactly what parsing reads.
    #[test]
    fn streamed_in_chunks_as_parsed(chunk in 1_usize..300) {
        let data = mixed();
        let streamed = gather(read(Trickle { data: &data, chunk }));
        prop_assert_eq!(streamed, parse(&data));
    }

    /// Any bytes: records or problems, never a panic, the same both ways,
    /// in order and never overlapping.
    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..3_000), chunk in 1_usize..64) {
        let parsed = parse(&data);
        let mut spans: Vec<(u64, u64)> = parsed.records.iter().map(|r| (r.offset, u64::from(r.length)))
            .chain(parsed.ranges.iter().map(|r| (r.offset, u64::from(r.length))))
            .chain(parsed.problems.iter().map(|p| (p.offset, p.length)))
            .collect();
        spans.sort_unstable();
        for pair in spans.windows(2) {
            prop_assert!(pair[0].0 + pair[0].1 <= pair[1].0);
        }
        prop_assert!(spans.last().is_none_or(|(o, l)| o + l <= data.len() as u64));
        prop_assert_eq!(gather(read(Trickle { data: &data, chunk })), parsed);
    }

    /// Real and built journals, damaged anywhere.
    #[test]
    fn damaged_journals(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..30), real in any::<bool>()) {
        let mut data = if real {
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plaso/UsnJrnl.raw")).unwrap()
        } else {
            mixed()
        };
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        prop_assert_eq!(gather(read(Trickle { data: &data, chunk: 7 })), parse(&data));
    }

    /// Carving a damaged journal in any chunk size carves what one read does.
    #[test]
    fn carved_in_chunks_as_whole(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..30), chunk in 1_usize..300) {
        let mut data = mixed();
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        prop_assert_eq!(carved(&data, chunk), carved(&data, 1 << 20));
    }
}
