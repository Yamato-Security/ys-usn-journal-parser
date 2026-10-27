//! plaso's USN journal (Apache-2.0, `tests/fixtures/plaso/UsnJrnl.raw`, the
//! `$J` of plaso's `usnjrnl.qcow2`), against two independent readers of the
//! same volume: libfsntfs's `fsntfsinfo -U` and The Sleuth Kit's
//! `usnjls -l` (`tests/oracle/`, written by `tests/oracle/regenerate.sh`).
//! Every record and every field either prints is compared.
//!
//! `usnjls` stops after 11 of the 19 records: the 12th starts at byte 984
//! and crosses the 1 KiB block it reads the journal in. libfsntfs reads all
//! 19, as plaso's own test expects.

use std::fs;
use std::path::Path;

use usn::{parse, read, Entry, Record};

fn manifest(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn journal() -> Vec<u8> {
    fs::read(manifest("tests/fixtures/plaso/UsnJrnl.raw")).unwrap()
}

/// The oracle's records: blocks of `key: value` lines, from each line
/// starting with `starts`.
fn blocks(oracle: &str, starts: &str) -> Vec<Vec<(String, String)>> {
    let text = fs::read_to_string(manifest(&format!("tests/oracle/{oracle}"))).unwrap();
    let mut blocks: Vec<Vec<(String, String)>> = Vec::new();
    for line in text.lines() {
        if line.starts_with(starts) {
            blocks.push(Vec::new());
        }
        let (Some(block), Some((key, value))) = (blocks.last_mut(), line.split_once(": ")) else {
            continue;
        };
        block.push((key.trim().to_owned(), value.trim().to_owned()));
    }
    blocks
}

fn field<'a>(block: &'a [(String, String)], key: &str) -> &'a str {
    &block
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("no {key} in {block:?}"))
        .1
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The record's time as The Sleuth Kit and libfsntfs write it.
fn time(record: &Record) -> (String, String) {
    let iso = record.time.to_iso8601().unwrap();
    let (date, clock) = (&iso[..10], &iso[11..27]);
    let tsk = format!("{date} {clock}00 (UTC)");
    let month = MONTHS[iso[5..7].parse::<usize>().unwrap() - 1];
    let libfsntfs = format!("{month} {}, {} {clock}00 UTC", &iso[8..10], &iso[..4]);
    (tsk, libfsntfs)
}

#[test]
fn every_record_as_libfsntfs_reads_it() {
    let journal = parse(&journal());
    let oracle = blocks("fsntfsinfo.txt", "USN record:");
    assert_eq!(journal.records.len(), 19);
    assert_eq!(oracle.len(), 19);
    assert!(journal.problems.is_empty() && journal.ranges.is_empty());
    for (record, block) in journal.records.iter().zip(&oracle) {
        let hex = |value: u32| format!("0x{value:08x}");
        assert_eq!(time(record).1, field(block, "Update time"));
        assert_eq!(
            record.usn.to_string(),
            field(block, "Update sequence number")
        );
        assert_eq!(
            hex(record.reasons.bits()),
            field(block, "Update reason flags")
        );
        assert_eq!(
            hex(record.source_info.bits()),
            field(block, "Update source flags")
        );
        assert_eq!(record.name, field(block, "Name"));
        assert_eq!(record.file.to_string(), field(block, "File reference"));
        assert_eq!(
            record.parent.to_string(),
            field(block, "Parent file reference")
        );
        assert_eq!(
            hex(record.attributes.bits()),
            field(block, "File attribute flags")
        );
    }
}

#[test]
fn the_records_the_sleuth_kit_reads() {
    let journal = parse(&journal());
    let oracle = blocks("usnjls.txt", "Version:");
    assert_eq!(oracle.len(), 11);
    for (record, block) in journal.records.iter().zip(&oracle) {
        let version_line = format!("{} Length: {}", record.version, record.length);
        assert_eq!(version_line, field(block, "Version"));
        assert_eq!(record.file.to_string(), field(block, "Reference Number"));
        assert_eq!(
            record.parent.to_string(),
            field(block, "Parent Reference Number")
        );
        assert_eq!(
            record.usn.to_string(),
            field(block, "Update Sequence Number")
        );
        assert_eq!(time(record).0, field(block, "Time"));
        assert_eq!(record.reasons.to_string(), field(block, "Reason"));
        assert_eq!(record.source_info.to_string(), field(block, "Source Info"));
        assert_eq!(record.security_id.to_string(), field(block, "Security Id"));
        assert_eq!(record.attributes.to_string(), field(block, "Attributes"));
        assert_eq!(record.name, field(block, "Name"));
    }
}

#[test]
fn streamed_as_parsed() {
    let data = journal();
    let streamed: Vec<Entry> = read(&data[..]).map(Result::unwrap).collect();
    let parsed = parse(&data);
    let records: Vec<&Record> = streamed
        .iter()
        .filter_map(|entry| match entry {
            Entry::Record(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(records.len(), streamed.len());
    assert!(records.into_iter().eq(&parsed.records));
}

#[test]
fn first_record_as_plaso_expects() {
    let record = &parse(&journal()).records[0];
    assert_eq!(record.name, "Nieuw - Tekstdocument.txt");
    assert_eq!(record.file.raw(), 0x1_0000_0000_001E);
    assert_eq!((record.file.entry(), record.file.sequence()), (30, 1));
    assert_eq!(record.parent.raw(), 0x5_0000_0000_0005);
    assert_eq!(record.reasons, usn::Reasons::FILE_CREATE);
    assert_eq!(
        record.time.to_iso8601().as_deref(),
        Some("2015-11-30T21:15:27.2031250Z")
    );
    assert_eq!(record.offset, record.usn);
}
