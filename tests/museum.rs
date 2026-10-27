//! Real Windows 11 and Windows Server 2012 R2 journals (slices of
//! `DFIRArtifactMuseum`'s, MIT; see `tests/fixtures/museum/README.md`),
//! against every field `dfir_ntfs` reads from them.

use std::fs;
use std::path::Path;

use usn::{carve, parse};

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/museum")
        .join(name)
}

fn check(name: &str) {
    let data = fs::read(fixture(&format!("{name}.bin"))).unwrap();
    let expected = fs::read_to_string(fixture(&format!("{name}.dfir_ntfs.tsv"))).unwrap();
    let journal = parse(&data);
    assert_eq!(journal.problems, [] as [usn::Problem; 0]);
    assert_eq!(journal.ranges, []);
    let rows: Vec<Vec<&str>> = expected
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split('\t').collect())
        .collect();
    assert_eq!(journal.records.len(), rows.len());
    for (record, row) in journal.records.iter().zip(&rows) {
        let got = [
            record.usn.to_string(),
            record.version.major.to_string(),
            record.length.to_string(),
            record.file.raw().to_string(),
            record.parent.raw().to_string(),
            record.time.raw().to_string(),
            record.reasons.bits().to_string(),
            record.source_info.bits().to_string(),
            record.security_id.to_string(),
            record.attributes.bits().to_string(),
            record.name.clone(),
        ];
        assert_eq!(
            got.as_slice(),
            row.as_slice(),
            "record at {}",
            record.offset
        );
        assert_eq!(record.version.minor, 0);
        assert!(!record.name_escaped);
    }
    // Every real record also passes carving's checks, at the same offsets.
    let carved: Vec<u64> = carve(data.as_slice()).map(|r| r.unwrap().offset).collect();
    let read: Vec<u64> = journal.records.iter().map(|r| r.offset).collect();
    assert_eq!(carved, read);
}

#[test]
fn windows_11() {
    check("win11_rathbunvm");
}

#[test]
fn windows_server_2012_r2() {
    check("win2012r2_stolenszechuan");
}
