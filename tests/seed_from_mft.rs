//! `PathBuilder::seed_from_mft` on a small MFT built here: directory names
//! from extension records, deleted directories, and the leftover extension
//! record of a reused base record.
#![cfg(feature = "mft")]

use mft::MftParser;
use usn::{PathBuilder, Reference};

const RECORD_SIZE: usize = 1024;
const ROOT: (u64, u16) = (5, 5);
const WIN32: u8 = 1;
const DOS: u8 = 2;

fn file_reference((entry, sequence): (u64, u16)) -> [u8; 8] {
    let mut r = entry.to_le_bytes();
    r[6..8].copy_from_slice(&sequence.to_le_bytes());
    r
}

fn reference((entry, sequence): (u64, u16)) -> Reference {
    Reference::new(u128::from(sequence) << 48 | u128::from(entry))
}

fn resident(type_code: u32, value: &[u8]) -> Vec<u8> {
    let length = (0x18 + value.len() + 7) & !7;
    let mut a = vec![0u8; length];
    a[0..4].copy_from_slice(&type_code.to_le_bytes());
    a[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    a[0x0A..0x0C].copy_from_slice(&0x18u16.to_le_bytes());
    a[0x10..0x14].copy_from_slice(&(value.len() as u32).to_le_bytes());
    a[0x14..0x16].copy_from_slice(&0x18u16.to_le_bytes());
    a[0x18..0x18 + value.len()].copy_from_slice(value);
    a
}

/// A directory's `$FILE_NAME`.
fn file_name(name: &str, namespace: u8, parent: (u64, u16)) -> Vec<u8> {
    let mut v = file_reference(parent).to_vec();
    v.extend_from_slice(&[0; 48]); // times and sizes
    v.extend_from_slice(&0x1000_0000u32.to_le_bytes()); // directory
    v.extend_from_slice(&[0; 4]);
    let utf16: Vec<u16> = name.encode_utf16().collect();
    v.push(utf16.len() as u8);
    v.push(namespace);
    for c in utf16 {
        v.extend_from_slice(&c.to_le_bytes());
    }
    resident(0x30, &v)
}

/// A resident `$ATTRIBUTE_LIST` naming the record of each `$FILE_NAME`.
fn attribute_list(segments: &[(u64, u16)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (i, segment) in segments.iter().enumerate() {
        let mut e = [0u8; 0x20];
        e[0..4].copy_from_slice(&0x30u32.to_le_bytes());
        e[4..6].copy_from_slice(&0x20u16.to_le_bytes());
        e[7] = 0x1A;
        e[0x10..0x18].copy_from_slice(&file_reference(*segment));
        e[0x18..0x1A].copy_from_slice(&(i as u16).to_le_bytes());
        v.extend_from_slice(&e);
    }
    resident(0x20, &v)
}

/// Writes a directory record (`flags`: 1 in use, 2 directory).
fn record(
    mft: &mut [u8],
    number: u64,
    sequence: u16,
    flags: u16,
    base: (u64, u16),
    attributes: &[Vec<u8>],
) {
    let e = &mut mft[number as usize * RECORD_SIZE..][..RECORD_SIZE];
    e.fill(0);
    e[0..4].copy_from_slice(b"FILE");
    e[4..6].copy_from_slice(&0x30u16.to_le_bytes());
    e[6..8].copy_from_slice(&3u16.to_le_bytes());
    e[0x10..0x12].copy_from_slice(&sequence.to_le_bytes());
    e[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
    e[0x16..0x18].copy_from_slice(&flags.to_le_bytes());
    e[0x1C..0x20].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes());
    e[0x20..0x28].copy_from_slice(&file_reference(base));
    e[0x2C..0x30].copy_from_slice(&(number as u32).to_le_bytes());
    let mut at = 0x38;
    for a in attributes {
        e[at..at + a.len()].copy_from_slice(a);
        at += a.len();
    }
    e[at..at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    e[0x18..0x1C].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    e[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
    e[510..512].copy_from_slice(&1u16.to_le_bytes());
    e[1022..1024].copy_from_slice(&1u16.to_le_bytes());
}

#[test]
fn directories_are_named_by_their_own_records() {
    let mut mft = vec![0u8; 32 * RECORD_SIZE];
    for number in 0..32 {
        record(&mut mft, number, 1, 0, (0, 0), &[]);
    }
    record(&mut mft, 5, 5, 3, (0, 0), &[file_name(".", WIN32, ROOT)]);
    // 20: a directory whose long name is in its extension record 21.
    record(
        &mut mft,
        20,
        1,
        3,
        (0, 0),
        &[
            file_name("AMD64_~1", DOS, ROOT),
            attribute_list(&[(20, 1), (21, 1)]),
        ],
    );
    record(
        &mut mft,
        21,
        1,
        1,
        (20, 1),
        &[file_name("amd64_component", WIN32, ROOT)],
    );
    // 22: a deleted directory in 20; the journal knew it by sequence 1.
    record(
        &mut mft,
        22,
        2,
        2,
        (0, 0),
        &[file_name("deleted dir", WIN32, (20, 1))],
    );
    // 23: a directory reused from an older one whose long name was in the
    // extension record 24, which still points at the old version (23, 1).
    record(
        &mut mft,
        23,
        2,
        3,
        (0, 0),
        &[file_name("NEWDIR~1", DOS, ROOT)],
    );
    record(
        &mut mft,
        24,
        2,
        0,
        (23, 1),
        &[file_name("old long name", WIN32, ROOT)],
    );

    let mut builder = PathBuilder::new();
    let seeded = builder.seed_from_mft(&mut MftParser::from_buffer(mft).unwrap());
    let paths = builder.finish();
    assert_eq!(seeded, 4, "the root, 20, 22 and 23");
    assert_eq!(paths.resolve(reference((20, 1))), ".\\amd64_component");
    assert_eq!(
        paths.resolve(reference((22, 1))),
        ".\\amd64_component\\deleted dir"
    );
    // not the previous owner's name
    assert_eq!(paths.resolve(reference((23, 2))), ".\\NEWDIR~1");
}
