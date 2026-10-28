//! Seeding [`PathBuilder`] from the volume's `$MFT` (feature `mft`), with
//! Yamato Security's ys-mft-parser.

use std::io::{Read, Seek};

use mft::attribute::x30::FileNamespace;
use mft::attribute::MftAttributeType;
use mft::entry::{EntryFlags, MftEntry};
use mft::MftParser;

use crate::{PathBuilder, Reference};

fn reference(entry: u64, sequence: u16) -> Reference {
    Reference::new(u128::from(sequence) << 48 | u128::from(entry))
}

/// The long name first: Win32 (or Win32 and DOS), then POSIX, then the 8.3
/// DOS name.
fn rank(namespace: FileNamespace) -> u8 {
    match namespace {
        FileNamespace::Win32 | FileNamespace::Win32AndDos => 3,
        FileNamespace::POSIX => 2,
        FileNamespace::DOS => 1,
    }
}

/// The best name of a file across its base record and extension records,
/// ranked by namespace (the first of the best rank), and its parent.
fn best_name<'a>(records: impl Iterator<Item = &'a MftEntry>) -> Option<(String, Reference)> {
    let mut best: Option<(u8, String, Reference)> = None;
    for record in records {
        let attributes = record
            .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
            .filter_map(Result::ok);
        for attribute in attributes {
            let Some(file_name) = attribute.data.as_file_name() else {
                continue;
            };
            let rank = rank(file_name.namespace);
            if best.as_ref().is_some_and(|(known, ..)| *known >= rank) {
                continue;
            }
            best = Some((
                rank,
                file_name.name.to_utf8_string(),
                reference(file_name.parent.entry, file_name.parent.sequence),
            ));
        }
    }
    best.map(|(_, name, parent)| (name, parent))
}

impl PathBuilder {
    /// Seed with every directory of `parser`'s MFT, in use or deleted, and
    /// return how many there were.
    ///
    /// A directory's long name is often in an extension record (when its
    /// attributes did not fit in the base record), so its name is chosen
    /// across the base record and the extension records that still belong to
    /// it (ys-mft-parser's `get_extension_entries`, which leaves out the
    /// records a reused base record's previous owner left behind): Win32 over
    /// POSIX over DOS, whichever record holds it. A deleted directory is
    /// seeded with the sequence number the journal knew it by: NTFS raises it
    /// when the record is freed.
    pub fn seed_from_mft<R: Read + Seek>(&mut self, parser: &mut MftParser<R>) -> usize {
        let mut seeded = 0;
        for number in 0..parser.get_entry_count() {
            let Ok(entry) = parser.get_entry(number) else {
                continue;
            };
            if !entry.header.is_base_record() || !entry.is_dir() {
                continue;
            }
            let sequence = if entry.header.flags.contains(EntryFlags::ALLOCATED) {
                entry.header.sequence
            } else if let Some(before_free) = entry.header.sequence.checked_sub(1) {
                before_free
            } else {
                continue;
            };
            let extensions = parser.get_extension_entries(&entry);
            let Some((name, parent)) = best_name(std::iter::once(&entry).chain(&extensions)) else {
                continue;
            };
            self.seed(reference(number, sequence), &name, parent);
            seeded += 1;
        }
        seeded
    }
}
