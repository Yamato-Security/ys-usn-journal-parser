//! Seeding [`PathBuilder`] from the volume's `$MFT` (feature `mft`), with
//! Yamato Security's ys-mft-parser.

use std::collections::HashMap;
use std::io::{Read, Seek};

use mft::attribute::x30::FileNamespace;
use mft::attribute::MftAttributeType;
use mft::entry::EntryFlags;
use mft::MftParser;

use crate::{PathBuilder, Reference};

/// What the MFT says about one base record.
struct Base {
    allocated: bool,
    sequence: u16,
    directory: bool,
}

/// A name and its parent, ranked by namespace.
struct Name {
    rank: u8,
    text: String,
    parent: Reference,
}

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

impl PathBuilder {
    /// Seed with every directory of `parser`'s MFT, in use or deleted, and
    /// return how many there were.
    ///
    /// A directory's long name is often in an extension record (when its
    /// attributes did not fit in the base record), so the names of every
    /// record count for their base record, the long name preferred. A
    /// deleted directory is seeded with the sequence number the journal knew
    /// it by: NTFS raises it when the record is freed.
    pub fn seed_from_mft<R: Read + Seek>(&mut self, parser: &mut MftParser<R>) -> usize {
        let mut bases: HashMap<u64, Base> = HashMap::new();
        let mut names: HashMap<u64, Name> = HashMap::new();
        for number in 0..parser.get_entry_count() {
            let Ok(entry) = parser.get_entry(number) else {
                continue;
            };
            let base = match entry.header.base_reference.entry {
                0 => {
                    bases.insert(
                        entry.header.record_number,
                        Base {
                            allocated: entry.header.flags.contains(EntryFlags::ALLOCATED),
                            sequence: entry.header.sequence,
                            directory: entry.is_dir(),
                        },
                    );
                    entry.header.record_number
                }
                base => base,
            };
            let attributes = entry
                .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
                .filter_map(Result::ok);
            for attribute in attributes {
                let Some(file_name) = attribute.data.as_file_name() else {
                    continue;
                };
                let rank = rank(file_name.namespace);
                if names.get(&base).is_some_and(|known| known.rank >= rank) {
                    continue;
                }
                names.insert(
                    base,
                    Name {
                        rank,
                        text: file_name.name.to_utf8_string(),
                        parent: reference(file_name.parent.entry, file_name.parent.sequence),
                    },
                );
            }
        }
        let mut seeded = 0;
        for (number, name) in names {
            let Some(base) = bases.get(&number).filter(|base| base.directory) else {
                continue;
            };
            let sequence = if base.allocated {
                base.sequence
            } else if let Some(before_free) = base.sequence.checked_sub(1) {
                before_free
            } else {
                continue;
            };
            self.seed(reference(number, sequence), &name.text, name.parent);
            seeded += 1;
        }
        seeded
    }
}
