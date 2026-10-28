//! Seeding [`PathBuilder`] from the volume's `$MFT` (feature `mft`), with
//! Yamato Security's ys-mft-parser.

use std::io::{Read, Seek};

use mft::entry::{find_best_name_attribute_in, EntryFlags};
use mft::MftParser;

use crate::{PathBuilder, Reference};

fn reference(entry: u64, sequence: u16) -> Reference {
    Reference::new(u128::from(sequence) << 48 | u128::from(entry))
}

impl PathBuilder {
    /// Seed with every directory of `parser`'s MFT, in use or deleted, and
    /// return how many there were.
    ///
    /// A directory's long name is often in an extension record (when its
    /// attributes did not fit in the base record), so its name is chosen
    /// across the base record and the extension records that still belong to
    /// it (ys-mft-parser's `get_extension_entries`, which leaves out the
    /// records a reused base record's previous owner left behind), the long
    /// name preferred. A deleted directory is seeded with the sequence number
    /// the journal knew it by: NTFS raises it when the record is freed.
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
            let Some(name) = find_best_name_attribute_in(&entry, &extensions) else {
                continue;
            };
            self.seed(
                reference(number, sequence),
                &name.name.to_utf8_string(),
                reference(name.parent.entry, name.parent.sequence),
            );
            seeded += 1;
        }
        seeded
    }
}
