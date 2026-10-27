//! Paths: the full path of the directory each record's file was in, as it
//! was when the record was written.
//!
//! A record only names its directory by reference. The volume's MFT gives
//! the directory's path *now*, which is wrong for every record written
//! before that directory was renamed, moved or deleted. The journal itself
//! holds those changes, so it can be rewound (the technique of
//! `RustyUsn`, usnjrnl-forensic / ntfs-core's `rewind`, and `CyberCX`'s "USN journal
//! rewind"):
//!
//! 1. [`PathBuilder::observe`] every record, in journal order. With the MFT
//!    state given to [`PathBuilder::seed`], this finds each directory's
//!    name and parent at the start of the journal: the oldest
//!    `RENAME_OLD_NAME` record of it if it was ever renamed or moved, else
//!    the MFT, else the last name the journal gives it.
//! 2. [`PathBuilder::finish`], then [`Paths::parent_path`] every record
//!    again, in the same order: each one is resolved against the state at
//!    its time, and creates and new names then update the state.
//!
//! References include the sequence number, so a directory whose MFT record
//! was reused is not mistaken for its successor. Only directories are kept
//! (records with [`Attributes::DIRECTORY`]), so memory grows with the number
//! of directories, not records; the journal is read twice instead of held.
//! Without an MFT, directories that the journal never names resolve as
//! `[Unknown <reference>]`.

use std::collections::HashMap;

use crate::{Attributes, Reasons, Record, Reference};

/// The deepest directory chain followed; deeper (or looping) chains are
/// cut with an `[Unknown …]` component.
const MAX_DEPTH: usize = 256;

/// NTFS's root directory is MFT entry 5.
const ROOT_ENTRY: u64 = 5;

/// A directory's name and its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    name: Box<str>,
    parent: Reference,
}

impl Node {
    fn of(record: &Record) -> Self {
        Self {
            name: record.name.as_str().into(),
            parent: record.parent,
        }
    }
}

/// The first pass: what the journal and the MFT say about each directory.
#[derive(Debug, Default)]
pub struct PathBuilder {
    seeds: HashMap<Reference, Node>,
    oldest_old_name: HashMap<Reference, Node>,
    last: HashMap<Reference, Node>,
}

impl PathBuilder {
    /// An empty builder: without seeds, only the directories the journal
    /// names can be resolved.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The volume's current state, from its MFT: directory `file` is named
    /// `name` in `parent`. For a deleted MFT record, NTFS has already raised
    /// the sequence number; pass the reference the journal used (sequence
    /// number one lower) as well.
    pub fn seed(&mut self, file: Reference, name: &str, parent: Reference) {
        self.seeds.insert(
            file,
            Node {
                name: name.into(),
                parent,
            },
        );
    }

    /// Learn from one record (call for every record, in journal order).
    pub fn observe(&mut self, record: &Record) {
        if !record.attributes.contains(Attributes::DIRECTORY) {
            return;
        }
        if record.reasons.contains(Reasons::RENAME_OLD_NAME) {
            self.oldest_old_name
                .entry(record.file)
                .or_insert_with(|| Node::of(record));
        }
        self.last.insert(record.file, Node::of(record));
    }

    /// The state at the start of the journal.
    #[must_use]
    pub fn finish(self) -> Paths {
        let Self {
            seeds,
            oldest_old_name,
            last,
        } = self;
        let mut nodes = last;
        nodes.extend(seeds);
        nodes.extend(oldest_old_name);
        Paths { nodes }
    }
}

/// The second pass: paths as of each record, in journal order.
#[derive(Debug, Default)]
pub struct Paths {
    nodes: HashMap<Reference, Node>,
}

impl Paths {
    /// The path of `record`'s directory when it was written (`.` for the
    /// root, `.\Windows\System32` below it), then the record's own change
    /// to the state. Call for every record, in journal order.
    pub fn parent_path(&mut self, record: &Record) -> String {
        let path = self.resolve(record.parent);
        self.apply(record);
        path
    }

    /// The path of directory `reference` in the current state, without
    /// changing it.
    #[must_use]
    pub fn resolve(&self, reference: Reference) -> String {
        let mut names: Vec<String> = Vec::new();
        let mut current = reference;
        loop {
            if is_root(current) {
                break;
            }
            match self.nodes.get(&current) {
                Some(node) if names.len() < MAX_DEPTH => {
                    names.push(node.name.to_string());
                    current = node.parent;
                }
                _ => {
                    names.push(format!("[Unknown {current}]"));
                    break;
                }
            }
        }
        let mut path = String::from(".");
        for name in names.iter().rev() {
            path.push('\\');
            path.push_str(name);
        }
        path
    }

    /// Apply `record` to the state: a directory created or given a new name
    /// takes it from here on.
    pub fn apply(&mut self, record: &Record) {
        if !record.attributes.contains(Attributes::DIRECTORY) {
            return;
        }
        if record.reasons.contains(Reasons::FILE_CREATE)
            || record.reasons.contains(Reasons::RENAME_NEW_NAME)
        {
            self.nodes.insert(record.file, Node::of(record));
        } else {
            self.nodes
                .entry(record.file)
                .or_insert_with(|| Node::of(record));
        }
    }
}

fn is_root(reference: Reference) -> bool {
    reference.is_ntfs() && reference.entry() == ROOT_ENTRY
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Filetime, SourceInfo, Version};

    fn reference(entry: u64, sequence: u16) -> Reference {
        Reference::new(u128::from(sequence) << 48 | u128::from(entry))
    }

    fn dir(file: Reference, parent: Reference, name: &str, reasons: Reasons) -> Record {
        record(file, parent, name, reasons, Attributes::DIRECTORY)
    }

    fn record(
        file: Reference,
        parent: Reference,
        name: &str,
        reasons: Reasons,
        attributes: Attributes,
    ) -> Record {
        Record {
            offset: 0,
            length: 0,
            version: Version { major: 2, minor: 0 },
            usn: 0,
            time: Filetime::new(0),
            file,
            parent,
            reasons,
            source_info: SourceInfo::default(),
            security_id: 0,
            attributes,
            name: name.into(),
            name_escaped: false,
        }
    }

    fn rewind(seeds: &[(Reference, &str, Reference)], journal: &[Record]) -> Vec<String> {
        let mut builder = PathBuilder::new();
        for (file, name, parent) in seeds {
            builder.seed(*file, name, *parent);
        }
        for r in journal {
            builder.observe(r);
        }
        let mut paths = builder.finish();
        journal.iter().map(|r| paths.parent_path(r)).collect()
    }

    const ROOT: Reference = Reference::new(5 << 48 | 5);
    const FILE: Attributes = Attributes::ARCHIVE;

    #[test]
    fn records_before_a_rename_get_the_old_directory_name() {
        let docs = reference(100, 1);
        let file = reference(200, 1);
        let journal = [
            record(file, docs, "a.txt", Reasons::FILE_CREATE, FILE),
            dir(docs, ROOT, "Old", Reasons::RENAME_OLD_NAME),
            dir(docs, ROOT, "New", Reasons::RENAME_NEW_NAME),
            record(file, docs, "a.txt", Reasons::DATA_EXTEND, FILE),
        ];
        // The MFT knows the directory by its new name only.
        let seeds = [(docs, "New", ROOT)];
        assert_eq!(rewind(&seeds, &journal), [r".\Old", ".", ".", r".\New"]);
    }

    #[test]
    fn moves_deletes_and_reused_records() {
        let a = reference(100, 1);
        let b = reference(101, 1);
        let gone = reference(102, 3);
        let reused = reference(102, 4);
        let file = reference(300, 1);
        let journal = [
            // `gone` is deleted; its MFT record is reused by another directory
            dir(gone, a, "Temp", Reasons::FILE_CREATE),
            record(file, gone, "x.exe", Reasons::FILE_CREATE, FILE),
            dir(gone, a, "Temp", Reasons::FILE_DELETE),
            dir(reused, b, "Cache", Reasons::FILE_CREATE),
            record(file, reused, "y.dat", Reasons::FILE_CREATE, FILE),
            // `b` moves from `a` to the root
            dir(b, a, "B", Reasons::RENAME_OLD_NAME),
            dir(b, ROOT, "B", Reasons::RENAME_NEW_NAME),
            record(file, reused, "z.dat", Reasons::FILE_CREATE, FILE),
        ];
        let seeds = [(a, "A", ROOT), (b, "B", ROOT), (reused, "Cache", b)];
        let paths = rewind(&seeds, &journal);
        assert_eq!(paths[1], r".\A\Temp");
        assert_eq!(paths[4], r".\A\B\Cache", "before the move");
        assert_eq!(paths[7], r".\B\Cache", "after the move");
    }

    #[test]
    fn unknown_directories_and_loops_are_marked() {
        let looped_a = reference(10, 1);
        let looped_b = reference(11, 1);
        let mut paths = PathBuilder::new();
        paths.seed(looped_a, "a", looped_b);
        paths.seed(looped_b, "b", looped_a);
        let paths = paths.finish();
        assert_eq!(paths.resolve(reference(77, 2)), r".\[Unknown 77-2]");
        assert_eq!(paths.resolve(ROOT), ".");
        let looped = paths.resolve(looped_a);
        assert!(looped.starts_with(r".\[Unknown "), "{looped}");
        assert_eq!(looped.matches('\\').count(), MAX_DEPTH + 1);
    }

    #[test]
    fn without_an_mft_the_journal_names_directories() {
        let dir_ref = reference(100, 1);
        let file = reference(200, 1);
        let journal = [
            record(file, dir_ref, "a.txt", Reasons::FILE_CREATE, FILE),
            dir(
                dir_ref,
                reference(90, 1),
                "Logs",
                Reasons::BASIC_INFO_CHANGE,
            ),
        ];
        assert_eq!(rewind(&[], &journal)[0], r".\[Unknown 90-1]\Logs");
    }
}
