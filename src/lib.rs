//! The NTFS USN change journal: `$Extend\$UsnJrnl:$J`, Windows' record of
//! every change to every file on a volume, as KAPE, Velociraptor and
//! forensic images give it.
//!
//! A `$J` is mostly a sparse file: NTFS frees the journal's old pages, so a
//! collected copy is often gigabytes of zeros followed by the records still
//! kept. Records are 8-byte aligned and never cross a 4 KiB page; the end
//! of a page is padded with zeros. Zeros are skipped 64 KiB at a time.
//!
//! Three record versions are read:
//!
//! - **V2** (`USN_RECORD_V2`, what NTFS writes by default) and **V3**
//!   (`USN_RECORD_V3`, 128-bit file references: ReFS, and NTFS when a
//!   program asks for them) become a [`Record`]: when, which file and
//!   directory, why ([`Reasons`]), the name, attributes and security id.
//! - **V4** (`USN_RECORD_V4`, range tracking) becomes a [`RangeRecord`]:
//!   the file and the ranges of it written.
//!
//! Bytes that aren't a record are passed 8 at a time until the next record
//! or zeros, and reported as one [`Problem`]; so is a record the journal
//! ends in the middle of. Neither is fatal.
//!
//! [`parse`] reads a journal held in memory; [`read`] reads one from a
//! stream, holding at most 1 MiB of it. A record names its file and
//! directory by MFT reference: joining with the volume's MFT gives paths.

mod flags;
mod record;
mod scan;
mod stream;

use core::fmt;

pub use flags::{Attributes, Reasons, SourceInfo};
pub use record::{Extent, RangeRecord, Record, Reference, Version};
pub use stream::{read, Records};

use scan::{Scanner, Step};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Something in the journal, in journal order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A change to a file (V2 or V3).
    Record(Record),
    /// Ranges of a file written (V4).
    Ranges(RangeRecord),
    /// Bytes that couldn't be read as records.
    Problem(Problem),
}

/// Bytes that couldn't be read as records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Problem {
    /// Byte offset in the journal where they start.
    pub offset: u64,
    /// How many bytes.
    pub length: u64,
    /// What they are.
    pub kind: ProblemKind,
}

/// What a [`Problem`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    /// Not zeros and not a record: damage, or data that isn't a journal.
    Unreadable,
    /// The start of a record that the journal ends before.
    Truncated,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            ProblemKind::Unreadable => "not USN records, skipped",
            ProblemKind::Truncated => "a USN record cut short by the end of the journal",
        };
        write!(
            f,
            "bytes {}..{}: {what}",
            self.offset,
            self.offset + self.length
        )
    }
}

/// A journal's contents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Journal {
    /// Changes to files (V2 and V3), in journal order.
    pub records: Vec<Record>,
    /// Ranges written (V4), in journal order.
    pub ranges: Vec<RangeRecord>,
    /// Bytes that couldn't be read as records, in journal order.
    pub problems: Vec<Problem>,
}

impl Journal {
    fn push(&mut self, entry: Entry) {
        match entry {
            Entry::Record(record) => self.records.push(record),
            Entry::Ranges(record) => self.ranges.push(record),
            Entry::Problem(problem) => self.problems.push(problem),
        }
    }
}

/// Read a journal held in memory. For a journal too big for that, see
/// [`read`].
///
/// ```
/// let journal = usn::parse(&[0; 4096]);
/// assert!(journal.records.is_empty() && journal.problems.is_empty());
/// ```
#[must_use]
pub fn parse(data: &[u8]) -> Journal {
    let mut journal = Journal::default();
    let mut scanner = Scanner::default();
    let mut at = 0;
    loop {
        // At the end of the data, the scanner never needs more.
        match scanner.step(&data[at..], true) {
            Step::Advance(bytes) => at += bytes,
            Step::Found(bytes, entry) => {
                at += bytes;
                journal.push(entry);
            }
            Step::NeedMore | Step::End => return journal,
        }
    }
}
