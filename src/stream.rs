//! Reading a journal from a stream, in bounded memory.

use std::io::{self, Read};

use crate::record::MAX_RECORD;
use crate::scan::{Scanner, Step};
use crate::{Entry, Record};

/// How much of the stream is held at once. Larger than any record, so a
/// record always fits.
const BUFFER: usize = 1024 * 1024;
const _: () = assert!(BUFFER > MAX_RECORD);

/// Read a journal from a stream: every record and problem in journal
/// order, holding at most 1 MiB of it at a time.
///
/// ```no_run
/// let file = std::fs::File::open("$J")?;
/// for entry in usn::read(std::io::BufReader::new(file)) {
///     if let usn::Entry::Record(record) = entry? {
///         println!("{} {} {}", record.time, record.reasons, record.name);
///     }
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn read<R: Read>(reader: R) -> Records<R> {
    Records::new(reader, Scanner::default())
}

/// Carve V2 and V3 records out of data that is not a journal: a disk or
/// volume image, unallocated clusters, a pagefile, a volume shadow copy, a
/// memory image. Every 8-byte word is tried, holding at most 1 MiB at a
/// time, and only records laid out the way NTFS writes them are returned:
/// the name right after the header and the record ending with it, a USN
/// that keeps the record inside one 4 KiB journal page, a time from 1980 to
/// 2100, known reason, source and attribute bits, a valid name and a parent
/// that can be a directory. Their offsets are offsets in `reader`.
///
/// ```no_run
/// let image = std::fs::File::open("disk.raw")?;
/// for record in usn::carve(std::io::BufReader::new(image)) {
///     let record = record?;
///     println!("{} {} {} at {}", record.time, record.reasons, record.name, record.offset);
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn carve<R: Read>(reader: R) -> Carved<R> {
    Carved(Records::new(reader, Scanner::carving()))
}

/// The records carved from a stream; see [`carve`].
#[derive(Debug)]
pub struct Carved<R>(Records<R>);

impl<R: Read> Iterator for Carved<R> {
    type Item = io::Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next()? {
                Ok(Entry::Record(record)) => return Some(Ok(record)),
                Ok(Entry::Ranges(_) | Entry::Problem(_)) => {}
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

/// The entries of a journal read from a stream; see [`read`].
///
/// A read error is returned once, and ends the iteration.
#[derive(Debug)]
pub struct Records<R> {
    reader: R,
    buffer: Box<[u8]>,
    /// The bytes read and not yet stepped over.
    start: usize,
    end: usize,
    at_eof: bool,
    failed: bool,
    scanner: Scanner,
}

impl<R: Read> Records<R> {
    fn new(reader: R, scanner: Scanner) -> Self {
        Self {
            reader,
            buffer: vec![0; BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            at_eof: false,
            failed: false,
            scanner,
        }
    }

    /// Move what's left to the front of the buffer and read after it.
    fn fill(&mut self) -> io::Result<()> {
        self.buffer.copy_within(self.start..self.end, 0);
        self.end -= self.start;
        self.start = 0;
        let read = loop {
            match self.reader.read(&mut self.buffer[self.end..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => break result?,
            }
        };
        self.end += read;
        self.at_eof = read == 0;
        Ok(())
    }
}

impl<R: Read> Iterator for Records<R> {
    type Item = io::Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.failed {
            match self
                .scanner
                .step(&self.buffer[self.start..self.end], self.at_eof)
            {
                Step::Advance(bytes) => self.start += bytes,
                Step::Found(bytes, entry) => {
                    self.start += bytes;
                    return Some(Ok(entry));
                }
                Step::NeedMore => {
                    if let Err(error) = self.fill() {
                        self.failed = true;
                        return Some(Err(error));
                    }
                }
                Step::End => return None,
            }
        }
        None
    }
}
