//! Reading a journal from a stream, in bounded memory.

use std::io::{self, Read};

use crate::record::MAX_RECORD;
use crate::scan::{Scanner, Step};
use crate::Entry;

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
    Records {
        reader,
        buffer: vec![0; BUFFER].into_boxed_slice(),
        start: 0,
        end: 0,
        at_eof: false,
        failed: false,
        scanner: Scanner::default(),
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
