//! Walking a journal: records, the zeros between and before them, and
//! whatever else is there.
//!
//! The scanner sees the journal through windows that start where it
//! stopped, so a whole file in memory and a stream read in chunks take the
//! same path.

use crate::record::{decode, Decoded, Fit, ALIGNMENT};
use crate::{Entry, Problem, ProblemKind};

/// Zeros are checked this many bytes at a time: a sparse `$J` can start
/// with gigabytes of them.
const ZERO_CHUNK: usize = 64 * 1024;
/// Zeros are first looked at one by one, this many of them.
const SHORT_RUN: usize = 256;

/// What one step found.
pub(crate) enum Step {
    /// Bytes skipped (zeros, or bytes that aren't records).
    Advance(usize),
    /// An entry, and the bytes it took (none for a problem reported once
    /// the bytes it covers have been passed).
    Found(usize, Entry),
    /// The window ends too soon to tell.
    NeedMore,
    /// The journal is done.
    End,
}

/// What the start of a window holds.
enum Here {
    /// Too little of it to tell.
    NeedMore,
    /// This many bytes that aren't zeros or a record.
    Unreadable(usize),
    /// Something to take once any unreadable run before it is reported.
    Readable(Step),
}

/// Where the walk is.
#[derive(Debug, Default)]
pub(crate) struct Scanner {
    /// Offset in the journal of the next window's start.
    offset: u64,
    /// Start of the run of unreadable bytes being passed, if any.
    unreadable_from: Option<u64>,
}

impl Scanner {
    /// Take one step through `window`, which starts where the last step
    /// stopped; `at_eof` when the journal ends with it.
    pub(crate) fn step(&mut self, window: &[u8], at_eof: bool) -> Step {
        match self.look(window, at_eof) {
            Here::NeedMore => Step::NeedMore,
            Here::Unreadable(bytes) => {
                self.unreadable_from.get_or_insert(self.offset);
                self.take(Step::Advance(bytes))
            }
            Here::Readable(step) => match self.end_unreadable() {
                Some(problem) => Step::Found(0, Entry::Problem(problem)),
                None => self.take(step),
            },
        }
    }

    fn look(&self, window: &[u8], at_eof: bool) -> Here {
        if window.is_empty() {
            return if at_eof {
                Here::Readable(Step::End)
            } else {
                Here::NeedMore
            };
        }
        let zeros = zero_run(window, at_eof);
        if zeros > 0 {
            return Here::Readable(Step::Advance(zeros));
        }
        if window.len() < ALIGNMENT {
            return if at_eof {
                Here::Unreadable(window.len())
            } else {
                Here::NeedMore
            };
        }
        match decode(window, self.offset) {
            Fit::Complete(length, Decoded::Change(record)) => {
                Here::Readable(Step::Found(length, Entry::Record(record)))
            }
            Fit::Complete(length, Decoded::Ranges(record)) => {
                Here::Readable(Step::Found(length, Entry::Ranges(record)))
            }
            Fit::Incomplete if !at_eof => Here::NeedMore,
            // A header the journal ends too soon for, with a whole record
            // after it: the header is a false one, not a cut record.
            Fit::Incomplete if record_ahead(window) => Here::Unreadable(ALIGNMENT),
            Fit::Incomplete => {
                let problem = Problem {
                    offset: self.offset,
                    length: window.len() as u64,
                    kind: ProblemKind::Truncated,
                };
                Here::Readable(Step::Found(window.len(), Entry::Problem(problem)))
            }
            Fit::Invalid => Here::Unreadable(ALIGNMENT),
        }
    }

    /// Move past what `step` took.
    fn take(&mut self, step: Step) -> Step {
        let bytes = match &step {
            Step::Advance(bytes) | Step::Found(bytes, _) => *bytes,
            Step::NeedMore | Step::End => 0,
        };
        self.offset += bytes as u64;
        step
    }

    /// The run of unreadable bytes that ends here, if one does.
    fn end_unreadable(&mut self) -> Option<Problem> {
        let from = self.unreadable_from.take()?;
        Some(Problem {
            offset: from,
            length: self.offset - from,
            kind: ProblemKind::Unreadable,
        })
    }
}

/// Whether a whole record starts at a later word of `window` (the journal's
/// last bytes, shorter than the largest record).
fn record_ahead(window: &[u8]) -> bool {
    (ALIGNMENT..window.len())
        .step_by(ALIGNMENT)
        .any(|at| matches!(decode(&window[at..], 0), Fit::Complete(..)))
}

/// How many bytes at the start of `window` are whole zero words; all of
/// them, when the journal ends with them.
fn zero_run(window: &[u8], at_eof: bool) -> usize {
    // Most steps start at a record: answer those from the first word instead
    // of scanning a whole chunk first.
    if window.iter().take(ALIGNMENT).any(|&byte| byte != 0) {
        return 0;
    }
    // Short runs (page padding, the gaps in data being carved) end within a
    // few words: find their end byte by byte rather than with a chunk scan.
    let short = window.len().min(SHORT_RUN);
    let mut zeros = match window[..short].iter().position(|&byte| byte != 0) {
        Some(end) => return round_down(end, window.len(), at_eof),
        None => short,
    };
    for chunk in window[short..].chunks(ZERO_CHUNK) {
        // An OR over the chunk compiles to wide instructions; finding the
        // first non-zero byte is only done once.
        if chunk.iter().fold(0, |any, &byte| any | byte) != 0 {
            zeros += chunk.iter().take_while(|&&byte| byte == 0).count();
            break;
        }
        zeros += chunk.len();
    }
    round_down(zeros, window.len(), at_eof)
}

/// `zeros` in whole words; all of them when they run to the journal's end.
fn round_down(zeros: usize, window: usize, at_eof: bool) -> usize {
    if at_eof && zeros == window {
        zeros
    } else {
        zeros - zeros % ALIGNMENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_runs_end_on_a_word() {
        let mut window = vec![0_u8; 100_000];
        window[70_001] = 1;
        assert_eq!(zero_run(&window, false), 70_000);
        assert_eq!(zero_run(&[0; 13], false), 8);
        assert_eq!(zero_run(&[0; 13], true), 13);
        assert_eq!(zero_run(&[1, 0, 0, 0, 0, 0, 0, 0], true), 0);
        let mut short = vec![0_u8; 300];
        short[20] = 1;
        assert_eq!(zero_run(&short, false), 16);
        short[20] = 0;
        assert_eq!(zero_run(&short, true), 300);
        short[299] = 1;
        assert_eq!(zero_run(&short, true), 296);
    }
}
