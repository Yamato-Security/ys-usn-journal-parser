//! One record: its layout in each version, and what it says.

use core::fmt;

use common::bytes::Reader;
use common::text::utf16le;
use common::time::Ts;

use crate::{Attributes, Reasons, SourceInfo};

/// Records are aligned to, and padded to a multiple of, 8 bytes.
pub(crate) const ALIGNMENT: usize = 8;
/// The journal is written in 4 KiB pages and no record crosses one.
pub(crate) const MAX_RECORD: usize = 4096;
/// An NTFS name is at most 255 UTF-16 code units.
const MAX_NAME_BYTES: usize = 255 * 2;
/// What every version starts with: length, major and minor version.
const COMMON_HEADER: usize = 8;
/// Fixed parts, up to the name (V2, V3) or the extents (V4).
const V2_HEADER: usize = 60;
const V3_HEADER: usize = 76;
const V4_HEADER: usize = 64;
/// A V4 extent: offset and length.
const EXTENT_SIZE: usize = 16;

/// An NTFS file reference (MFT entry number and sequence number), or a
/// 128-bit file identifier from a V3 or V4 record.
///
/// On NTFS a 128-bit identifier is the 64-bit reference with its upper
/// half zero; on ReFS it is an opaque identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reference(u128);

impl Reference {
    /// A reference from its recorded value.
    #[must_use]
    pub const fn new(raw: u128) -> Self {
        Self(raw)
    }

    /// The value as recorded.
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }

    /// The MFT entry number: the low 48 bits.
    #[must_use]
    pub const fn entry(self) -> u64 {
        (self.0 & 0xFFFF_FFFF_FFFF) as u64
    }

    /// The sequence number: bits 48 to 63. It tells reuses of one MFT entry
    /// apart, so a reference only matches an MFT record with the same one.
    #[must_use]
    pub const fn sequence(self) -> u16 {
        (self.0 >> 48) as u16
    }

    /// Whether this is an NTFS reference (the upper 64 bits are zero), so
    /// [`Reference::entry`] and [`Reference::sequence`] mean something.
    #[must_use]
    pub const fn is_ntfs(self) -> bool {
        self.0 >> 64 == 0
    }
}

/// `entry-sequence` (`30-1`) for an NTFS reference, as The Sleuth Kit
/// writes it; 32 hex digits otherwise.
impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_ntfs() {
            write!(f, "{}-{}", self.entry(), self.sequence())
        } else {
            write!(f, "0x{:032x}", self.0)
        }
    }
}

/// A record's format version: 2.0, 3.0 or 4.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version {
    /// 2, 3 or 4.
    pub major: u16,
    /// 0 in every version Windows writes.
    pub minor: u16,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A change to a file: a `USN_RECORD_V2` (64-bit references) or
/// `USN_RECORD_V3` (128-bit references).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Byte offset of the record in the journal.
    pub offset: u64,
    /// Its length in bytes, padding included.
    pub length: u32,
    /// Its format version.
    pub version: Version,
    /// Its update sequence number: its offset in the journal as NTFS
    /// counts it, which is the byte offset in a whole `$J`.
    pub usn: u64,
    /// When it was written (FILETIME, UTC).
    pub time: Ts,
    /// The file changed.
    pub file: Reference,
    /// The directory it was in. Joining with the MFT gives its path.
    pub parent: Reference,
    /// Why it was written.
    pub reasons: Reasons,
    /// Who made the change, when not an ordinary program.
    pub source_info: SourceInfo,
    /// The file's security identifier: its index in `$Secure`.
    pub security_id: u32,
    /// The file's attributes.
    pub attributes: Attributes,
    /// The file's name (not its path). Invalid UTF-16 is escaped, never
    /// replaced (`\u{d800}`).
    pub name: String,
    /// Whether the name held invalid UTF-16, now escaped.
    pub name_escaped: bool,
}

/// Which ranges of a file changed: a `USN_RECORD_V4`, written after a V3
/// record when range tracking is on (`fsutil usn enablerangetracking`).
/// It has no time or name: those are in the V3 record before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeRecord {
    /// Byte offset of the record in the journal.
    pub offset: u64,
    /// Its length in bytes, padding included.
    pub length: u32,
    /// Its format version.
    pub version: Version,
    /// Its update sequence number.
    pub usn: u64,
    /// The file changed.
    pub file: Reference,
    /// The directory it was in.
    pub parent: Reference,
    /// Why it was written.
    pub reasons: Reasons,
    /// Who made the change, when not an ordinary program.
    pub source_info: SourceInfo,
    /// How many more extents follow, in further records.
    pub remaining_extents: u32,
    /// The ranges written.
    pub extents: Vec<Extent>,
}

/// A range of a file that changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Extent {
    /// Its offset in the file, in bytes.
    pub offset: u64,
    /// Its length, in bytes.
    pub length: u64,
}

/// A record read from the start of a window.
pub(crate) enum Decoded {
    Change(Record),
    Ranges(RangeRecord),
}

/// What the start of a window holds.
pub(crate) enum Fit {
    /// A whole record, this many bytes long.
    Complete(usize, Decoded),
    /// The start of a record that the window ends before.
    Incomplete,
    /// Not a record.
    Invalid,
}

/// Read the record at the start of `window` (at least [`ALIGNMENT`] bytes),
/// which is at `offset` in the journal.
pub(crate) fn decode(window: &[u8], offset: u64) -> Fit {
    let Some((length, version)) = common_header(window) else {
        return Fit::Invalid;
    };
    let Some(data) = window.get(..length) else {
        return Fit::Incomplete;
    };
    let decoded = match version.major {
        2 => change(data, offset, version, false).map(Decoded::Change),
        3 => change(data, offset, version, true).map(Decoded::Change),
        _ => ranges(data, offset, version).map(Decoded::Ranges),
    };
    decoded.map_or(Fit::Invalid, |decoded| Fit::Complete(length, decoded))
}

/// The length and version, when they are a plausible record's.
fn common_header(window: &[u8]) -> Option<(usize, Version)> {
    let mut r = Reader::new(window);
    let length = r.u32_le().ok()? as usize;
    let version = Version {
        major: r.u16_le().ok()?,
        minor: r.u16_le().ok()?,
    };
    let fixed = match version.major {
        2 => V2_HEADER,
        3 => V3_HEADER,
        4 => V4_HEADER,
        _ => return None,
    };
    (length % ALIGNMENT == 0 && (fixed..=MAX_RECORD).contains(&length)).then_some((length, version))
}

/// Whether `length` is `used` padded to the alignment.
fn padded(used: usize, length: usize) -> bool {
    used <= length && length - used < ALIGNMENT
}

/// A file reference: 64 bits (V2) or 128 (V3, V4).
fn reference(r: &mut Reader<'_>, wide: bool) -> Option<Reference> {
    let raw = if wide {
        u128::from_le_bytes(r.array().ok()?)
    } else {
        u128::from(r.u64_le().ok()?)
    };
    Some(Reference::new(raw))
}

/// A V2 or V3 record, `data` exactly its length.
fn change(data: &[u8], offset: u64, version: Version, wide: bool) -> Option<Record> {
    let mut r = Reader::new(data);
    r.skip(COMMON_HEADER).ok()?;
    let file = reference(&mut r, wide)?;
    let parent = reference(&mut r, wide)?;
    let usn = r.u64_le().ok()?;
    let time = Ts::from_filetime(r.u64_le().ok()?);
    let reasons = Reasons::from_bits(r.u32_le().ok()?);
    let source_info = SourceInfo::from_bits(r.u32_le().ok()?);
    let security_id = r.u32_le().ok()?;
    let attributes = Attributes::from_bits(r.u32_le().ok()?);
    let name_length = usize::from(r.u16_le().ok()?);
    // Microsoft: find the name by its offset, not by the header's size.
    let name_offset = usize::from(r.u16_le().ok()?);
    let name_end = name_offset + name_length;
    if name_offset < r.position()
        || name_length % 2 != 0
        || name_length > MAX_NAME_BYTES
        || !padded(name_end, data.len())
    {
        return None;
    }
    let name = utf16le(data.get(name_offset..name_end)?);
    Some(Record {
        offset,
        length: data.len() as u32,
        version,
        usn,
        time,
        file,
        parent,
        reasons,
        source_info,
        security_id,
        attributes,
        name: name.text,
        name_escaped: name.escaped,
    })
}

/// A V4 record, `data` exactly its length.
fn ranges(data: &[u8], offset: u64, version: Version) -> Option<RangeRecord> {
    let mut r = Reader::new(data);
    r.skip(COMMON_HEADER).ok()?;
    let file = reference(&mut r, true)?;
    let parent = reference(&mut r, true)?;
    let usn = r.u64_le().ok()?;
    let reasons = Reasons::from_bits(r.u32_le().ok()?);
    let source_info = SourceInfo::from_bits(r.u32_le().ok()?);
    let remaining_extents = r.u32_le().ok()?;
    let count = usize::from(r.u16_le().ok()?);
    let extent_size = usize::from(r.u16_le().ok()?);
    if extent_size != EXTENT_SIZE || !padded(V4_HEADER + count * EXTENT_SIZE, data.len()) {
        return None;
    }
    let extents = (0..count)
        .map(|_| {
            Some(Extent {
                offset: r.u64_le().ok()?,
                length: r.u64_le().ok()?,
            })
        })
        .collect::<Option<_>>()?;
    Some(RangeRecord {
        offset,
        length: data.len() as u32,
        version,
        usn,
        file,
        parent,
        reasons,
        source_info,
        remaining_extents,
        extents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntfs_and_wide_references() {
        let ntfs = Reference::new(0x0001_0000_0000_001E);
        assert_eq!((ntfs.entry(), ntfs.sequence()), (30, 1));
        assert!(ntfs.is_ntfs());
        assert_eq!(ntfs.to_string(), "30-1");
        let wide = Reference::new(1 << 64 | 7);
        assert!(!wide.is_ntfs());
        assert_eq!(wide.to_string(), "0x00000000000000010000000000000007");
    }

    #[test]
    fn implausible_headers_are_not_records() {
        let header = |length: u32, major: u16| -> Vec<u8> {
            let mut data = length.to_le_bytes().to_vec();
            data.extend(major.to_le_bytes());
            data.extend([0, 0]);
            data
        };
        for (length, major) in [
            (0, 2),
            (60, 2),
            (68, 2),
            (72, 3),
            (4104, 2),
            (64, 1),
            (64, 5),
        ] {
            assert!(
                common_header(&header(length, major)).is_none(),
                "{length} {major}"
            );
        }
        assert!(common_header(&header(64, 2)).is_some());
        assert!(matches!(decode(&header(64, 2), 0), Fit::Incomplete));
    }
}
