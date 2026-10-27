//! The flag sets a record carries: why it was written, who wrote it, and
//! the file's attributes.

use core::fmt;

/// A set of named bits over a `u32`, with the names Windows gives them.
macro_rules! flags {
    (
        $(#[$doc:meta])*
        $name:ident {
            $($(#[$flag_doc:meta])* $flag:ident = $bit:literal,)+
        }
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name(u32);

        impl $name {
            $($(#[$flag_doc])* pub const $flag: Self = Self($bit);)+

            const NAMED: &'static [(u32, &'static str)] = &[$(($bit, stringify!($flag)),)+];
            const KNOWN: u32 = 0 $(| $bit)+;

            /// The set with these bits, named or not.
            #[must_use]
            pub const fn from_bits(bits: u32) -> Self {
                Self(bits)
            }

            /// The bits as recorded.
            #[must_use]
            pub const fn bits(self) -> u32 {
                self.0
            }

            /// Whether every bit of `other` is set.
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            /// The names of the bits set, in bit order.
            pub fn names(self) -> impl Iterator<Item = &'static str> {
                Self::NAMED
                    .iter()
                    .filter(move |(bit, _)| self.0 & bit != 0)
                    .map(|&(_, name)| name)
            }

            /// The bits set that have no name here.
            #[must_use]
            pub const fn unknown(self) -> u32 {
                self.0 & !Self::KNOWN
            }
        }

        /// The names, separated by spaces, then any unnamed bits in hex.
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut separator = "";
                for name in self.names() {
                    write!(f, "{separator}{name}")?;
                    separator = " ";
                }
                if self.unknown() != 0 {
                    write!(f, "{separator}0x{:08x}", self.unknown())?;
                }
                Ok(())
            }
        }
    };
}

flags! {
    /// Why the record was written (`USN_REASON_*`). Changes to a file are
    /// gathered until it is closed: each record carries every reason since
    /// it was opened, and the last one adds [`Reasons::CLOSE`].
    Reasons {
        /// The unnamed data stream was overwritten.
        DATA_OVERWRITE = 0x0000_0001,
        /// The unnamed data stream was extended.
        DATA_EXTEND = 0x0000_0002,
        /// The unnamed data stream was truncated.
        DATA_TRUNCATION = 0x0000_0004,
        /// A named data stream was overwritten.
        NAMED_DATA_OVERWRITE = 0x0000_0010,
        /// A named data stream was extended.
        NAMED_DATA_EXTEND = 0x0000_0020,
        /// A named data stream was truncated.
        NAMED_DATA_TRUNCATION = 0x0000_0040,
        /// The file or directory was created.
        FILE_CREATE = 0x0000_0100,
        /// The file or directory was deleted.
        FILE_DELETE = 0x0000_0200,
        /// Its extended attributes changed.
        EA_CHANGE = 0x0000_0400,
        /// Its security descriptor changed.
        SECURITY_CHANGE = 0x0000_0800,
        /// It was renamed: the record carries the old name.
        RENAME_OLD_NAME = 0x0000_1000,
        /// It was renamed: the record carries the new name.
        RENAME_NEW_NAME = 0x0000_2000,
        /// Its content-indexed attribute changed.
        INDEXABLE_CHANGE = 0x0000_4000,
        /// Its attributes or times changed.
        BASIC_INFO_CHANGE = 0x0000_8000,
        /// A hard link was added or removed.
        HARD_LINK_CHANGE = 0x0001_0000,
        /// It was compressed or decompressed.
        COMPRESSION_CHANGE = 0x0002_0000,
        /// It was encrypted or decrypted.
        ENCRYPTION_CHANGE = 0x0004_0000,
        /// Its object identifier changed.
        OBJECT_ID_CHANGE = 0x0008_0000,
        /// Its reparse point changed.
        REPARSE_POINT_CHANGE = 0x0010_0000,
        /// A named stream was added, removed or renamed.
        STREAM_CHANGE = 0x0020_0000,
        /// It changed inside a transaction (TxF).
        TRANSACTED_CHANGE = 0x0040_0000,
        /// Its integrity stream setting changed (ReFS).
        INTEGRITY_CHANGE = 0x0080_0000,
        /// Its desired storage class changed.
        DESIRED_STORAGE_CLASS_CHANGE = 0x0100_0000,
        /// The file was closed: the last record of a run of changes.
        CLOSE = 0x8000_0000,
    }
}

flags! {
    /// Who made the change, when it wasn't an ordinary program
    /// (`USN_SOURCE_*`).
    SourceInfo {
        /// The operating system, managing data: the file's content is
        /// unchanged.
        DATA_MANAGEMENT = 0x0000_0001,
        /// Auxiliary data was written (such as a cached thumbnail).
        AUXILIARY_DATA = 0x0000_0002,
        /// File replication (such as DFS replication).
        REPLICATION_MANAGEMENT = 0x0000_0004,
        /// Replication from a client, such as cloud file synchronisation.
        CLIENT_REPLICATION_MANAGEMENT = 0x0000_0008,
    }
}

flags! {
    /// The file's attributes when the record was written
    /// (`FILE_ATTRIBUTE_*`).
    Attributes {
        /// Read-only.
        READONLY = 0x0000_0001,
        /// Hidden.
        HIDDEN = 0x0000_0002,
        /// Used by the operating system.
        SYSTEM = 0x0000_0004,
        /// A directory.
        DIRECTORY = 0x0000_0010,
        /// Marked for backup or removal.
        ARCHIVE = 0x0000_0020,
        /// A device.
        DEVICE = 0x0000_0040,
        /// No other attribute.
        NORMAL = 0x0000_0080,
        /// Temporary.
        TEMPORARY = 0x0000_0100,
        /// Sparse.
        SPARSE_FILE = 0x0000_0200,
        /// Has a reparse point, or is a symbolic link.
        REPARSE_POINT = 0x0000_0400,
        /// Compressed.
        COMPRESSED = 0x0000_0800,
        /// Its data is offline, in remote storage.
        OFFLINE = 0x0000_1000,
        /// Not indexed by the content indexing service.
        NOT_CONTENT_INDEXED = 0x0000_2000,
        /// Encrypted.
        ENCRYPTED = 0x0000_4000,
        /// Has an integrity stream (ReFS).
        INTEGRITY_STREAM = 0x0000_8000,
        /// Reserved for the system.
        VIRTUAL = 0x0001_0000,
        /// Excluded from the data integrity scanner.
        NO_SCRUB_DATA = 0x0002_0000,
        /// Has no physical representation on the volume yet (cloud files).
        RECALL_ON_OPEN = 0x0004_0000,
        /// Kept fully present locally (cloud files).
        PINNED = 0x0008_0000,
        /// Not kept locally unless accessed (cloud files).
        UNPINNED = 0x0010_0000,
        /// Not fully present locally: reading it recalls it (cloud files).
        RECALL_ON_DATA_ACCESS = 0x0040_0000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_in_bit_order_and_unknown_bits_in_hex() {
        let reasons = Reasons::from_bits(0x8000_0102 | 0x0200_0000);
        assert_eq!(
            reasons.names().collect::<Vec<_>>(),
            ["DATA_EXTEND", "FILE_CREATE", "CLOSE"]
        );
        assert_eq!(reasons.unknown(), 0x0200_0000);
        assert_eq!(
            reasons.to_string(),
            "DATA_EXTEND FILE_CREATE CLOSE 0x02000000"
        );
        assert!(reasons.contains(Reasons::FILE_CREATE));
        assert!(!reasons.contains(Reasons::FILE_DELETE));
    }

    #[test]
    fn empty_sets_print_nothing() {
        assert_eq!(SourceInfo::default().to_string(), "");
        assert_eq!(Attributes::from_bits(0).names().count(), 0);
    }
}
