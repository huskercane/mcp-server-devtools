//! Reading a journal back: one record at a time, with the sequence checked
//! and the hash chain recomputed as it goes (WPs B.5, B.6, B.7).
//!
//! Shared by the verifier, the exports, and the metrics report. Strict in
//! the same way the journal's own recovery is — a gap, a duplicate, or an
//! unparseable line is a finding, not something to skip — but it *reports*
//! rather than refuses, because a verifier's job is to say what is wrong.
//! A torn trailing line (the one corruption an append-only file can
//! legitimately produce) is reported as such and ends the read.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use serde_json::Value;

use super::checkpoint::{CHECKPOINT_KIND, Chain};

/// One journal line, parsed, with the chain state on either side of it.
#[derive(Debug, Clone)]
pub struct Record {
    pub seq: u64,
    /// The record's `kind`: a tool-call kind, a control kind, or
    /// [`CHECKPOINT_KIND`].
    pub kind: String,
    pub value: Value,
    /// The exact line, including its trailing newline.
    pub line: Vec<u8>,
    /// The chain value **before** this line was folded in — what a
    /// checkpoint at this sequence asserts.
    pub chain_before: Chain,
}

impl Record {
    #[must_use]
    pub fn is_checkpoint(&self) -> bool {
        self.kind == CHECKPOINT_KIND
    }

    /// The record's `timestamp`, when present.
    #[must_use]
    pub fn timestamp(&self) -> Option<&str> {
        self.value.get("timestamp").and_then(Value::as_str)
    }
}

/// Why a read stopped or a line could not be accounted for.
#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    /// The line is not a JSON object with a numeric `seq` and a string `kind`.
    Unparseable {
        at_seq: u64,
        detail: String,
    },
    /// The `seq` is not the previous one plus one.
    Gap {
        expected: u64,
        found: u64,
    },
    /// The file ends mid-line.
    TornTail {
        after_seq: u64,
        bytes: usize,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "read error: {error}"),
            Self::Unparseable { at_seq, detail } => {
                write!(formatter, "record {at_seq} is unparseable: {detail}")
            }
            Self::Gap { expected, found } => write!(
                formatter,
                "expected sequence {expected}, found {found} (gap, duplicate, or reordering)"
            ),
            Self::TornTail { after_seq, bytes } => write!(
                formatter,
                "torn trailing record after sequence {after_seq} ({bytes} bytes without a newline)"
            ),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Where a reader stands between two records: what the next record's
/// sequence must be, how many bytes of the file precede it, and the chain
/// value over everything before it. A forwarder persists one of these as
/// its cursor and resumes from it after a restart ([`JournalReader::resume`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub next_seq: u64,
    pub offset: u64,
    pub chain: Chain,
}

impl Position {
    /// Before the first record.
    #[must_use]
    pub fn start() -> Self {
        Self {
            next_seq: 1,
            offset: 0,
            chain: Chain::genesis(),
        }
    }
}

/// Iterates the records of a journal file.
pub struct JournalReader {
    reader: BufReader<File>,
    expected: u64,
    offset: u64,
    chain: Chain,
    done: bool,
}

impl JournalReader {
    /// Open the journal file (`<dir>/audit-journal.jsonl`, or a file path).
    ///
    /// # Errors
    ///
    /// When the file cannot be opened.
    pub fn open(path: &Path) -> io::Result<Self> {
        let path = if path.is_dir() {
            path.join(super::journal::JOURNAL_FILE_NAME)
        } else {
            path.to_path_buf()
        };
        Ok(Self {
            reader: BufReader::new(File::open(path)?),
            expected: 1,
            offset: 0,
            chain: Chain::genesis(),
            done: false,
        })
    }

    /// Open the journal and continue from `position`, as a reader that had
    /// read everything before it would: the next record must carry
    /// `position.next_seq`, and the chain continues from `position.chain`.
    /// The caller vouches for the position (it came from this reader);
    /// a position past the end of the file is an error here, and a record
    /// with the wrong sequence is a [`ReadError::Gap`] on the first read.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened, or is shorter than `position.offset`.
    pub fn resume(path: &Path, position: Position) -> io::Result<Self> {
        use std::io::Seek as _;
        let path = if path.is_dir() {
            path.join(super::journal::JOURNAL_FILE_NAME)
        } else {
            path.to_path_buf()
        };
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        if len < position.offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "journal is {len} bytes, shorter than the resume offset {}",
                    position.offset
                ),
            ));
        }
        file.seek(io::SeekFrom::Start(position.offset))?;
        Ok(Self {
            reader: BufReader::new(file),
            expected: position.next_seq,
            offset: position.offset,
            chain: position.chain,
            done: false,
        })
    }

    /// Where the reader stands after the records read so far.
    #[must_use]
    pub const fn position(&self) -> Position {
        Position {
            next_seq: self.expected,
            offset: self.offset,
            chain: self.chain,
        }
    }

    /// The chain value after every record read so far. (Not `chain`: that
    /// is `Iterator::chain`.)
    #[must_use]
    pub const fn chain_state(&self) -> Chain {
        self.chain
    }

    /// The sequence the next record must carry.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.expected
    }

    fn read_one(&mut self) -> Result<Option<Record>, ReadError> {
        let mut line = Vec::new();
        let read = self.reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(None);
        }
        if line.last() != Some(&b'\n') {
            return Err(ReadError::TornTail {
                after_seq: self.expected - 1,
                bytes: read,
            });
        }
        let value: Value =
            serde_json::from_slice(&line[..read - 1]).map_err(|error| ReadError::Unparseable {
                at_seq: self.expected,
                detail: error.to_string(),
            })?;
        let seq =
            value
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or_else(|| ReadError::Unparseable {
                    at_seq: self.expected,
                    detail: "no numeric `seq`".to_owned(),
                })?;
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| ReadError::Unparseable {
                at_seq: self.expected,
                detail: "no string `kind`".to_owned(),
            })?
            .to_owned();
        if seq != self.expected {
            return Err(ReadError::Gap {
                expected: self.expected,
                found: seq,
            });
        }
        let chain_before = self.chain;
        self.chain.extend(&line);
        self.expected += 1;
        self.offset += read as u64;
        Ok(Some(Record {
            seq,
            kind,
            value,
            line,
            chain_before,
        }))
    }
}

impl Iterator for JournalReader {
    type Item = Result<Record, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read_one() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                // Every error here is terminal: after a gap or a torn line
                // nothing later can be attributed to a sequence.
                self.done = true;
                Some(Err(error))
            }
        }
    }
}
