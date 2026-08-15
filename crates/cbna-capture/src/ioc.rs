//! Reader for a threat-intel indicator list.
//!
//! The list is the second kind of external file this tool trusts a third party
//! to hand an analyst (a capture is the first), so parsing it lives here, on the
//! I/O side of the crate boundary, and produces a finished [`IocSet`] for the
//! no-I/O core to match against. The format is deliberately plain: one indicator
//! per line, `#` starts a comment, blank lines are ignored, and each token is
//! auto-classified as an IP, CIDR, domain or JA3 hash.
//!
//! It never fails as a whole — a line it cannot classify becomes a warning and
//! the rest of the list still loads — and it never panics on arbitrary bytes, so
//! it is fuzzed alongside the capture readers.

use cbna_core::ioc::{IocError, IocSet};

/// A line the parser could not turn into an indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocWarning {
    /// 1-based line number in the source, for pointing the operator at it.
    pub line: usize,
    /// The offending text, trimmed.
    pub text: String,
    /// Why it was skipped.
    pub reason: String,
}

/// Ceiling on collected warnings. A file that is mostly junk should not build an
/// unbounded warning list; past this the parser stops recording them but keeps
/// loading the indicators it can. The set itself is bounded by
/// [`IocSet::MAX_INDICATORS`].
const MAX_WARNINGS: usize = 100;

/// Parse an indicator list from raw bytes into an [`IocSet`] plus any lines that
/// were skipped. Non-UTF-8 bytes on a line are replaced rather than rejected, so
/// a stray encoding does not lose the rest of the file.
pub fn parse_iocs(bytes: &[u8]) -> (IocSet, Vec<IocWarning>) {
    let mut set = IocSet::default();
    let mut warnings = Vec::new();

    for (i, raw) in bytes.split(|&b| b == b'\n').enumerate() {
        let line = String::from_utf8_lossy(raw);
        // Everything from the first '#' is a comment. A '#' never appears in any
        // indicator we accept, so this is safe to strip unconditionally.
        let token = line.split('#').next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        match set.insert(token) {
            Ok(_) => {}
            Err(reason) => {
                if warnings.len() < MAX_WARNINGS {
                    warnings.push(IocWarning {
                        line: i + 1,
                        text: token.to_string(),
                        reason: reason.to_string(),
                    });
                }
                // A full set is not worth spamming a warning per remaining line;
                // one is enough to tell the operator the list was truncated.
                if reason == IocError::Full {
                    break;
                }
            }
        }
    }

    (set, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_mixed_list() {
        let list = b"# malware feed, 2026-08\n\
                     203.0.113.7\n\
                     198.51.100.0/24\n\
                     c2.evil.example\n\
                     e7d705a3286e19ea42f587b344ee6865\n";
        let (set, warnings) = parse_iocs(list);
        assert_eq!(set.len(), 4);
        assert!(warnings.is_empty());
    }

    #[test]
    fn skips_blanks_and_comments() {
        let list = b"\n  \n# just a comment\n10.0.0.1  # inline note\n";
        let (set, warnings) = parse_iocs(list);
        assert_eq!(set.len(), 1);
        assert!(warnings.is_empty());
        assert!(set.match_ip("10.0.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn records_unclassifiable_lines_with_their_number() {
        let list = b"203.0.113.7\nnot a valid indicator\nevil.example\n";
        let (set, warnings) = parse_iocs(list);
        assert_eq!(set.len(), 2);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].line, 2);
        assert_eq!(warnings[0].text, "not a valid indicator");
    }

    #[test]
    fn non_utf8_bytes_do_not_lose_the_file() {
        // A bad byte on its own line is skipped; the valid line after it loads.
        let mut list = vec![0xff, 0xfe, b'\n'];
        list.extend_from_slice(b"evil.example\n");
        let (set, _warnings) = parse_iocs(&list);
        assert!(set.match_domain("evil.example").is_some());
    }

    #[test]
    fn empty_input_is_an_empty_set() {
        let (set, warnings) = parse_iocs(b"");
        assert!(set.is_empty());
        assert!(warnings.is_empty());
    }
}
