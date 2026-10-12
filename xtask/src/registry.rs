//! `/mutants.toml`: every mutant, the SI tests that have none and why, and
//! the M2 rows still waiting for code. A strict reader for the small subset of
//! TOML the file uses, so the harness needs no dependency: `[[table]]`
//! headers and `key = "string"` pairs, which may follow the header on its own
//! line (`[[mutant]] si = "SI-3", crate = "..."`) or come one per line.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutant {
    /// `SI-<n>`.
    pub si: String,
    /// The package that holds the protection and declares the feature.
    pub krate: String,
    /// `mutant-si<n>-<slug>`.
    pub feature: String,
    /// The name of the test function that must fail with the feature on and
    /// pass without it.
    pub test: String,
    /// The package whose tests hold `test`; defaults to `krate`.
    pub test_crate: String,
    pub note: String,
}

/// An SI test no feature flag can falsify (a compile-time check, or a
/// self-test of a checker), with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmutated {
    pub test: String,
    pub reason: String,
}

/// Something an M2 row names that this branch does not have yet: `item` is a
/// named mutant feature, `test` (the row has no test) or `mutant` (the row
/// has no mutant). The policy reports these apart from failures, and fails
/// once one is no longer missing, so the list only shrinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub si: String,
    pub item: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    pub mutants: Vec<Mutant>,
    pub unmutated: Vec<Unmutated>,
    pub pending: Vec<Pending>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub what: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mutants.toml line {}: {}", self.line, self.what)
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Table {
    Mutant,
    Unmutated,
    Pending,
}

impl Table {
    fn named(name: &str) -> Option<Table> {
        match name {
            "mutant" => Some(Table::Mutant),
            "unmutated" => Some(Table::Unmutated),
            "pending" => Some(Table::Pending),
            _ => None,
        }
    }

    fn keys(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Table::Mutant => (&["si", "crate", "feature", "test", "note"], &["test_crate"]),
            Table::Unmutated => (&["test", "reason"], &[]),
            Table::Pending => (&["si", "item", "reason"], &[]),
        }
    }
}

struct Entry {
    table: Table,
    line: usize,
    pairs: Vec<(String, String)>,
}

impl Entry {
    fn take(&mut self, key: &str) -> String {
        self.pairs
            .iter()
            .position(|(k, _)| k == key)
            .map(|i| self.pairs.swap_remove(i).1)
            .unwrap_or_default()
    }
}

pub fn parse(text: &str) -> Result<Registry, ParseError> {
    let mut entries: Vec<Entry> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index.saturating_add(1);
        let err = |what: &str| ParseError {
            line,
            what: what.to_owned(),
        };
        let mut rest = strip_comment(raw).trim();
        if rest.is_empty() {
            continue;
        }
        if let Some(after) = rest.strip_prefix("[[") {
            let (name, tail) = after
                .split_once("]]")
                .ok_or_else(|| err("unclosed header"))?;
            let table = Table::named(name.trim()).ok_or_else(|| err("unknown table"))?;
            entries.push(Entry {
                table,
                line,
                pairs: Vec::new(),
            });
            rest = tail.trim();
            if rest.is_empty() {
                continue;
            }
        }
        let entry = entries
            .last_mut()
            .ok_or_else(|| err("key outside a [[table]]"))?;
        for (key, value) in pairs(rest).map_err(|what| err(&what))? {
            let (required, optional) = entry.table.keys();
            if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
                return Err(err(&format!("unknown key `{key}`")));
            }
            if entry.pairs.iter().any(|(k, _)| *k == key) {
                return Err(err(&format!("duplicate key `{key}`")));
            }
            entry.pairs.push((key, value));
        }
    }

    let mut registry = Registry::default();
    for mut entry in entries {
        let (required, _) = entry.table.keys();
        if let Some(missing) = required
            .iter()
            .find(|k| !entry.pairs.iter().any(|(key, _)| key == *k))
        {
            return Err(ParseError {
                line: entry.line,
                what: format!("missing key `{missing}`"),
            });
        }
        match entry.table {
            Table::Mutant => {
                let krate = entry.take("crate");
                let test_crate = Some(entry.take("test_crate"))
                    .filter(|c| !c.is_empty())
                    .unwrap_or_else(|| krate.clone());
                registry.mutants.push(Mutant {
                    si: entry.take("si"),
                    feature: entry.take("feature"),
                    test: entry.take("test"),
                    note: entry.take("note"),
                    krate,
                    test_crate,
                });
            }
            Table::Unmutated => registry.unmutated.push(Unmutated {
                test: entry.take("test"),
                reason: entry.take("reason"),
            }),
            Table::Pending => registry.pending.push(Pending {
                si: entry.take("si"),
                item: entry.take("item"),
                reason: entry.take("reason"),
            }),
        }
    }
    Ok(registry)
}

/// Everything after a `#` that is not inside a string.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '#' if !in_string => return line.get(..i).unwrap_or(line),
            _ => {}
        }
    }
    line
}

/// `key = "value"` pairs separated by commas. Strings support `\"` and `\\`
/// only; anything else is refused rather than guessed at.
fn pairs(mut text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    loop {
        let (key, after) = text.split_once('=').ok_or("expected `key = \"value\"`")?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
        {
            return Err(format!("bad key `{key}`"));
        }
        let after = after.trim_start();
        let body = after.strip_prefix('"').ok_or("values must be strings")?;
        let mut value = String::new();
        let mut chars = body.char_indices();
        let end = loop {
            match chars.next() {
                Some((i, '"')) => break i,
                Some((_, '\\')) => match chars.next() {
                    Some((_, c @ ('"' | '\\'))) => value.push(c),
                    _ => return Err("unsupported escape".to_owned()),
                },
                Some((_, c)) => value.push(c),
                None => return Err("unterminated string".to_owned()),
            }
        };
        out.push((key.to_owned(), value));
        let tail = body.get(end.saturating_add(1)..).unwrap_or("").trim();
        if tail.is_empty() {
            return Ok(out);
        }
        text = tail
            .strip_prefix(',')
            .ok_or("expected `,` between pairs")?
            .trim();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_layouts_parse_to_the_same_entry() {
        let blocks = "# header\n[[mutant]]\nsi = \"SI-3\"\ncrate = \"kickoff-wire\"\n\
                      feature = \"mutant-si3-x\" # trailing\ntest = \"si_3_y\"\nnote = \"a # b\"\n";
        let line = "[[mutant]] si = \"SI-3\", crate = \"kickoff-wire\", feature = \"mutant-si3-x\", \
                    test = \"si_3_y\", note = \"a # b\"\n";
        let a = parse(blocks).unwrap();
        assert_eq!(a, parse(line).unwrap());
        assert_eq!(a.mutants[0].test_crate, "kickoff-wire");
        assert_eq!(a.mutants[0].note, "a # b");
    }

    #[test]
    fn mistakes_are_refused_with_their_line() {
        for (text, line) in [
            ("si = \"SI-1\"", 1),
            ("[[mutant]]\nsi = \"SI-1\"\nsi = \"SI-2\"", 3),
            ("[[mutant]]\nwho = \"x\"", 2),
            ("[[mutants]]", 1),
            ("[[pending]]\nsi = \"SI-1\"\nitem = \"test\"", 1),
            ("[[unmutated]]\ntest = \"a\", reason = unquoted", 2),
            ("[[unmutated]]\ntest = \"a\\n\"", 2),
        ] {
            assert_eq!(parse(text).unwrap_err().line, line, "{text}");
        }
    }
}
