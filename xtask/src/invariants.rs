//! The rows of `docs/SECURITY-INVARIANTS.md`. Each section has its own table
//! header, so columns are found by name from the header above each row, not by
//! position.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// `SI-<n>`.
    pub id: String,
    pub number: u32,
    pub enforced_by: String,
    pub mutant: String,
    pub scope: String,
    pub held: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub what: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SECURITY-INVARIANTS.md line {}: {}",
            self.line, self.what
        )
    }
}

impl std::error::Error for ParseError {}

struct Columns {
    count: usize,
    enforced_by: usize,
    mutant: usize,
    scope: usize,
    held: usize,
}

impl Columns {
    fn from_header(cells: &[&str]) -> Option<Columns> {
        // "Mutant" or "Mutant (test must fail)".
        let find = |name: &str| {
            cells.iter().position(|c| {
                *c == name || c.strip_prefix(name).is_some_and(|r| r.starts_with(" ("))
            })
        };
        Some(Columns {
            count: cells.len(),
            enforced_by: find("Enforced by")?,
            mutant: find("Mutant")?,
            scope: find("Scope")?,
            held: find("Held")?,
        })
    }
}

pub fn parse(text: &str) -> Result<Vec<Row>, ParseError> {
    let mut columns: Option<Columns> = None;
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_no = index.saturating_add(1);
        let err = |what| ParseError {
            line: line_no,
            what,
        };
        let Some(inner) = line
            .trim()
            .strip_prefix('|')
            .and_then(|l| l.strip_suffix('|'))
        else {
            continue;
        };
        let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
        let first = cells.first().copied().unwrap_or("");
        if first == "#" {
            columns = Some(Columns::from_header(&cells).ok_or(err("table header lacks a column"))?);
            continue;
        }
        let Some(number) = first.strip_prefix("SI-") else {
            continue;
        };
        let number: u32 = number.parse().map_err(|_| err("row id is not SI-<n>"))?;
        let cols = columns.as_ref().ok_or(err("row before any table header"))?;
        if cells.len() != cols.count {
            return Err(err("row has a different number of cells than its header"));
        }
        let cell = |i: usize| cells.get(i).copied().unwrap_or("").to_owned();
        rows.push(Row {
            id: first.to_owned(),
            number,
            enforced_by: cell(cols.enforced_by),
            mutant: cell(cols.mutant),
            scope: cell(cols.scope),
            held: cell(cols.held),
        });
    }
    Ok(rows)
}

impl Row {
    /// Whether the Held column names `milestone` as a whole word: `M2` in
    /// "M2 (Linux), M7 (Windows)" but not in "M2a" or "M12".
    pub fn held_in(&self, milestone: &str) -> bool {
        self.held
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| word == milestone)
    }

    /// Build mutants the Mutant column names (`mutant-si<n>-...` in backticks).
    /// Configuration mutants are prose and are not returned.
    pub fn named_mutants(&self) -> Vec<String> {
        code_spans(&self.mutant)
            .filter(|s| s.starts_with("mutant-"))
            .map(str::to_owned)
            .collect()
    }

    /// Test functions the Enforced-by column names in backticks: snake_case
    /// identifiers with at least one underscore, such as `online_untouched`.
    /// Constants (`SCM_RIGHTS`), types and file names are not tests.
    pub fn named_tests(&self) -> Vec<String> {
        code_spans(&self.enforced_by)
            .filter(|s| {
                s.contains('_')
                    && s.starts_with(|c: char| c.is_ascii_lowercase())
                    && s.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            })
            .map(str::to_owned)
            .collect()
    }

    /// The prefix every test enforcing this row carries (`si_18_`).
    pub fn test_prefix(&self) -> String {
        format!("si_{}_", self.number)
    }
}

fn code_spans(text: &str) -> impl Iterator<Item = &str> {
    text.split('`').skip(1).step_by(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "\
| # | Rule | Enforced by | Mutant (test must fail) | Born from | Scope | Held |
|---|---|---|---|---|---|---|
| SI-1 | r | **Test** `online_untouched` and `SCM_RIGHTS` | `mutant-si1-a`; a prose mutant | X | all | M5 |

| # | Rule | Enforced by | Mutant | Born from | Scope | Held |
|---|---|---|---|---|---|---|
| SI-7 | r | t | `mutant-si7-b` | X | Linux | M2 (Linux), M7 (Windows) |
| SI-9 | r | t | m | X | all | M12, M2a |
";

    #[test]
    fn columns_are_found_by_name_in_each_section() {
        let rows = parse(DOC).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].named_tests(), ["online_untouched"]);
        assert_eq!(rows[0].named_mutants(), ["mutant-si1-a"]);
        assert!(rows[1].held_in("M2") && rows[1].held_in("M7"));
        assert!(!rows[2].held_in("M2"));
        assert_eq!(rows[1].test_prefix(), "si_7_");
    }

    #[test]
    fn a_row_that_does_not_fit_its_header_is_refused() {
        let doc = "| # | Enforced by | Mutant | Scope | Held |\n| SI-2 | a | b | c |\n";
        assert_eq!(parse(doc).unwrap_err().line, 2);
        assert_eq!(parse("| SI-2 | a |\n").unwrap_err().line, 1);
    }
}
