#![allow(
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::collections::HashSet;

use kickoff_secret::diag::{
    Component, Counter, Field, Flag, MAX_FIELDS, PathKind, PathRole, Report, ReportFull, StateKey,
    StateValue, Version,
};

fn key_names() -> Vec<&'static str> {
    let mut names = Vec::new();
    names.extend(Counter::ALL.iter().map(|k| k.name()));
    names.extend(Flag::ALL.iter().map(|k| k.name()));
    names.extend(Component::ALL.iter().map(|k| k.name()));
    names.extend(StateKey::ALL.iter().map(|k| k.name()));
    names.extend(PathRole::ALL.iter().map(|k| k.name()));
    names
}

fn word_values() -> HashSet<&'static str> {
    let mut words: HashSet<&'static str> = StateValue::ALL.iter().map(|v| v.name()).collect();
    words.extend(PathKind::ALL.iter().map(|v| v.name()));
    words.extend(["true", "false"]);
    words
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[(self.next() % items.len() as u64) as usize]
    }
}

fn random_field(rng: &mut Rng) -> Field {
    let field = match rng.next() % 5 {
        0 => Field::Count(rng.pick(Counter::ALL), rng.next()),
        1 => Field::Flag(rng.pick(Flag::ALL), rng.next().is_multiple_of(2)),
        2 => Field::Version(
            rng.pick(Component::ALL),
            Version {
                major: rng.next() as u16,
                minor: rng.next() as u16,
                patch: rng.next() as u16,
            },
        ),
        3 => Field::State(rng.pick(StateKey::ALL), rng.pick(StateValue::ALL)),
        _ => Field::PathType(rng.pick(PathRole::ALL), rng.pick(PathKind::ALL)),
    };
    // Exhaustive on purpose: a new kind of field must be generated above, and
    // its rendering must then pass the grammar check below.
    match field {
        Field::Count(..)
        | Field::Flag(..)
        | Field::Version(..)
        | Field::State(..)
        | Field::PathType(..) => field,
    }
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| is_number(p))
}

/// Everything an export can contain is a schema key and a typed value, so no
/// secret, path, peer name or log text can be in it (SI-30).
#[test]
fn si_30_diagnostics_render_only_schema_keys_and_typed_values() {
    let keys: HashSet<&str> = key_names().into_iter().collect();
    let words = word_values();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..2000 {
        let mut report = Report::new();
        for _ in 0..(rng.next() % 40) {
            report.push(random_field(&mut rng)).unwrap();
        }
        let rendered = report.to_string();
        assert_eq!(rendered.lines().count(), report.fields().len());
        for line in rendered.lines() {
            let (key, value) = line.split_once('=').expect("key=value");
            assert!(keys.contains(key), "unknown key {key:?}");
            assert!(
                is_number(value) || is_version(value) || words.contains(value),
                "free-form value {value:?} under {key}"
            );
        }
    }
}

#[test]
fn schema_names_and_tags_are_unique_and_plain() {
    let names = key_names();
    let unique: HashSet<&str> = names.iter().copied().collect();
    assert_eq!(unique.len(), names.len(), "duplicate diagnostics key");
    for name in names.iter().chain(word_values().iter()) {
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_'),
            "{name:?}"
        );
    }

    macro_rules! roundtrip {
        ($($table:ty),+) => {$(
            let tags: HashSet<u8> = <$table>::ALL.iter().map(|k| k.tag()).collect();
            assert_eq!(tags.len(), <$table>::ALL.len());
            for k in <$table>::ALL {
                assert_eq!(<$table>::from_tag(k.tag()), Some(*k));
            }
            assert_eq!(<$table>::from_tag(0), None);
        )+};
    }
    roundtrip!(
        Counter, Flag, Component, StateKey, StateValue, PathRole, PathKind
    );
}

#[test]
fn report_is_bounded() {
    let mut report = Report::new();
    let field = Field::Count(Counter::LanToGame, 1);
    for _ in 0..MAX_FIELDS {
        report.push(field).unwrap();
    }
    assert_eq!(report.push(field), Err(ReportFull));
    assert_eq!(report.fields().len(), MAX_FIELDS);
}
