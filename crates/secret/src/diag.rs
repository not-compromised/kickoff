//! The diagnostics schema (design §6.4). A diagnostics record is a typed value
//! under a key from one of the closed tables below. Nothing here takes a
//! string, so a log line, argv, launcher output, a path, a peer name or a
//! ticket has no way into an export; a new field is a new table row, reviewed
//! here.

use std::fmt;

/// Each table row is the one place its key's tag (for channels) and name (for
/// rendering) are defined.
macro_rules! schema_table {
    ($(#[$meta:meta])* $table:ident { $($variant:ident = $tag:literal, $name:literal;)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $table {
            $($variant,)+
        }

        impl $table {
            pub const ALL: &'static [$table] = &[$($table::$variant,)+];

            pub fn name(self) -> &'static str {
                match self {
                    $($table::$variant => $name,)+
                }
            }

            pub fn tag(self) -> u8 {
                match self {
                    $($table::$variant => $tag,)+
                }
            }

            pub fn from_tag(tag: u8) -> Option<Self> {
                match tag {
                    $($tag => Some($table::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

schema_table! {
    /// Monotonic event counts.
    Counter {
        LanFromGame = 1, "lan.from_game";
        LanToGame = 2, "lan.to_game";
        LanDroppedFilter = 3, "lan.dropped_filter";
        LanDroppedMalformed = 4, "lan.dropped_malformed";
        LanDroppedOverload = 5, "lan.dropped_overload";
        SessionPeers = 6, "session.peers";
        SessionJoinsRefused = 7, "session.joins_refused";
        SessionKicks = 8, "session.kicks";
        NetOverBudget = 9, "net.over_budget";
        IpcPeersRejected = 10, "ipc.peers_rejected";
        IpcFramesRefused = 11, "ipc.frames_refused";
    }
}

schema_table! {
    Flag {
        SessionActive = 1, "session.active";
        GameboxRunning = 2, "gamebox.running";
        LandlockActive = 3, "landlock.active";
    }
}

schema_table! {
    Component {
        Kickoff = 1, "version.kickoff";
        IpcProtocol = 2, "version.ipc_protocol";
    }
}

schema_table! {
    StateKey {
        SessionRole = 1, "state.session_role";
        LinkPath = 2, "state.link_path";
        Game = 3, "state.game";
    }
}

schema_table! {
    StateValue {
        None = 1, "none";
        Unknown = 2, "unknown";
        Host = 3, "host";
        Guest = 4, "guest";
        Relay = 5, "relay";
        Direct = 6, "direct";
        Menu = 7, "menu";
        Lobby = 8, "lobby";
        Match = 9, "match";
    }
}

schema_table! {
    /// Which of Kickoff's locations a path-type record describes; the path
    /// itself is never recorded.
    PathRole {
        RuntimeDir = 1, "path.runtime_dir";
        Library = 2, "path.library";
        Copies = 3, "path.copies";
        Prefix = 4, "path.prefix";
        State = 5, "path.state";
        OnlineInstall = 6, "path.online_install";
    }
}

schema_table! {
    PathKind {
        Missing = 1, "missing";
        Directory = 2, "directory";
        File = 3, "file";
        Symlink = 4, "symlink";
        Socket = 5, "socket";
        Other = 6, "other";
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    Count(Counter, u64),
    Flag(Flag, bool),
    Version(Component, Version),
    State(StateKey, StateValue),
    PathType(PathRole, PathKind),
}

impl Field {
    pub fn key(&self) -> &'static str {
        match *self {
            Field::Count(key, _) => key.name(),
            Field::Flag(key, _) => key.name(),
            Field::Version(key, _) => key.name(),
            Field::State(key, _) => key.name(),
            Field::PathType(key, _) => key.name(),
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=", self.key())?;
        match *self {
            Field::Count(_, n) => write!(f, "{n}"),
            Field::Flag(_, b) => write!(f, "{b}"),
            Field::Version(_, v) => write!(f, "{}.{}.{}", v.major, v.minor, v.patch),
            Field::State(_, s) => f.write_str(s.name()),
            Field::PathType(_, k) => f.write_str(k.name()),
        }
    }
}

/// At most this many fields per report, so a report has a fixed worst-case
/// size on every channel that carries it.
pub const MAX_FIELDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportFull;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    fields: Vec<Field>,
}

impl Report {
    pub fn new() -> Report {
        Report::default()
    }

    pub fn push(&mut self, field: Field) -> Result<(), ReportFull> {
        if self.fields.len() >= MAX_FIELDS {
            return Err(ReportFull);
        }
        self.fields.push(field);
        Ok(())
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
}

/// One `key=value` line per field: the export format and the preview the
/// owner sees before it is written.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for field in &self.fields {
            writeln!(f, "{field}")?;
        }
        Ok(())
    }
}
