//! What the game sees: the bwrap view of design §3.2's table, less the
//! authorities later chunks add (render node, display socket, audio, tap).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::barrier::Fault;
use super::install::{LINK, PROBE};

pub(super) const BWRAP: &str = "/usr/bin/bwrap";
/// Where the trusted barrier link and the probe sit inside the box.
pub(super) const BOX_BIN: &str = "/kickoff/bin";

/// Host files the box reads. Everything else under /etc is absent.
const ETC: &[&str] = &[
    "nsswitch.conf",
    "host.conf",
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "ssl",
    "ca-certificates",
    "fonts",
    "localtime",
    "locale.conf",
    "os-release",
    "gai.conf",
    "protocols",
    "services",
];

pub(super) struct View<'a> {
    /// The supervisor's private directory: generated /etc files, the copy
    /// and the prefix base.
    pub run: &'a Path,
    pub link: &'a Path,
    pub probe: &'a Path,
    pub home: &'a Path,
    pub uid: u32,
    pub gid: u32,
}

impl View<'_> {
    pub(super) fn bwrap_args(&self, fault: Fault) -> Vec<OsString> {
        let mut a = Args::default();
        let (uid, gid) = if fault == Fault::Capabilities {
            ("0".to_owned(), "0".to_owned())
        } else {
            (self.uid.to_string(), self.gid.to_string())
        };
        a.s(&[
            "--unshare-user",
            "--uid",
            &uid,
            "--gid",
            &gid,
            "--unshare-pid",
        ]);
        if fault != Fault::Namespaces {
            a.s(&["--unshare-ipc"]);
        }
        a.s(&[
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--hostname",
            "kickoff",
            "--die-with-parent",
            "--new-session",
        ]);
        if fault != Fault::Capabilities {
            a.s(&["--cap-drop", "ALL"]);
        }
        a.s(&[
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/bin",
            "/sbin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/dev/shm",
            "--ro-bind",
            "/sys",
            "/sys",
        ]);
        for name in ["passwd", "group", "hosts", "resolv.conf"] {
            a.bind(
                "--ro-bind",
                &self.run.join(name),
                &Path::new("/etc").join(name),
            );
        }
        for name in ETC {
            let path = Path::new("/etc").join(name);
            if path.exists() {
                a.bind("--ro-bind", &path, &path);
            }
        }
        let run_user = format!("/run/user/{}", self.uid);
        a.s(&["--tmpfs", "/tmp", "--tmpfs", "/run", "--dir", &run_user]);
        a.s(&["--chmod", "0700", &run_user, "--tmpfs", "/home"]);
        a.s(&["--dir"]);
        a.p(self.home);
        a.s(&["--dir", "/kickoff"]);
        let copy = if cfg!(feature = "mutant-si34-copy-writable") {
            "--bind"
        } else {
            "--ro-bind"
        };
        a.bind(copy, &self.run.join("game"), Path::new("/kickoff/game"));
        if cfg!(feature = "mutant-si35-host-x11-mounted") {
            a.s(&["--ro-bind", "/tmp/.X11-unix", "/tmp/.X11-unix"]);
        }
        // The writable layer is the sized tmpfs the setup link mounted on
        // prefix-rw, in its own mount namespace (design §3.2 table).
        a.bind("--overlay-src", &self.run.join("prefix"), Path::new(""));
        a.bind(
            "--overlay",
            &self.run.join("prefix-rw").join("upper"),
            &self.run.join("prefix-rw").join("work"),
        );
        a.s(&["/kickoff/prefix"]);
        a.bind("--ro-bind", self.link, &Path::new(BOX_BIN).join(LINK));
        a.bind("--ro-bind", self.probe, &Path::new(BOX_BIN).join(PROBE));
        a.s(&["--chdir", "/kickoff", "--setenv", "HOME"]);
        a.p(self.home);
        a.s(&[
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "XDG_RUNTIME_DIR",
            &run_user,
            "--setenv",
            "WINEPREFIX",
            "/kickoff/prefix",
            "--",
        ]);
        a.0
    }
}

#[derive(Default)]
struct Args(Vec<OsString>);

impl Args {
    fn s(&mut self, args: &[&str]) {
        self.0.extend(args.iter().map(OsString::from));
    }
    fn p(&mut self, path: &Path) {
        self.0.push(path.as_os_str().to_owned());
    }
    /// `option source [dest]`; an empty `dest` is left out.
    fn bind(&mut self, option: &str, source: &Path, dest: &Path) {
        self.0.push(option.into());
        self.p(source);
        if dest != Path::new("") {
            self.p(dest);
        }
    }
}

/// The barrier link and the probe as the box sees them.
pub(super) fn in_box(name: &str) -> PathBuf {
    Path::new(BOX_BIN).join(name)
}
