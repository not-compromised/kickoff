//! The descriptor sweep shared by every Kickoff process that starts with
//! inherited authority it must drop: kickoffd and its worker at entry, and the
//! gamebox's trusted links before they exec the next link (SI-36).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

/// Closes every descriptor above stdio, each close checked (SI-36). Call it
/// before the process opens descriptors of its own: anything it opened
/// first would be closed under it.
pub fn close_descriptors_above_stdio() -> io::Result<()> {
    close_above_stdio(&open_descriptors()?, |fd| {
        nix::unistd::close(fd).map_err(io::Error::from)
    })
}

/// As [`close_descriptors_above_stdio`], keeping the descriptors in `keep`:
/// the ones a link was handed on purpose, at numbers fixed by its caller.
pub fn close_descriptors_above_stdio_except(keep: &[i32]) -> io::Result<()> {
    let listed: Vec<i32> = open_descriptors()?
        .into_iter()
        .filter(|fd| !keep.contains(fd))
        .collect();
    close_above_stdio(&listed, |fd| {
        nix::unistd::close(fd).map_err(io::Error::from)
    })
}

/// Descriptor numbers in another process's `fd` directory, open on `dir`,
/// listed and closed as strictly as this process's own.
pub fn descriptors_in(dir: OwnedFd) -> io::Result<Vec<i32>> {
    list_and_close(dir, read_names, checked_close, Listing::Other)
}

/// Every listed descriptor above stdio must close, or startup is refused.
/// Not every error leaves the descriptor open: Linux releases the number
/// even when close reports EINTR or EIO, and EBADF means it was not open.
/// But a filter that refuses the call leaves it open, and no error proves
/// it closed, so every error refuses rather than being skipped.
fn close_above_stdio(
    listed: &[i32],
    mut close: impl FnMut(i32) -> io::Result<()>,
) -> io::Result<()> {
    for &fd in listed.iter().filter(|fd| **fd >= 3) {
        match close(fd) {
            Ok(()) => {}
            Err(_) if cfg!(feature = "mutant-si36-fd-errors-skipped") => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Descriptor numbers open in this process, from `/proc/self/fd`.
pub fn open_descriptors() -> io::Result<Vec<i32>> {
    use rustix::fs::{Mode, OFlags};
    let listing = rustix::fs::open(
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    list_and_close(listing, read_names, checked_close, Listing::Own)
}

fn checked_close(fd: OwnedFd) -> io::Result<()> {
    nix::unistd::close(fd).map_err(io::Error::from)
}

/// Whose `fd` directory a listing reads. In this process's own, the
/// listing's descriptor is itself an entry and is left out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Listing {
    Own,
    Other,
}

/// Lists the descriptor directory open on `listing` through `read`, then
/// closes `listing` through `close`, checked like every other close: left
/// open, it would be a descriptor outside the allowlist that the list no
/// longer names. Only `listing`'s own number is left out and nothing listed
/// is looked up, so no lookup error can hide an entry. Any read, close or
/// name error refuses.
fn list_and_close(
    listing: OwnedFd,
    read: impl FnOnce(BorrowedFd<'_>) -> io::Result<Vec<Vec<u8>>>,
    close: impl FnOnce(OwnedFd) -> io::Result<()>,
    whose: Listing,
) -> io::Result<Vec<i32>> {
    let own = listing.as_raw_fd();
    let names = read(listing.as_fd());
    let closed = close(listing);
    let names = names?;
    if !cfg!(feature = "mutant-si36-listing-close-unchecked") {
        closed?;
    }
    let mut open = Vec::new();
    for name in names {
        if name == b"." || name == b".." {
            continue;
        }
        let fd = std::str::from_utf8(&name)
            .ok()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or(io::ErrorKind::InvalidData)?;
        if cfg!(feature = "mutant-si36-listed-fds-looked-up")
            && std::fs::symlink_metadata(Path::new("/proc/self/fd").join(fd.to_string())).is_err()
        {
            continue;
        }
        if whose == Listing::Other || fd != own {
            open.push(fd);
        }
    }
    Ok(open)
}

/// Every entry name of the directory open on `dir`, through getdents64,
/// with every error returned. rustix's `Dir` ends the listing on ENOENT
/// instead, which would turn a refused enumeration into a short list.
fn read_names(dir: BorrowedFd<'_>) -> io::Result<Vec<Vec<u8>>> {
    let mut buf = Vec::with_capacity(8192);
    let mut entries = rustix::fs::RawDir::new(dir, buf.spare_capacity_mut());
    let mut names = Vec::new();
    while let Some(entry) = entries.next() {
        match entry {
            Ok(entry)
                if cfg!(feature = "mutant-si36-enumeration-looks-up")
                    && entry.file_name().to_str().is_ok_and(|name| {
                        name.parse::<i32>().is_ok()
                            && std::fs::symlink_metadata(Path::new("/proc/self/fd").join(name))
                                .is_err()
                    }) => {}
            Ok(entry) => names.push(entry.file_name().to_bytes().to_vec()),
            Err(_) if cfg!(feature = "mutant-si36-listing-error-ends") => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn open_dir(path: &str) -> OwnedFd {
        use rustix::fs::{Mode, OFlags};
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn checked_close(fd: OwnedFd) -> io::Result<()> {
        nix::unistd::close(fd).map_err(io::Error::from)
    }

    #[test]
    fn si_36_descriptor_listing_keeps_every_enumerated_descriptor() {
        // The real enumeration names the descriptors this test holds and
        // leaves out only the listing's own number.
        let held = [open_dir("/"), open_dir("/proc")];
        let listing = open_dir("/proc/self/fd");
        let own = listing.as_raw_fd();
        let listed = list_and_close(listing, read_names, checked_close, Listing::Own).unwrap();
        for fd in &held {
            assert!(
                listed.contains(&fd.as_raw_fd()),
                "held descriptor {} was enumerated but dropped, so it would stay open",
                fd.as_raw_fd()
            );
        }
        assert!(
            !listed.contains(&own),
            "the listing's own descriptor was listed"
        );

        // Every enumerated number is kept whether or not a lookup of it would
        // succeed: i32::MAX is never open here, so a lookup filter drops it.
        let listing = open_dir("/proc/self/fd");
        let own = listing.as_raw_fd().to_string().into_bytes();
        let mut names: Vec<Vec<u8>> = [".", "..", "0", "1", "2"].map(Vec::from).into();
        names.extend([own, b"2147483647".to_vec()]);
        assert_eq!(
            list_and_close(listing, |_| Ok(names), checked_close, Listing::Own)
                .map_err(|e| e.kind()),
            Ok(vec![0, 1, 2, i32::MAX]),
            "an enumerated descriptor was dropped, so it would stay open"
        );
        let listing = open_dir("/proc/self/fd");
        let names = vec![b"3".to_vec(), b"not-a-number".to_vec()];
        assert_eq!(
            list_and_close(listing, |_| Ok(names), checked_close, Listing::Own)
                .map_err(|e| e.kind()),
            Err(io::ErrorKind::InvalidData)
        );
    }

    const HOLDER: &str = "KIPC_DESCRIPTOR_HOLDER";
    const HOLDER_FD: &str = "HOLDER-FD ";
    const HOLDER_SEALED: &str = "HOLDER-NONDUMPABLE";
    /// Far above anything the test process holds.
    const HELD_FD: i32 = 900;

    /// Holds [`HELD_FD`], then turns nondumpable when told on stdin, and
    /// exits at stdin's EOF.
    #[test]
    fn descriptor_holder_helper() {
        use std::io::{Read, Write};
        if std::env::var_os(HOLDER).is_none() {
            return;
        }
        let null = std::fs::File::open("/dev/null").unwrap();
        let held = rustix::io::fcntl_dupfd_cloexec(&null, HELD_FD).unwrap();
        println!("{HOLDER_FD}{}", held.as_raw_fd());
        let mut byte = [0u8];
        std::io::stdin().read_exact(&mut byte).unwrap();
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .unwrap();
        println!("{HOLDER_SEALED}");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
    }

    #[test]
    fn si_36_descriptor_enumeration_keeps_entries_whose_lookup_fails() {
        // getdents64 lists a descriptor directory opened earlier even after
        // its process turns nondumpable, while every lookup of its entries
        // fails: by number in this process (not held here), and through the
        // directory itself (EACCES once procfs revalidates its owner). A
        // lookup filter anywhere in the enumeration drops the entry.
        // Root, even a user namespace's, still looks up a nondumpable
        // process's entries, so as root the scenario reruns unprivileged.
        use std::io::{BufRead, Write};
        use std::process::{Command, Stdio};
        if rustix::process::geteuid().is_root() {
            rerun_unprivileged(
                "fds::tests::si_36_descriptor_enumeration_keeps_entries_whose_lookup_fails",
            );
            return;
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fds::tests::descriptor_holder_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HOLDER, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut marked = |marker: &str| loop {
            let line = lines.next().unwrap().unwrap();
            if let Some((_, rest)) = line.split_once(marker) {
                return rest.to_owned();
            }
        };
        let held = marked(HOLDER_FD);
        let listing = open_dir(&format!("/proc/{}/fd", child.id()));
        stdin.write_all(b"x").unwrap();
        marked(HOLDER_SEALED);
        std::fs::symlink_metadata(format!("/proc/{}/fd", child.id())).unwrap();
        assert!(
            std::fs::symlink_metadata(format!("/proc/self/fd/{held}")).is_err(),
            "this process holds {held} too"
        );
        assert_eq!(
            rustix::fs::statat(
                &listing,
                held.as_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW
            )
            .map(drop),
            Err(rustix::io::Errno::ACCESS),
            "a lookup through the nondumpable process's listing succeeded: \
             this process bypasses permission checks (CAP_DAC_*)"
        );
        let listed = list_and_close(listing, read_names, checked_close, Listing::Other).unwrap();
        drop(stdin);
        child.wait().unwrap();
        assert!(
            listed.contains(&held.parse().unwrap()),
            "enumerated descriptor {held} was dropped because its lookup failed: {listed:?}"
        );
    }

    /// Runs test `name` as uid and gid 65534 from a copy of this executable
    /// that uid can run, and requires that it ran and passed. Dropping from
    /// root to another uid clears every capability.
    fn rerun_unprivileged(name: &str) {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        struct Dir(PathBuf);
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir =
            Dir(std::env::temp_dir().join(format!("kickoff-unprivileged-{}", std::process::id())));
        std::fs::create_dir(&dir.0).unwrap();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exe = dir.0.join("tests");
        crate::test_exec::copy_executable(std::env::current_exe().unwrap(), &exe);
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = std::process::Command::new(&exe)
            .args(["--exact", name, "--test-threads=1"])
            .current_dir(&dir.0)
            .uid(65534)
            .gid(65534)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{name} failed as uid 65534:\n{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn si_36_descriptor_listing_refuses_an_enumeration_error() {
        // getdents64 on the descriptor directory of a reaped process fails
        // with ENOENT, which rustix's Dir reports as the end of the listing.
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let listing = open_dir(&format!("/proc/{}/fd", child.id()));
        child.kill().unwrap();
        child.wait().unwrap();
        let mut closed = Vec::new();
        let listed = list_and_close(
            listing,
            read_names,
            |fd| {
                closed.push(fd.as_raw_fd());
                checked_close(fd)
            },
            Listing::Own,
        )
        .map_err(|e| e.kind());
        assert_eq!(
            listed,
            Err(io::ErrorKind::NotFound),
            "an enumeration error passed as a complete listing"
        );
        assert_eq!(
            closed.len(),
            1,
            "the listing was not closed after the error"
        );
    }

    #[test]
    fn si_36_descriptor_listing_refuses_when_its_own_close_fails() {
        for errno in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
            let listing = open_dir("/proc/self/fd");
            let own = listing.as_raw_fd();
            let mut closed = Vec::new();
            let listed = list_and_close(
                listing,
                read_names,
                |fd| {
                    closed.push(fd.as_raw_fd());
                    drop(fd);
                    Err(errno.into())
                },
                Listing::Own,
            )
            .map_err(|e| e.kind());
            assert_eq!(
                listed,
                Err(errno),
                "the listing descriptor failed to close ({errno:?}) and the listing still succeeded"
            );
            assert_eq!(
                closed,
                [own],
                "the close was not given the listing descriptor"
            );
        }
    }

    #[test]
    fn si_36_sweep_close_fails_closed_on_any_error() {
        for errno in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
            let mut attempted = Vec::new();
            let result = close_above_stdio(&[0, 1, 2, 3, 7, 9], |fd| {
                attempted.push(fd);
                if fd == 7 { Err(errno.into()) } else { Ok(()) }
            });
            assert!(
                result.is_err(),
                "a descriptor that failed to close ({errno:?}) was skipped"
            );
            assert_eq!(attempted, [3, 7], "stdio was closed or the sweep went on");
        }
        let mut attempted = Vec::new();
        let result = close_above_stdio(&[0, 1, 2, 3, 9], |fd| {
            attempted.push(fd);
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(attempted, [3, 9]);
    }
}

#[cfg(test)]
mod other_tests {
    use super::*;

    #[test]
    fn another_process_listing_keeps_every_number() {
        // Listing another process's directory leaves nothing out, not even
        // a number equal to the listing's own descriptor here.
        let child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let dir = rustix::fs::open(
            format!("/proc/{}/fd", child.id()),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut listed = descriptors_in(dir).unwrap();
        listed.sort_unstable();
        let mut child = child;
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(listed.starts_with(&[0, 1, 2]), "{listed:?}");
    }
}
