//! Clean exec with explicit stdio, environment and checked descriptor closes.
use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

/// A direct child, killed and reaped on drop unless its exit status was
/// already collected, so its pid cannot be recycled under the handle.
pub struct Child(Option<rustix::process::Pid>);

impl Child {
    pub fn try_exit(&mut self) -> io::Result<Option<rustix::process::WaitStatus>> {
        let Some(pid) = self.0 else {
            return Err(io::ErrorKind::NotFound.into());
        };
        let status = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)?;
        if status.is_some() {
            self.0 = None;
        }
        Ok(status.map(|(_, status)| status))
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
        }
    }
}

/// posix_spawn rather than `Command`: its file actions close, by number, the
/// descriptors this process inherited without close-on-exec from whatever
/// launched it. Safe Rust cannot own those to mark them close-on-exec. The
/// child gets exactly `stdin` (or `/dev/null`) on 0, `/dev/null` on 1 and 2,
/// and with `sweep` every other descriptor in the listing is closed. Serialize
/// descriptor creation or validate/sweep again at child entry: enumeration
/// and spawn are not atomic.
pub fn spawn_clean(
    program: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    stdin: Option<OwnedFd>,
    sweep: bool,
) -> io::Result<Child> {
    use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, posix_spawn};
    use std::os::unix::ffi::OsStrExt;
    let cstring = |bytes: &[u8]| {
        CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    };
    let program = cstring(program.as_os_str().as_bytes())?;
    let mut argv = vec![program.clone()];
    for arg in args {
        argv.push(cstring(arg.as_bytes())?);
    }
    let mut envp = Vec::with_capacity(env.len());
    for (key, value) in env {
        let mut pair = key.as_bytes().to_vec();
        pair.push(b'=');
        pair.extend_from_slice(value.as_bytes());
        envp.push(cstring(&pair)?);
    }
    let null = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let input = stdin.as_ref().map_or(null.as_raw_fd(), AsRawFd::as_raw_fd);
    let mut actions = PosixSpawnFileActions::init().map_err(io::Error::from)?;
    actions.add_dup2(input, 0).map_err(io::Error::from)?;
    for target in 1..3 {
        actions
            .add_dup2(null.as_raw_fd(), target)
            .map_err(io::Error::from)?;
    }
    if sweep {
        for fd in crate::fds::open_descriptors()? {
            if fd >= 3 {
                actions.add_close(fd).map_err(io::Error::from)?;
            }
        }
    }
    let attr = PosixSpawnAttr::init().map_err(io::Error::from)?;
    let pid =
        posix_spawn(program.as_c_str(), &actions, &attr, &argv, &envp).map_err(io::Error::from)?;
    let pid = rustix::process::Pid::from_raw(pid.as_raw())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(Child(Some(pid)))
}
