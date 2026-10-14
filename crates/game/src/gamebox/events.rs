//! What the supervisor waits on: SIGTERM (stop), SIGCHLD (the chain or a
//! helper ended) and, once the box has a network, host network changes. Every
//! wait, including scope registration and helpers, goes through here, so a
//! stop is seen at once whatever the supervisor is doing.

use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::SignalFd;
use rustix::event::{PollFd, PollFlags, Timespec};

use super::Refused;

pub(super) const POLL: Duration = Duration::from_millis(5);

/// Why the supervisor stops waiting for the box.
#[derive(Debug)]
pub(super) enum Halt {
    /// SIGTERM: a normal stop.
    Stop,
    /// The chain's first process (pasta) ended.
    Ended(ExitStatus),
    Refused(Refused),
}

impl From<Refused> for Halt {
    fn from(refused: Refused) -> Self {
        Halt::Refused(refused)
    }
}

impl From<std::io::Error> for Halt {
    fn from(error: std::io::Error) -> Self {
        Halt::Refused(error.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Wake {
    Child,
    Extra,
    Timeout,
}

pub(super) struct Events {
    signals: SignalFd,
    stopping: bool,
    child: bool,
}

impl Events {
    /// Blocks SIGTERM and SIGCHLD and reads them from a descriptor. Child
    /// processes get an empty mask again (std resets it; the links do too).
    pub(super) fn new() -> Result<Events, Refused> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGCHLD);
        mask.thread_block()?;
        Ok(Events {
            signals: SignalFd::new(&mask)?,
            stopping: false,
            child: false,
        })
    }

    /// Waits for a child to end, `extra` to become readable or `deadline`.
    /// A stop, once seen, is returned by this and every later wait.
    pub(super) fn wait(
        &mut self,
        extra: Option<BorrowedFd<'_>>,
        deadline: Instant,
    ) -> Result<Wake, Halt> {
        loop {
            if self.stopping {
                return Err(Halt::Stop);
            }
            if std::mem::take(&mut self.child) {
                return Ok(Wake::Child);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let mut fds = vec![PollFd::new(&self.signals, PollFlags::IN)];
            if let Some(fd) = extra {
                fds.push(PollFd::from_borrowed_fd(fd, PollFlags::IN));
            }
            rustix::event::poll(&mut fds, Some(&timespec(left))).map_err(Refused::from)?;
            let signalled = fds.first().is_some_and(|f| !f.revents().is_empty());
            let extra_ready = fds.get(1).is_some_and(|f| !f.revents().is_empty());
            if signalled {
                self.read_signal()?;
                continue;
            }
            if extra_ready {
                return Ok(Wake::Extra);
            }
            if Instant::now() >= deadline {
                return Ok(Wake::Timeout);
            }
        }
    }

    /// Whether a stop arrived, without waiting. The barrier is never
    /// released once one has.
    pub(super) fn stop_pending(&mut self) -> Result<bool, Halt> {
        loop {
            let mut fds = [PollFd::new(&self.signals, PollFlags::IN)];
            let ready = rustix::event::poll(&mut fds, Some(&timespec(Duration::ZERO)))
                .map_err(Refused::from)?;
            if ready == 0 {
                return Ok(self.stopping);
            }
            self.read_signal()?;
        }
    }

    fn read_signal(&mut self) -> Result<(), Refused> {
        let Some(info) = self.signals.read_signal()? else {
            return Ok(());
        };
        let signal = i32::try_from(info.ssi_signo)
            .ok()
            .and_then(|n| Signal::try_from(n).ok());
        match signal {
            Some(Signal::SIGTERM) => self.stopping = true,
            Some(Signal::SIGCHLD) => self.child = true,
            _ => {}
        }
        Ok(())
    }

    /// Waits for `chain` to end. Returns how the wait ended.
    pub(super) fn until_end(&mut self, chain: &mut Child) -> Halt {
        loop {
            match self.wait(None, after(Duration::from_secs(3600))) {
                Ok(Wake::Child) => match chain.try_wait() {
                    Ok(Some(status)) => return Halt::Ended(status),
                    Ok(None) => {}
                    Err(error) => return error.into(),
                },
                Ok(_) => {}
                Err(halt) => return halt,
            }
        }
    }

    /// Runs a helper to completion within `limit`, answering a stop, the
    /// chain's end or a timeout by killing and reaping it. Returns its exit
    /// status and stdout.
    pub(super) fn helper(
        &mut self,
        chain: &mut Child,
        command: &mut Command,
        limit: Duration,
    ) -> Result<(ExitStatus, Vec<u8>), Halt> {
        let mut helper = Reaped(
            command
                .stdout(Stdio::piped())
                .spawn()
                .map_err(Refused::from)?,
        );
        let mut stdout = helper.0.stdout.take().ok_or(Refused::Malformed)?;
        rustix::io::ioctl_fionbio(&stdout, true).map_err(Refused::from)?;
        let deadline = after(limit);
        let mut out = Vec::new();
        let mut open = true;
        loop {
            if !open && let Some(status) = helper.0.try_wait()? {
                return Ok((status, out));
            }
            let fd = stdout.as_fd();
            match self.wait(open.then_some(fd), deadline)? {
                Wake::Extra => {
                    let mut chunk = [0u8; 4096];
                    match stdout.read(&mut chunk) {
                        Ok(0) => open = false,
                        Ok(n) => out.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(e.into()),
                    }
                    if out.len() > 1 << 20 {
                        return Err(Refused::HelperFailed.into());
                    }
                }
                Wake::Child => {
                    if let Some(status) = chain.try_wait()? {
                        return Err(Halt::Ended(status));
                    }
                }
                Wake::Timeout => return Err(Refused::HelperFailed.into()),
            }
        }
    }
}

/// A helper that is killed and reaped when dropped, unless it ended first.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// Runs a helper with no output within `limit`, killing and reaping it
/// on timeout. For teardown, where a stop is already in progress.
pub(super) fn bounded(command: &mut Command, limit: Duration) -> Result<ExitStatus, Refused> {
    let mut helper = Reaped(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let started = Instant::now();
    loop {
        if let Some(status) = helper.0.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() > limit {
            return Err(Refused::HelperFailed);
        }
        std::thread::sleep(POLL);
    }
}

/// `d` from now; an unrepresentable deadline is now, which fails closed.
pub(super) fn after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d).unwrap_or(now)
}

pub(super) fn timespec(d: Duration) -> Timespec {
    Timespec {
        tv_sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(d.subsec_nanos()),
    }
}
