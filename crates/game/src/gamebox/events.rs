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
use super::netlink::HostWatch;

pub(super) const POLL: Duration = Duration::from_millis(5);

/// Why the supervisor stops waiting for the box.
#[derive(Debug)]
pub(super) enum Halt {
    /// SIGTERM: a normal stop.
    Stop,
    /// The chain's first process (pasta) ended.
    Ended(ExitStatus),
    /// The host's addresses, routes or rules changed, so the box's deny set
    /// may be stale (design §3.2.4). The box is stopped: fail closed.
    HostChanged,
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
    watch: Option<HostWatch>,
    changed: bool,
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
            watch: None,
            changed: false,
        })
    }

    /// From now on every wait also ends on a host network change.
    pub(super) fn watch(&mut self, watch: HostWatch) {
        if !cfg!(feature = "mutant-si14-no-host-watch") {
            self.watch = Some(watch);
        }
    }

    /// Waits for a child to end, `extra` to become readable or `deadline`.
    /// A stop or a host change, once seen, is returned by this and every
    /// later wait.
    pub(super) fn wait(
        &mut self,
        extra: Option<BorrowedFd<'_>>,
        deadline: Instant,
    ) -> Result<Wake, Halt> {
        loop {
            if self.stopping {
                return Err(Halt::Stop);
            }
            if self.changed {
                return Err(Halt::HostChanged);
            }
            if std::mem::take(&mut self.child) {
                return Ok(Wake::Child);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let (signalled, watched, extra_ready) = self.poll(extra, left)?;
            if signalled {
                self.read_signal()?;
                continue;
            }
            if watched {
                self.changed |= self.watch.as_ref().is_some_and(HostWatch::changed);
                continue;
            }
            // The deadline wins over a descriptor that is always readable,
            // such as a helper streaming output without end.
            let expired = Instant::now() >= deadline;
            if expired && !cfg!(feature = "mutant-si38-helper-deadline-late") {
                return Ok(Wake::Timeout);
            }
            if extra_ready {
                return Ok(Wake::Extra);
            }
            if expired {
                return Ok(Wake::Timeout);
            }
        }
    }

    /// Which of the signal descriptor, the watch and `extra` are readable.
    fn poll(
        &self,
        extra: Option<BorrowedFd<'_>>,
        timeout: Duration,
    ) -> Result<(bool, bool, bool), Refused> {
        let mut fds = vec![PollFd::new(&self.signals, PollFlags::IN)];
        let watch_at = self.watch.as_ref().map(|w| {
            fds.push(PollFd::from_borrowed_fd(w.as_fd(), PollFlags::IN));
            fds.len().saturating_sub(1)
        });
        let extra_at = extra.map(|fd| {
            fds.push(PollFd::from_borrowed_fd(fd, PollFlags::IN));
            fds.len().saturating_sub(1)
        });
        rustix::event::poll(&mut fds, Some(&timespec(timeout)))?;
        let ready = |at: Option<usize>| {
            at.and_then(|i| fds.get(i))
                .is_some_and(|f| !f.revents().is_empty())
        };
        Ok((ready(Some(0)), ready(watch_at), ready(extra_at)))
    }

    /// A stop or host change that already arrived, without waiting. The
    /// barrier is never released once one has.
    pub(super) fn pending(&mut self) -> Result<(), Halt> {
        loop {
            let (signalled, watched, _) = self.poll(None, Duration::ZERO)?;
            if signalled {
                self.read_signal()?;
            } else if watched {
                self.changed |= self.watch.as_ref().is_some_and(HostWatch::changed);
            } else {
                break;
            }
        }
        if self.stopping {
            return Err(Halt::Stop);
        }
        if self.changed {
            return Err(Halt::HostChanged);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn si_38_an_expired_deadline_wins_over_a_readable_helper_pipe() {
        // A helper that keeps its pipe readable must still be stopped at
        // its deadline: an expired wait reports Timeout even though output
        // is waiting, and never Extra.
        use std::io::Write;
        use std::os::fd::AsFd;
        let mut events = Events::new().unwrap();
        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        writer.write_all(b"output that is never read").unwrap();
        let started = Instant::now();
        let expired = started
            .checked_sub(Duration::from_millis(1))
            .unwrap_or(started);
        for _ in 0..3 {
            assert_eq!(
                events.wait(Some(reader.as_fd()), expired).ok(),
                Some(Wake::Timeout),
                "a readable pipe outlived its deadline"
            );
        }
        // Before the deadline the same pipe wakes the wait.
        assert_eq!(
            events
                .wait(Some(reader.as_fd()), after(Duration::from_secs(1)))
                .ok(),
            Some(Wake::Extra)
        );
    }
}
