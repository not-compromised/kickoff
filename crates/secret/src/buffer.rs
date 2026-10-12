//! Owned transport bytes. No shared owners; every release wipes the allocation.

use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

pub struct SecretBuffer(Vec<u8>);

impl SecretBuffer {
    pub fn zeroed(len: usize) -> Self {
        Self(vec![0; len])
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }
    pub fn copy_from(bytes: &[u8]) -> Self {
        let mut out = Self::with_capacity(bytes.len());
        out.extend_from_slice(bytes);
        out
    }
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        let len = self.0.len().saturating_add(bytes.len());
        if len > self.0.capacity() {
            let mut grown = Self::with_capacity(len);
            grown.0.extend_from_slice(&self.0);
            std::mem::swap(self, &mut grown);
        }
        self.0.extend_from_slice(bytes);
    }
    pub fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }
    pub fn truncate(&mut self, len: usize) {
        if let Some(tail) = self.0.get_mut(len..) {
            tail.zeroize();
        }
        self.0.truncate(len);
    }
}
impl Deref for SecretBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl DerefMut for SecretBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for SecretBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl Drop for SecretBuffer {
    fn drop(&mut self) {
        if !cfg!(feature = "mutant-si30-buffer-no-wipe") {
            self.0.as_mut_slice().zeroize();
        }
        #[cfg(test)]
        AUDIT.with(|audit| {
            audit
                .borrow_mut()
                .push((self.0.len(), self.0.iter().all(|b| *b == 0)))
        });
        if !cfg!(feature = "mutant-si30-buffer-no-wipe") {
            self.0.zeroize();
        }
    }
}

#[cfg(test)]
thread_local! { static AUDIT: std::cell::RefCell<Vec<(usize, bool)>> = const { std::cell::RefCell::new(Vec::new()) }; }

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn si_30_transport_buffers_wipe_on_success_error_and_cancel() {
        AUDIT.with(|audit| audit.borrow_mut().clear());
        let make = || SecretBuffer::copy_from(b"capability-canary");
        {
            let buffer = make();
            assert_eq!(&*buffer, b"capability-canary");
        }
        let failure = || -> Result<(), ()> {
            let _buffer = make();
            Err(())
        };
        assert!(failure().is_err());
        let pending = async {
            let _buffer = make();
            std::future::pending::<()>().await;
        };
        {
            let mut pending = pin!(pending);
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(pending.as_mut().poll(&mut context), Poll::Pending);
        }
        AUDIT.with(|audit| {
            let audit = audit.borrow();
            assert_eq!(
                audit.len(),
                3,
                "each completed, failed or cancelled owner releases its buffer"
            );
            assert!(
                audit.iter().all(|(len, wiped)| *len == 17 && *wiped),
                "inspect live allocations after wipe, before release"
            );
        });
    }
}
