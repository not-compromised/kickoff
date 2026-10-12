//! Secrets that cannot leave the process through formatting or serialization,
//! and the diagnostics schema that replaces free-form logs (design §6.4, SI-30).

pub mod diag;

use zeroize::Zeroize;

/// Holds a key, ticket, exchange code or relay voucher.
///
/// Deliberately implements none of `Debug`, `Display`, `Serialize`, `Clone` or
/// `PartialEq`, so the value cannot reach a log line, an error string, a
/// diagnostics export, a second owner or a short-circuiting comparison by
/// accident. `si_30_secret_has_no_debug_display_serialize` fails if any is
/// added. A type that wants to carry a secret on a channel writes its own
/// encoder around `expose`; nothing derives one.
///
/// The value lives in one heap allocation for its whole life, so moving the
/// `Secret` moves a pointer and leaves no stale copy behind; drop wipes it.
pub struct Secret<T> {
    value: Box<T>,
    // Captured from `T: Wipe` at construction. Keeping the bound off the struct
    // lets signatures name `Secret<T>` for any `T`; only creating one needs it.
    wipe: fn(&mut T),
}

impl<T> Secret<T> {
    pub fn new(value: T) -> Self
    where
        T: Wipe,
    {
        Self {
            value: Box::new(value),
            wipe: T::wipe,
        }
    }

    /// The only way to read the value. A closure keeps the borrow scoped to the
    /// single consumer that needs it.
    pub fn expose<R>(&self, use_it: impl FnOnce(&T) -> R) -> R {
        use_it(&self.value)
    }
}

impl<T: AsRef<[u8]>> Secret<T> {
    /// Equality whose running time does not depend on where the bytes differ.
    /// Lengths are not secret: different lengths compare unequal at once.
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let mine: &[u8] = (*self.value).as_ref();
        bool::from(mine.ct_eq(other))
    }
}

impl<T> Drop for Secret<T> {
    fn drop(&mut self) {
        if !cfg!(feature = "mutant-si30-no-wipe") {
            (self.wipe)(&mut self.value);
        }
    }
}

#[cfg(feature = "mutant-si30-secret-debug")]
impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Overwrites a secret's bytes in place. `Secret::new` requires it, so every
/// secret type states how it is wiped.
///
/// An implementation must leave no secret byte reachable from the value once
/// `wipe` returns, or, for a type that wipes itself, once it is dropped right
/// after (the `SecretKey` impl relies on that).
pub trait Wipe {
    fn wipe(&mut self);
}

impl Wipe for String {
    fn wipe(&mut self) {
        // Covers spare capacity as well as the live bytes.
        self.zeroize();
    }
}

impl Wipe for Vec<u8> {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl Wipe for Box<[u8]> {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> Wipe for [u8; N] {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl Wipe for iroh_base::SecretKey {
    fn wipe(&mut self) {
        // The key zeroizes itself when the box drops it, right after this
        // call. Compile-time proof, so an iroh bump that drops it fails here:
        fn wipes_on_drop<K: zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<iroh_base::SecretKey>();
    }
}
