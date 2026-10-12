use std::fmt::{Debug, Display};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kickoff_secret::{Secret, Wipe};

// Inherent methods win over trait methods only when their bounds hold, so
// `probe` answers "does T implement the trait" at compile time, without a
// compile-fail harness.
macro_rules! implements {
    ($ty:ty: $($bound:tt)+) => {{
        struct Probe<T: ?Sized>(std::marker::PhantomData<T>);
        #[allow(dead_code)]
        trait Fallback {
            fn probe(&self) -> bool {
                false
            }
        }
        impl<T: ?Sized> Fallback for Probe<T> {}
        #[allow(dead_code)]
        impl<T: ?Sized + $($bound)+> Probe<T> {
            fn probe(&self) -> bool {
                true
            }
        }
        Probe::<$ty>(std::marker::PhantomData).probe()
    }};
}

#[test]
fn si_30_secret_has_no_debug_display_serialize() {
    // The wrapped type must have every trait itself, so a conditional impl such
    // as `impl<T: Debug> Debug for Secret<T>` is caught too; and the probe must
    // see them, or a false result below would prove nothing.
    assert!(implements!(u32: Debug));
    assert!(implements!(u32: Display));
    assert!(implements!(u32: serde::Serialize));
    assert!(implements!(u32: Clone));
    assert!(implements!(u32: PartialEq));

    assert!(
        !implements!(Secret<u32>: Debug),
        "Secret must not implement Debug"
    );
    assert!(
        !implements!(Secret<u32>: Display),
        "Secret must not implement Display"
    );
    assert!(
        !implements!(Secret<u32>: serde::Serialize),
        "Secret must not implement Serialize"
    );
    assert!(
        !implements!(Secret<u32>: Clone),
        "Secret must not implement Clone"
    );
    // `==` on bytes short-circuits at the first difference; `ct_eq` is the
    // only comparison.
    assert!(
        !implements!(Secret<u32>: PartialEq),
        "Secret must not implement PartialEq"
    );
}

struct Tracked {
    bytes: [u8; 8],
    wiped: Arc<AtomicBool>,
}

impl Wipe for Tracked {
    fn wipe(&mut self) {
        self.bytes = [0; 8];
        self.wiped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn si_30_secret_wiped_on_drop() {
    let wiped = Arc::new(AtomicBool::new(false));
    let secret = Secret::new(Tracked {
        bytes: *b"canary-1",
        wiped: wiped.clone(),
    });
    assert_eq!(secret.expose(|t| t.bytes), *b"canary-1");
    // A move must not wipe early or skip the wipe.
    let moved = secret;
    assert!(!wiped.load(Ordering::SeqCst));
    drop(moved);
    assert!(wiped.load(Ordering::SeqCst), "drop must wipe the secret");
}

#[test]
fn wipe_clears_string_and_bytes() {
    let mut s = String::from("canary-7f3a");
    s.wipe();
    assert!(s.is_empty());
    let mut v = b"canary-7f3a".to_vec();
    v.wipe();
    assert!(v.iter().all(|b| *b == 0));
    let mut a = *b"canary";
    a.wipe();
    assert_eq!(a, [0; 6]);
}

#[test]
fn ct_eq_compares_bytes() {
    let s = Secret::new(b"canary-7f3a".to_vec());
    assert!(s.ct_eq(b"canary-7f3a"));
    assert!(!s.ct_eq(b"canary-7f3b"));
    assert!(!s.ct_eq(b"Canary-7f3a"));
    assert!(!s.ct_eq(b"canary-7f3"));
    assert!(!s.ct_eq(b""));
    let t = Secret::new(String::from("ticket"));
    assert!(t.ct_eq(b"ticket"));
}

#[test]
fn exposes_value_only_through_closure() {
    let s = Secret::new(String::from("canary-7f3a"));
    assert_eq!(s.expose(|v| v.len()), 11);
}
