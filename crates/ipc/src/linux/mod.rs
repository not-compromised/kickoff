//! kickoffd's Unix socket (design §2.7, SI-7): a private directory, an
//! exclusively created socket, and kernel credentials checked on both ends
//! before a single byte is exchanged.

mod client;
mod dir;
mod facade;
mod server;
mod stream;
mod trust;

pub use client::{Client, connect};
pub use dir::RuntimeDir;
pub use facade::{Facade, Worker, run_core_probe_if_requested};
pub use server::{Channel, Server};
pub(crate) use stream::AncillaryRefused;
pub use trust::Trust;

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}
