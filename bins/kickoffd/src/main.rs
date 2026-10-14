//! Linux IPC startup. Session and game adapters are not wired in M2 yet.

#![allow(clippy::print_stderr)]

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    let result = linux_main();
    #[cfg(not(target_os = "linux"))]
    let result: Result<(), kickoff_ipc::IpcError> = Err(kickoff_ipc::IpcError::Unsupported);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kickoffd: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_main() -> Result<(), kickoff_ipc::IpcError> {
    kickoff_ipc::run_core_probe_if_requested()?;
    kickoff_ipc::close_inherited_descriptors()?;
    use kickoff_ipc::{Facade, IpcError, Refusal, Reply, RuntimeDir, Trust, Worker, WorkerLaunch};
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let worker = match args.as_slice() {
        [] => false,
        [arg] if arg == "--ipc-worker" => true,
        _ => return Err(IpcError::Malformed),
    };
    if worker {
        kickoff_secret::harden_process().map_err(|_| IpcError::PeerRejected)?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        if worker {
            let mut worker = Worker::inherit(Trust::kickoffd()?, Trust::clients()?).await?;
            loop {
                let mut channel = worker.accept().await?;
                tokio::spawn(async move {
                    while channel.recv().await.is_ok() {
                        // IPC works before final adapters exist. Refuse
                        // commands rather than claim their work completed.
                        if channel
                            .reply(Reply::Refused(Refusal::Failed))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        } else {
            let dir = RuntimeDir::open()?;
            let mut worker = WorkerLaunch::new(std::env::current_exe()?);
            worker.arg("--ipc-worker");
            Facade::spawn(&dir, Trust::clients()?, worker)
                .await?
                .run()
                .await
        }
    })
}
