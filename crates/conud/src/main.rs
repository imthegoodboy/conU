use std::env;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--check") => {
            print_check();
            ExitCode::SUCCESS
        }
        Some("--serve") | None => serve_runtime(),
        Some("--once") => run_once(),
        Some("--process-ipc") => process_ipc_once(),
        Some("--status") => print_status(),
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("conud {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("unknown option: {unknown}");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn serve_runtime() -> ExitCode {
    match conu_core::runtime::acquire_runtime(None) {
        Ok(lease) => {
            let status = lease.status();
            println!(
                "conUD runtime live; pid {}; health {}; payloads not observed",
                status
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                status.local_endpoint
            );

            match lease.serve_until_stop(Duration::from_secs(1)) {
                Ok(()) => match lease.stop() {
                    Ok(_) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("conUD shutdown failed: {error}");
                        ExitCode::from(1)
                    }
                },
                Err(error) => {
                    eprintln!("conUD runtime failed: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Err(conu_core::runtime::RuntimeError::AlreadyRunning(status)) => {
            println!(
                "conUD already running; pid {}; payloads not observed",
                status
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("conUD start failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_once() -> ExitCode {
    match conu_core::runtime::acquire_runtime(None) {
        Ok(lease) => match lease.heartbeat().and_then(|_| {
            conu_core::agents::process_gateway_requests(None)
                .map_err(conu_core::runtime::RuntimeError::from)?;
            conu_core::messages::process_message_requests(None)
                .map_err(conu_core::runtime::RuntimeError::from)?;
            conu_core::sessions::sync_remote_sessions(None)
                .map_err(conu_core::runtime::RuntimeError::from)?;
            lease.stop()
        }) {
            Ok(status) => {
                println!(
                    "conUD one-shot completed; state {}; payloads not observed",
                    status.state.as_str()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("conUD one-shot failed: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            eprintln!("conUD one-shot failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn process_ipc_once() -> ExitCode {
    match (
        conu_core::agents::process_gateway_requests(None),
        conu_core::messages::process_message_requests(None),
        conu_core::sessions::sync_remote_sessions(None),
    ) {
        (Ok(agent_report), Ok(message_report), Ok(session_report)) => {
            println!(
                "conUD IPC agents processed {}; agents rejected {}; messages delivered {}; messages rejected {}; sessions synced {}; remote agents {}; payloads not observed",
                agent_report.processed,
                agent_report.rejected,
                message_report.delivered,
                message_report.rejected,
                session_report.sessions_synced,
                session_report.remote_agents_synced
            );
            ExitCode::SUCCESS
        }
        (Err(error), _, _) => {
            eprintln!("conUD IPC processing failed: {error}");
            ExitCode::from(1)
        }
        (_, Err(error), _) => {
            eprintln!("conUD IPC processing failed: {error}");
            ExitCode::from(1)
        }
        (_, _, Err(error)) => {
            eprintln!("conUD IPC processing failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_status() -> ExitCode {
    match conu_core::runtime::read_runtime(None) {
        Ok(status) => {
            println!(
                "conUD status: {}; pid {}; health {}; payloads not observed",
                status.state.as_str(),
                status
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                status.local_endpoint
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("conUD status failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_check() {
    println!("{}", conu_core::scaffold_status("conud"));
    println!("runtime: phase 15 packaging-ready daemon; payloads not observed");
}

fn print_help() {
    println!(
        r"conud - conU local runtime daemon

Usage:
  conud
  conud --serve
  conud --once
  conud --process-ipc
  conud --check
  conud --status
  conud --help
  conud --version"
    );
}
