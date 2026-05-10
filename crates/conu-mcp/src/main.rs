use std::io::{self, BufRead, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let server = conu_mcp::McpServer::default();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        match line {
            Ok(line) => {
                if let Some(response) = server.handle_line(&line) {
                    if writeln!(stdout, "{response}").is_err() || stdout.flush().is_err() {
                        eprintln!("conu-mcp failed to write MCP response");
                        return ExitCode::from(1);
                    }
                }
            }
            Err(error) => {
                eprintln!("conu-mcp failed to read MCP input: {error}");
                return ExitCode::from(1);
            }
        }
    }

    ExitCode::SUCCESS
}
