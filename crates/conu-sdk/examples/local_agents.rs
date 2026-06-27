use std::env;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use conu_sdk::ConuClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ConuClient::with_home(example_home());

    client.init()?;
    client.register_agent(
        "agent.example.alice",
        "Alice Example Agent",
        "example-agent",
    )?;
    client.register_agent("agent.example.bob", "Bob Example Agent", "example-agent")?;
    client.process_queued()?;

    let sent = client.send_message_text(
        "agent.example.alice",
        "agent.example.bob",
        "example private payload",
    )?;
    let waited = client.wait_for_message(
        "agent.example.bob",
        None,
        std::time::Duration::from_secs(30),
        std::time::Duration::from_millis(250),
        true,
    )?;
    let envelope_id = waited
        .message
        .as_ref()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for agent.example.bob",
            )
        })?
        .envelope_id
        .clone();
    let received = client.receive_message_bytes("agent.example.bob", &envelope_id)?;

    println!("queued request {}", sent.request_id);
    println!("wait status {:?}", waited.status);
    println!("bob received {} opaque bytes", received.len());
    println!("payload contents were not displayed by conU");

    Ok(())
}

fn example_home() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    env::temp_dir().join(format!("conu-sdk-example-{}-{nonce}", process::id()))
}
