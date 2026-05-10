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
    let processed = client.process_queued()?;
    let inbox = client.inbox_metadata("agent.example.bob")?;
    let received = client.receive_message_bytes("agent.example.bob", &inbox[0].envelope_id)?;

    println!("queued request {}", sent.request_id);
    println!("delivered envelopes {}", processed.messages.delivered);
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
