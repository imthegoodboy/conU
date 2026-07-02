//! CLI rendering and command dispatch for conU.
//!
//! The CLI is conU's human control room: it exposes local runtime status,
//! agent metadata, trust/session/route state, streams, security audit output,
//! and release readiness checks without displaying private payload contents.

use std::collections::HashSet;
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use conu_core::agents::{
    self, AgentPresence, AgentRegistration, LocalAgentRecord, PresenceHeartbeat, SignedAgentCard,
};
use conu_core::direct_transport;
use conu_core::messages::{self, DeliveryReceipt, InboxEntry, LocalMessage};
use conu_core::observability::{self, LogRotationPolicy, LogRotationReport};
use conu_core::policy::{self, PeerPolicyRecord, PeerPolicyUpdate};
use conu_core::relay_delivery::{self, RemoteMessage};
use conu_core::rooms::{self, RoomEvent, RoomRecord, RoomTopicPolicyRecord, RoomTopicPolicyUpdate};
use conu_core::routes::{self, RouteProbe, RouteRecord, RouteSyncReport, RouteTransport};
use conu_core::runtime::{self, RuntimeState, RuntimeStatus, StopReport};
use conu_core::security::{
    self, IdentityKeyRetirementReport, IdentityKeyRotationReport, SecurityAudit, SecurityReport,
    StorageKeyRetirementReport, StorageKeyRotationReport,
};
use conu_core::sessions::{self, RemoteAgentRecord, RemoteSession, SessionSyncReport};
use conu_core::state::{self, InitReport, StateSnapshot};
use conu_core::streams::{self, StreamEvent, StreamRecord};
use conu_core::trust::{self, PeerCard, TrustStatus, TrustedPeer};
use conu_protocol::{AgentCapabilities, OpaquePayload};
use native_tls::{HandshakeError, TlsConnector};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

const MAX_CLI_PAYLOAD_FILE_BYTES: u64 = 64 * 1024;

/// A rendered CLI command result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CliOutput {
    fn success(stdout: impl Into<String>) -> Self {
        Self {
            code: 0,
            stdout: finish(stdout.into()),
            stderr: String::new(),
        }
    }

    fn failure(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            code,
            stdout: String::new(),
            stderr: finish(stderr.into()),
        }
    }
}

fn unknown_command_error() -> CliOutput {
    CliOutput::failure(
        2,
        format!(
            "unknown command; contentsDisplayed=false\n\n{}",
            render_help()
        ),
    )
}

fn unknown_option_error() -> CliOutput {
    CliOutput::failure(2, "unknown option; contentsDisplayed=false")
}

fn unexpected_argument_error() -> CliOutput {
    CliOutput::failure(2, "unexpected argument; contentsDisplayed=false")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuAction {
    Command(&'static [&'static str]),
    ConnectSelector,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MenuItem {
    title: &'static str,
    command: &'static str,
    detail: &'static str,
    action: MenuAction,
}

const MENU_ITEMS: &[MenuItem] = &[
    MenuItem {
        title: "Dashboard",
        command: "conu dashboard",
        detail: "runtime, agents, routes",
        action: MenuAction::Command(&["dashboard"]),
    },
    MenuItem {
        title: "Setup",
        command: "conu setup --start",
        detail: "prepare agents and runtime",
        action: MenuAction::Command(&["setup", "--start"]),
    },
    MenuItem {
        title: "Doctor",
        command: "conu doctor",
        detail: "install and readiness check",
        action: MenuAction::Command(&["doctor"]),
    },
    MenuItem {
        title: "Connect",
        command: "conu connect",
        detail: "agent selector",
        action: MenuAction::ConnectSelector,
    },
    MenuItem {
        title: "Inbox",
        command: "conu inbox",
        detail: "message overview",
        action: MenuAction::Command(&["inbox"]),
    },
    MenuItem {
        title: "Agents",
        command: "conu agents",
        detail: "local and remote agent list",
        action: MenuAction::Command(&["agents"]),
    },
    MenuItem {
        title: "Status",
        command: "conu status",
        detail: "runtime health",
        action: MenuAction::Command(&["status"]),
    },
    MenuItem {
        title: "Smoke",
        command: "conu smoke",
        detail: "local delivery check",
        action: MenuAction::Command(&["smoke"]),
    },
    MenuItem {
        title: "Start",
        command: "conu start",
        detail: "launch conUD runtime",
        action: MenuAction::Command(&["start"]),
    },
    MenuItem {
        title: "Watch",
        command: "conu watch",
        detail: "private transport activity",
        action: MenuAction::Command(&["watch"]),
    },
    MenuItem {
        title: "Pair",
        command: "conu pair",
        detail: "create a trusted peer invite",
        action: MenuAction::Command(&["pair"]),
    },
    MenuItem {
        title: "Help",
        command: "conu --help",
        detail: "quick guide",
        action: MenuAction::Command(&["--help"]),
    },
    MenuItem {
        title: "Exit",
        command: "close menu",
        detail: "return to terminal",
        action: MenuAction::Exit,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectMenuAction {
    Command(Vec<String>),
    Describe(String),
    PromptLocalChat {
        from_agent_id: String,
        to_agent_id: String,
    },
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectMenuItem {
    title: String,
    command: String,
    detail: String,
    action: ConnectMenuAction,
}

const CONNECT_MENU_MAX_LOCAL_STREAMS: usize = 8;
const CONNECT_MENU_MAX_LOCAL_CHAT_HINTS: usize = 4;
const CONNECT_MENU_MAX_ROOM_JOINS: usize = 8;
const CONNECT_MENU_MAX_REMOTE_HINTS: usize = 4;
const TERMINAL_CHAT_MAX_BYTES: usize = 64 * 1024;

struct TerminalMenuStatus {
    node: String,
    state: String,
    runtime_state: String,
    local_agents: usize,
    remote_agents: usize,
}

struct LocalSmokeReport {
    registered_agents: usize,
    delivered_messages: usize,
    inbox_entries: usize,
    receipts: usize,
    payload_bytes: usize,
    request_id: String,
    envelope_id: String,
}

struct LocalSetupReport {
    state_path: PathBuf,
    node_id: String,
    node_created: bool,
    from_agent_id: String,
    to_agent_id: String,
    from_agent_kind: String,
    to_agent_kind: String,
    registered_agents: usize,
    local_agents: usize,
    stream_id: String,
    stream_created: bool,
    room_id: String,
    room_created: bool,
    room_participants: usize,
    to_agent_joined_room: bool,
    inbox_entries: usize,
    receipts: usize,
    payload_bytes: usize,
    request_id: String,
    envelope_id: String,
    runtime: Option<StartRuntimeReport>,
}

struct LocalSetupOptions {
    from_agent_id: String,
    to_agent_id: String,
    from_display_name: String,
    to_display_name: String,
    from_agent_kind: String,
    to_agent_kind: String,
    from_display_name_explicit: bool,
    to_display_name_explicit: bool,
    from_agent_kind_explicit: bool,
    to_agent_kind_explicit: bool,
    room_id: String,
    room_display_name: String,
    room_display_name_explicit: bool,
    start_runtime: bool,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartRuntimeReport {
    status: RuntimeStatus,
    launched: bool,
}

struct SmokeHome {
    path: PathBuf,
}

struct TerminalMenuGuard;

impl Drop for TerminalMenuGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = crossterm::execute!(
            stdout,
            crossterm::cursor::Show,
            crossterm::terminal::LeaveAlternateScreen
        );
    }
}

/// Run the human terminal menu. Callers should gate this to real TTY sessions.
pub fn run_terminal_menu() -> io::Result<CliOutput> {
    crossterm::terminal::enable_raw_mode()?;
    let _guard = TerminalMenuGuard;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::cursor::Hide
    )?;

    let mut selected = 0usize;
    loop {
        draw_terminal_menu(&mut stdout, selected)?;
        if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
            match key {
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Up,
                    ..
                } => {
                    selected = if selected == 0 {
                        MENU_ITEMS.len() - 1
                    } else {
                        selected - 1
                    };
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Down,
                    ..
                } => {
                    selected = (selected + 1) % MENU_ITEMS.len();
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Enter,
                    ..
                } => {
                    let item = MENU_ITEMS[selected];
                    if item.action == MenuAction::ConnectSelector {
                        return run_connect_terminal_selector_loop(&mut stdout);
                    }
                    return Ok(run_menu_item(item));
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Esc,
                    ..
                }
                | crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Char('q'),
                    ..
                }
                | crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Char('Q'),
                    ..
                }
                | crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Char('c'),
                    modifiers: crossterm::event::KeyModifiers::CONTROL,
                    ..
                } => {
                    return Ok(CliOutput::success(
                        "conU menu closed\ncontentsDisplayed=false",
                    ));
                }
                _ => {}
            }
        }
    }
}

/// Run the human connect selector. Non-TTY callers should keep using
/// `conu connect`, which renders a static metadata-only selector.
pub fn run_connect_terminal_selector() -> io::Result<CliOutput> {
    crossterm::terminal::enable_raw_mode()?;
    let _guard = TerminalMenuGuard;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::cursor::Hide
    )?;

    run_connect_terminal_selector_loop(&mut stdout)
}

fn run_connect_terminal_selector_loop(mut stdout: &mut impl Write) -> io::Result<CliOutput> {
    let mut selected = 0usize;
    loop {
        let item_count = connect_menu_items(None).len();
        if item_count > 0 && selected >= item_count {
            selected = item_count - 1;
        }
        draw_connect_terminal_selector(&mut stdout, selected)?;
        if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
            match key {
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Up,
                    ..
                } => {
                    selected = if selected == 0 {
                        item_count.saturating_sub(1)
                    } else {
                        selected - 1
                    };
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Down,
                    ..
                } => {
                    selected = if item_count == 0 {
                        0
                    } else {
                        (selected + 1) % item_count
                    };
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Enter,
                    ..
                } => {
                    let items = connect_menu_items(None);
                    if let Some(item) = items.get(selected).cloned() {
                        return Ok(run_connect_menu_item(item));
                    }
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Esc,
                    ..
                }
                | crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Char('q'),
                    ..
                }
                | crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Char('Q'),
                    ..
                }
                | crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Char('c'),
                    modifiers: crossterm::event::KeyModifiers::CONTROL,
                    ..
                } => {
                    return Ok(CliOutput::success(
                        "conU connect selector closed\ncontentsDisplayed=false",
                    ));
                }
                _ => {}
            }
        }
    }
}

fn draw_terminal_menu(stdout: &mut impl Write, selected: usize) -> io::Result<()> {
    let status = terminal_menu_status(None);
    let selected = selected.min(MENU_ITEMS.len().saturating_sub(1));

    crossterm::queue!(
        stdout,
        crossterm::cursor::MoveTo(0, 0),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::style::SetForegroundColor(crossterm::style::Color::Cyan),
        crossterm::style::SetAttribute(crossterm::style::Attribute::Bold),
        crossterm::style::Print("conU\n"),
        crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
        crossterm::style::SetForegroundColor(crossterm::style::Color::Magenta),
        crossterm::style::Print("agent command bridge\n\n"),
        crossterm::style::ResetColor
    )?;

    queue_menu_status_line(
        stdout,
        "runtime",
        &status.runtime_state,
        runtime_menu_color(&status.runtime_state),
    )?;
    queue_menu_status_line(
        stdout,
        "node",
        &status.node,
        crossterm::style::Color::DarkGrey,
    )?;
    queue_menu_status_line(
        stdout,
        "state",
        &status.state,
        crossterm::style::Color::Blue,
    )?;
    queue_menu_status_line(
        stdout,
        "local agents",
        &status.local_agents.to_string(),
        crossterm::style::Color::Green,
    )?;
    queue_menu_status_line(
        stdout,
        "remote agents",
        &status.remote_agents.to_string(),
        crossterm::style::Color::Yellow,
    )?;

    crossterm::queue!(
        stdout,
        crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
        crossterm::style::Print("\nUse Up/Down to choose, Enter to run, q or Esc to close.\n\n"),
        crossterm::style::ResetColor
    )?;

    for (index, item) in MENU_ITEMS.iter().enumerate() {
        if index == selected {
            crossterm::queue!(
                stdout,
                crossterm::style::SetBackgroundColor(crossterm::style::Color::DarkCyan),
                crossterm::style::SetForegroundColor(crossterm::style::Color::White),
                crossterm::style::SetAttribute(crossterm::style::Attribute::Bold),
                crossterm::style::Print(format!("> {:<10} ", item.title)),
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
                crossterm::style::SetBackgroundColor(crossterm::style::Color::DarkCyan),
                crossterm::style::SetForegroundColor(crossterm::style::Color::Cyan),
                crossterm::style::Print(format!("{:<18} ", item.command)),
                crossterm::style::SetForegroundColor(crossterm::style::Color::White),
                crossterm::style::Print(item.detail),
                crossterm::style::ResetColor,
                crossterm::style::Print("\n")
            )?;
        } else {
            crossterm::queue!(
                stdout,
                crossterm::style::SetForegroundColor(crossterm::style::Color::White),
                crossterm::style::Print(format!("  {:<10} ", item.title)),
                crossterm::style::SetForegroundColor(crossterm::style::Color::Blue),
                crossterm::style::Print(format!("{:<18} ", item.command)),
                crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
                crossterm::style::Print(item.detail),
                crossterm::style::ResetColor,
                crossterm::style::Print("\n")
            )?;
        }
    }

    crossterm::queue!(
        stdout,
        crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
        crossterm::style::Print(
            "\nprivacy\n  payload view  private, never displayed\n  contentsDisplayed=false"
        ),
        crossterm::style::ResetColor
    )?;
    stdout.flush()
}

fn draw_connect_terminal_selector(stdout: &mut impl Write, selected: usize) -> io::Result<()> {
    let status = terminal_menu_status(None);
    let route_records = routes::list_routes(None).unwrap_or_default();
    let room_count = rooms::list_rooms(None).unwrap_or_default().len();
    let items = connect_menu_items(None);
    let selected = selected.min(items.len().saturating_sub(1));

    crossterm::queue!(
        stdout,
        crossterm::cursor::MoveTo(0, 0),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::style::SetForegroundColor(crossterm::style::Color::Cyan),
        crossterm::style::SetAttribute(crossterm::style::Attribute::Bold),
        crossterm::style::Print("conU connect\n"),
        crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
        crossterm::style::SetForegroundColor(crossterm::style::Color::Magenta),
        crossterm::style::Print("agent connection selector\n\n"),
        crossterm::style::ResetColor
    )?;

    queue_menu_status_line(
        stdout,
        "runtime",
        &status.runtime_state,
        runtime_menu_color(&status.runtime_state),
    )?;
    queue_menu_status_line(
        stdout,
        "local agents",
        &status.local_agents.to_string(),
        crossterm::style::Color::Green,
    )?;
    queue_menu_status_line(
        stdout,
        "remote agents",
        &status.remote_agents.to_string(),
        crossterm::style::Color::Yellow,
    )?;
    queue_menu_status_line(
        stdout,
        "rooms",
        &room_count.to_string(),
        crossterm::style::Color::Blue,
    )?;
    queue_menu_status_line(
        stdout,
        "routes",
        &format!(
            "direct {} | relay {}",
            selected_direct_route_count(&route_records),
            selected_relay_route_count(&route_records)
        ),
        crossterm::style::Color::DarkGrey,
    )?;

    crossterm::queue!(
        stdout,
        crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
        crossterm::style::Print("\nUse Up/Down to choose, Enter to run, q or Esc to close.\n\n"),
        crossterm::style::ResetColor
    )?;

    for (index, item) in items.iter().enumerate() {
        let command = abbreviate_for_terminal(&item.command, 44);
        let detail = abbreviate_for_terminal(&item.detail, 36);
        if index == selected {
            crossterm::queue!(
                stdout,
                crossterm::style::SetBackgroundColor(crossterm::style::Color::DarkCyan),
                crossterm::style::SetForegroundColor(crossterm::style::Color::White),
                crossterm::style::SetAttribute(crossterm::style::Attribute::Bold),
                crossterm::style::Print(format!("> {:<15} ", item.title)),
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
                crossterm::style::SetBackgroundColor(crossterm::style::Color::DarkCyan),
                crossterm::style::SetForegroundColor(crossterm::style::Color::Cyan),
                crossterm::style::Print(format!("{command:<44} ")),
                crossterm::style::SetForegroundColor(crossterm::style::Color::White),
                crossterm::style::Print(detail),
                crossterm::style::ResetColor,
                crossterm::style::Print("\n")
            )?;
        } else {
            crossterm::queue!(
                stdout,
                crossterm::style::SetForegroundColor(crossterm::style::Color::White),
                crossterm::style::Print(format!("  {:<15} ", item.title)),
                crossterm::style::SetForegroundColor(crossterm::style::Color::Blue),
                crossterm::style::Print(format!("{command:<44} ")),
                crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
                crossterm::style::Print(detail),
                crossterm::style::ResetColor,
                crossterm::style::Print("\n")
            )?;
        }
    }

    crossterm::queue!(
        stdout,
        crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
        crossterm::style::Print(
            "\nprivacy\n  selector shows metadata and commands only\n  payload view  private, never displayed\n  contentsDisplayed=false"
        ),
        crossterm::style::ResetColor
    )?;
    stdout.flush()
}

fn queue_menu_status_line(
    stdout: &mut impl Write,
    label: &str,
    value: &str,
    color: crossterm::style::Color,
) -> io::Result<()> {
    crossterm::queue!(
        stdout,
        crossterm::style::SetForegroundColor(crossterm::style::Color::DarkGrey),
        crossterm::style::Print(format!("{label:<14} ")),
        crossterm::style::SetForegroundColor(color),
        crossterm::style::Print(value),
        crossterm::style::ResetColor,
        crossterm::style::Print("\n")
    )
}

fn runtime_menu_color(runtime_state: &str) -> crossterm::style::Color {
    match runtime_state {
        "live" | "running" => crossterm::style::Color::Green,
        "offline" => crossterm::style::Color::Yellow,
        "unavailable" => crossterm::style::Color::Red,
        _ => crossterm::style::Color::White,
    }
}

fn run_menu_item(item: MenuItem) -> CliOutput {
    match item.action {
        MenuAction::Command(args) => run(args.iter().copied()),
        MenuAction::ConnectSelector => run(["connect"]),
        MenuAction::Exit => CliOutput::success("conU menu closed\ncontentsDisplayed=false"),
    }
}

fn run_connect_menu_item(item: ConnectMenuItem) -> CliOutput {
    match item.action {
        ConnectMenuAction::Command(args) => run(args),
        ConnectMenuAction::Describe(output) => CliOutput::success(output),
        ConnectMenuAction::PromptLocalChat {
            from_agent_id,
            to_agent_id,
        } => run_terminal_local_chat(&from_agent_id, &to_agent_id),
        ConnectMenuAction::Exit => {
            CliOutput::success("conU connect selector closed\ncontentsDisplayed=false")
        }
    }
}

fn run_terminal_local_chat(from_agent_id: &str, to_agent_id: &str) -> CliOutput {
    let _ = crossterm::terminal::disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = crossterm::execute!(
        stdout,
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    );

    println!("conU chat");
    println!("from: {from_agent_id}");
    println!("to: {to_agent_id}");
    println!("payload view: private, never displayed by conU");
    println!();

    let payload = match prompt_terminal_chat_payload("message: ") {
        Ok(payload) => payload,
        Err(error) => {
            return CliOutput::failure(1, format!("conU chat failed\n\n{error}"));
        }
    };

    render_chat(
        &[
            from_agent_id.to_string(),
            to_agent_id.to_string(),
            "--stdin".to_string(),
        ],
        None,
        payload,
    )
}

fn prompt_terminal_chat_payload(prompt: &str) -> Result<Vec<u8>, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|error| error.to_string())?;
    terminal_chat_payload_from_line(&value)
}

fn terminal_chat_payload_from_line(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err("message was empty; contentsDisplayed=false".to_string());
    }
    if value.len() > TERMINAL_CHAT_MAX_BYTES {
        return Err(format!(
            "message exceeds {} bytes; contentsDisplayed=false",
            TERMINAL_CHAT_MAX_BYTES
        ));
    }
    Ok(value.as_bytes().to_vec())
}

fn connect_menu_items(home_override: Option<PathBuf>) -> Vec<ConnectMenuItem> {
    let local_agents = agents::list_local_agents(home_override.clone()).unwrap_or_default();
    let remote_agents = sessions::list_remote_agents(home_override.clone()).unwrap_or_default();
    let rooms = rooms::list_rooms(home_override).unwrap_or_default();
    let mut items = Vec::new();
    let mut seen = HashSet::new();

    let stream_agents = local_agents
        .iter()
        .filter(|agent| agent.capabilities.streams)
        .collect::<Vec<_>>();
    let room_agents = local_agents
        .iter()
        .filter(|agent| agent.capabilities.rooms)
        .collect::<Vec<_>>();
    let message_agents = local_agents
        .iter()
        .filter(|agent| agent.capabilities.messages)
        .collect::<Vec<_>>();

    if stream_agents.len() >= 2 {
        let mut added = 0usize;
        'streams: for from in stream_agents.iter() {
            for to in stream_agents.iter() {
                if from.agent_id == to.agent_id {
                    continue;
                }
                push_connect_menu_item(
                    &mut items,
                    &mut seen,
                    ConnectMenuItem {
                        title: "Local stream".to_string(),
                        command: format!("conu connect local {} {}", from.agent_id, to.agent_id),
                        detail: "open private local stream".to_string(),
                        action: ConnectMenuAction::Command(vec![
                            "connect".to_string(),
                            "local".to_string(),
                            from.agent_id.clone(),
                            to.agent_id.clone(),
                        ]),
                    },
                );
                added += 1;
                if added >= CONNECT_MENU_MAX_LOCAL_STREAMS {
                    break 'streams;
                }
            }
        }
    } else {
        push_connect_menu_item(
            &mut items,
            &mut seen,
            ConnectMenuItem {
                title: "Setup".to_string(),
                command: "conu setup --start".to_string(),
                detail: "prepare agents and runtime".to_string(),
                action: ConnectMenuAction::Command(vec![
                    "setup".to_string(),
                    "--start".to_string(),
                ]),
            },
        );
    }

    if message_agents.len() >= 2 {
        let mut added = 0usize;
        'messages: for from in message_agents.iter() {
            for to in message_agents.iter() {
                if from.agent_id == to.agent_id {
                    continue;
                }
                let command = format!("conu chat {} {}", from.agent_id, to.agent_id);
                push_connect_menu_item(
                    &mut items,
                    &mut seen,
                    ConnectMenuItem {
                        title: "Local chat".to_string(),
                        command: command.clone(),
                        detail: "prompt one message".to_string(),
                        action: ConnectMenuAction::PromptLocalChat {
                            from_agent_id: from.agent_id.clone(),
                            to_agent_id: to.agent_id.clone(),
                        },
                    },
                );
                added += 1;
                if added >= CONNECT_MENU_MAX_LOCAL_CHAT_HINTS {
                    break 'messages;
                }
            }
        }
    }

    if !rooms.is_empty() && !room_agents.is_empty() {
        let mut added = 0usize;
        'rooms: for room in rooms.iter() {
            for agent in room_agents.iter() {
                let already_joined = room
                    .participants
                    .iter()
                    .any(|participant| participant.agent_id == agent.agent_id);
                if already_joined {
                    continue;
                }
                push_connect_menu_item(
                    &mut items,
                    &mut seen,
                    ConnectMenuItem {
                        title: "Room join".to_string(),
                        command: format!("conu connect room {} {}", room.room_id, agent.agent_id),
                        detail: "join agent to room bus".to_string(),
                        action: ConnectMenuAction::Command(vec![
                            "connect".to_string(),
                            "room".to_string(),
                            room.room_id.clone(),
                            agent.agent_id.clone(),
                        ]),
                    },
                );
                added += 1;
                if added >= CONNECT_MENU_MAX_ROOM_JOINS {
                    break 'rooms;
                }
            }
        }
    } else if !room_agents.is_empty() {
        let agent = room_agents[0];
        push_connect_menu_item(
            &mut items,
            &mut seen,
            ConnectMenuItem {
                title: "Create room".to_string(),
                command: format!(
                    "conu rooms create room.dev \"Dev Room\" --agent {}",
                    agent.agent_id
                ),
                detail: "create shared local room".to_string(),
                action: ConnectMenuAction::Command(vec![
                    "rooms".to_string(),
                    "create".to_string(),
                    "room.dev".to_string(),
                    "Dev Room".to_string(),
                    "--agent".to_string(),
                    agent.agent_id.clone(),
                ]),
            },
        );
    }

    if !message_agents.is_empty() && !remote_agents.is_empty() {
        let mut added = 0usize;
        'remote: for local in message_agents.iter() {
            for remote in remote_agents
                .iter()
                .filter(|agent| agent.capabilities.messages)
            {
                let command = format!(
                    "conu send {} {} --peer {} --file ./message.bin --json",
                    local.agent_id, remote.agent_id, remote.peer_node_id
                );
                push_connect_menu_item(
                    &mut items,
                    &mut seen,
                    ConnectMenuItem {
                        title: "Remote send".to_string(),
                        command: command.clone(),
                        detail: "prints file-send command".to_string(),
                        action: ConnectMenuAction::Describe(render_remote_send_hint(
                            local, remote, &command,
                        )),
                    },
                );
                added += 1;
                if added >= CONNECT_MENU_MAX_REMOTE_HINTS {
                    break 'remote;
                }
            }
        }
    } else {
        push_connect_menu_item(
            &mut items,
            &mut seen,
            ConnectMenuItem {
                title: "Pair peer".to_string(),
                command: "conu pair".to_string(),
                detail: "create peer invite".to_string(),
                action: ConnectMenuAction::Command(vec!["pair".to_string()]),
            },
        );
    }

    push_connect_menu_item(
        &mut items,
        &mut seen,
        ConnectMenuItem {
            title: "Start runtime".to_string(),
            command: "conu start".to_string(),
            detail: "launch local daemon".to_string(),
            action: ConnectMenuAction::Command(vec!["start".to_string()]),
        },
    );
    push_connect_menu_item(
        &mut items,
        &mut seen,
        ConnectMenuItem {
            title: "Watch".to_string(),
            command: "conu watch".to_string(),
            detail: "private transport view".to_string(),
            action: ConnectMenuAction::Command(vec!["watch".to_string()]),
        },
    );
    push_connect_menu_item(
        &mut items,
        &mut seen,
        ConnectMenuItem {
            title: "Dashboard".to_string(),
            command: "conu dashboard".to_string(),
            detail: "return to control room".to_string(),
            action: ConnectMenuAction::Command(vec!["dashboard".to_string()]),
        },
    );
    push_connect_menu_item(
        &mut items,
        &mut seen,
        ConnectMenuItem {
            title: "Exit".to_string(),
            command: "close selector".to_string(),
            detail: "return to terminal".to_string(),
            action: ConnectMenuAction::Exit,
        },
    );

    items
}

fn push_connect_menu_item(
    items: &mut Vec<ConnectMenuItem>,
    seen: &mut HashSet<String>,
    item: ConnectMenuItem,
) {
    if seen.insert(item.command.clone()) {
        items.push(item);
    }
}

fn render_remote_send_hint(
    local: &LocalAgentRecord,
    remote: &RemoteAgentRecord,
    command: &str,
) -> String {
    format!(
        r"conU connect remote

ready command
  {command}

from: {}
to: {}
peer: {}

privacy
  payload source  stdin or file
  payload view    contents are not displayed by conU
  contentsDisplayed=false",
        local.agent_id, remote.agent_id, remote.peer_node_id
    )
}

fn abbreviate_for_terminal(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let keep = max_chars.saturating_sub(3);
    let mut abbreviated = value.chars().take(keep).collect::<String>();
    abbreviated.push_str("...");
    abbreviated
}

/// Dispatch a conU CLI invocation.
pub fn run<I, S>(args: I) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    run_with_home_and_stdin(args, None, Vec::new())
}

/// Dispatch a conU CLI invocation with an explicit state home.
///
/// This is mostly used by tests and smoke checks so they do not touch a real
/// user profile.
pub fn run_with_home<I, S>(args: I, home_override: Option<PathBuf>) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    run_with_home_and_stdin(args, home_override, Vec::new())
}

/// Dispatch a conU CLI invocation with explicit stdin bytes.
pub fn run_with_stdin<I, S>(args: I, stdin_payload: Vec<u8>) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    run_with_home_and_stdin(args, None, stdin_payload)
}

/// Dispatch a conU CLI invocation with explicit state and stdin bytes.
pub fn run_with_home_and_stdin<I, S>(
    args: I,
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        return CliOutput::success(render_dashboard(home_override));
    };

    match command {
        "init" => render_init(&args[1..], home_override),
        "menu" => {
            if let Some(error) = reject_args(&args[1..]) {
                error
            } else {
                CliOutput::success(render_terminal_menu(0, home_override))
            }
        }
        "dashboard" => {
            if let Some(error) = reject_args(&args[1..]) {
                error
            } else {
                CliOutput::success(render_dashboard(home_override))
            }
        }
        "status" => render_status(&args[1..], home_override),
        "ready" => render_ready(&args[1..], home_override),
        "agents" => render_agents(&args[1..], home_override),
        "peers" => render_peers(&args[1..], home_override, stdin_payload),
        "send" => render_send(&args[1..], home_override, stdin_payload),
        "inbox" => render_inbox(&args[1..], home_override),
        "history" => render_history(&args[1..], home_override),
        "next" => render_next(&args[1..], home_override),
        "wait" => render_wait(&args[1..], home_override),
        "receive" => render_receive(&args[1..], home_override),
        "pull" => render_pull(&args[1..], home_override),
        "reply" => render_reply(&args[1..], home_override, stdin_payload),
        "chat" => render_chat(&args[1..], home_override, stdin_payload),
        "messages" => render_messages(&args[1..], home_override, stdin_payload),
        "relay" => render_relay(&args[1..], home_override, stdin_payload),
        "streams" => render_streams(&args[1..], home_override, stdin_payload),
        "rooms" => render_rooms(&args[1..], home_override, stdin_payload),
        "sessions" => render_sessions(&args[1..], home_override),
        "routes" => render_routes(&args[1..], home_override),
        "security" => render_security(&args[1..], home_override),
        "identity" => render_identity(&args[1..], home_override),
        "pair" => render_pair(&args[1..], home_override),
        "join" => render_join(&args[1..], home_override),
        "connect" => render_connect(&args[1..], home_override),
        "watch" => render_watch(&args[1..], home_override),
        "setup" => render_setup(&args[1..], home_override),
        "doctor" => render_doctor(&args[1..], home_override),
        "smoke" => render_smoke(&args[1..], home_override),
        "logs" => render_logs(&args[1..], home_override),
        "telemetry" => render_telemetry(&args[1..], home_override),
        "update" => render_update(&args[1..]),
        "components" => render_components(&args[1..]),
        "start" => render_start(&args[1..], home_override),
        "stop" => render_stop(&args[1..], home_override),
        "--help" | "-h" => CliOutput::success(render_help()),
        "help" => render_help_command(&args[1..]),
        "--version" | "-V" => CliOutput::success(format!("conu {}", env!("CARGO_PKG_VERSION"))),
        _unknown => unknown_command_error(),
    }
}

fn render_dashboard(home_override: Option<PathBuf>) -> String {
    let snapshot = state::read_state(home_override.clone()).ok();
    let runtime_status = runtime::read_runtime(home_override.clone()).ok();
    let local_agent_records = agents::list_local_agents(home_override.clone()).unwrap_or_default();
    let trusted_peers = trust::list_peers(home_override.clone())
        .map(|peers| {
            peers
                .iter()
                .filter(|peer| peer.status == TrustStatus::Trusted)
                .count()
        })
        .unwrap_or(0);
    let route_records = routes::list_routes(home_override.clone()).unwrap_or_default();
    let stream_records = streams::list_streams(home_override.clone()).unwrap_or_default();
    let room_records = rooms::list_rooms(home_override.clone()).unwrap_or_default();
    let room_events = rooms::list_room_events(home_override.clone()).unwrap_or_default();
    let relay_queue = relay_delivery::relay_queue_summary(home_override.clone()).ok();
    let remote_agent_records = sessions::list_remote_agents(home_override).unwrap_or_default();
    let local_agents = local_agent_records.len();
    let remote_agents = remote_agent_records.len();
    let open_streams = stream_records
        .iter()
        .filter(|stream| stream.state.as_str() == "open")
        .count();
    let relay_queued = relay_queue.as_ref().map(|queue| queue.queued).unwrap_or(0);
    let node = snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.node.as_ref())
        .map(|node| node.node_id.as_str())
        .unwrap_or("not initialized");
    let state = snapshot
        .as_ref()
        .map(initialization_label)
        .unwrap_or("unavailable");
    let runtime_state = runtime_status
        .as_ref()
        .map(runtime_state_label)
        .unwrap_or("unavailable");
    let local_preview = dashboard_local_agents(&local_agent_records);
    let remote_preview = dashboard_remote_agents(&remote_agent_records);
    let next_actions =
        dashboard_next_actions(&local_agent_records, &remote_agent_records, &room_records);

    format!(
        r"        ____ ___  _   _
  ____ / ___/ _ \| | | |
 / __|| |  | | | | | | |
| (__ | |__| |_| | |_| |
 \___| \____\___/ \___/

agent command bridge
{}

control room
  runtime        {runtime_state}
  node           {node}
  state          {state}
  local agents   {local_agents}
  remote agents  {remote_agents}
  rooms          {}
  open streams   {open_streams}
  relay queued   {relay_queued}
  remote peers   {trusted_peers} trusted
  routes         direct {} relay {}
  payload view   private, never displayed

agent desk
  local          {local_preview}
  remote         {remote_preview}

live road
  [agent] => [conUD] => [rooms | streams | relay] => [agent]
              metadata only, payloads opaque

recent room bus
  events         {}
  latest         {}

next actions
{next_actions}",
        conu_core::PRODUCT_LAW,
        room_records.len(),
        selected_direct_route_count(&route_records),
        selected_relay_route_count(&route_records),
        room_events.len(),
        latest_room_event_label(&room_events)
    )
}

fn dashboard_next_actions(
    local_agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    rooms: &[RoomRecord],
) -> String {
    let mut actions = Vec::new();
    let mut seen = HashSet::new();

    push_dashboard_action(&mut actions, &mut seen, "conu menu".to_string());

    let message_agents = local_agents
        .iter()
        .filter(|agent| agent.capabilities.messages)
        .collect::<Vec<_>>();
    let room_agent = local_agents.iter().find(|agent| agent.capabilities.rooms);

    if message_agents.len() >= 2 {
        let from = message_agents[0];
        let to = message_agents[1];
        push_dashboard_action(&mut actions, &mut seen, "conu chat".to_string());
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!("conu chat {} {}", from.agent_id, to.agent_id),
        );
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!(
                "conu send {} {} --file ./message.bin --json",
                from.agent_id, to.agent_id
            ),
        );
        push_dashboard_action(&mut actions, &mut seen, "conu inbox".to_string());
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!("conu inbox {}", to.agent_id),
        );
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!("conu next {} --json", to.agent_id),
        );
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!("conu history {}", to.agent_id),
        );
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!(
                "conu wait {} --process-ipc --timeout-ms 30000 --json",
                to.agent_id
            ),
        );
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!("conu connect local {} {}", from.agent_id, to.agent_id),
        );
    } else {
        push_dashboard_action(&mut actions, &mut seen, "conu setup --start".to_string());
        push_dashboard_action(&mut actions, &mut seen, "conu connect".to_string());
    }

    if let (Some(room), Some(agent)) = (rooms.first(), room_agent) {
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!(
                "conu rooms publish {} {} <topic> --stdin",
                room.room_id, agent.agent_id
            ),
        );
    } else if let Some(agent) = room_agent {
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!(
                "conu rooms create room.dev \"Dev Room\" --agent {}",
                agent.agent_id
            ),
        );
    }

    if let (Some(local), Some(remote)) = (message_agents.first(), remote_agents.first()) {
        push_dashboard_action(
            &mut actions,
            &mut seen,
            format!(
                "conu send {} {} --peer {} --file ./message.bin --json",
                local.agent_id, remote.agent_id, remote.peer_node_id
            ),
        );
    } else {
        push_dashboard_action(&mut actions, &mut seen, "conu pair".to_string());
    }

    push_dashboard_action(&mut actions, &mut seen, "conu start".to_string());
    push_dashboard_action(&mut actions, &mut seen, "conu doctor".to_string());
    push_dashboard_action(&mut actions, &mut seen, "conu smoke".to_string());
    push_dashboard_action(&mut actions, &mut seen, "conu agents".to_string());
    push_dashboard_action(&mut actions, &mut seen, "conu connect".to_string());
    push_dashboard_action(&mut actions, &mut seen, "conu watch".to_string());
    push_dashboard_action(&mut actions, &mut seen, "conu --help".to_string());

    actions
        .into_iter()
        .map(|action| format!("  {action}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn push_dashboard_action(actions: &mut Vec<String>, seen: &mut HashSet<String>, action: String) {
    if seen.insert(action.clone()) {
        actions.push(action);
    }
}

fn render_terminal_menu(selected: usize, home_override: Option<PathBuf>) -> String {
    let status = terminal_menu_status(home_override);
    let selected = selected.min(MENU_ITEMS.len().saturating_sub(1));

    let mut output = format!(
        r"conU
agent command bridge

runtime        {}
node           {}
state          {}
local agents   {}
remote agents  {}

Use Up/Down to choose, Enter to run, q or Esc to close.

",
        status.runtime_state, status.node, status.state, status.local_agents, status.remote_agents
    );

    for (index, item) in MENU_ITEMS.iter().enumerate() {
        let marker = if index == selected { ">" } else { " " };
        output.push_str(&format!(
            "{marker} {:<10} {:<18} {}\n",
            item.title, item.command, item.detail
        ));
    }

    output.push_str(
        r"
privacy
  payload view  private, never displayed
  contentsDisplayed=false",
    );
    output
}

fn terminal_menu_status(home_override: Option<PathBuf>) -> TerminalMenuStatus {
    let snapshot = state::read_state(home_override.clone()).ok();
    let runtime_status = runtime::read_runtime(home_override.clone()).ok();
    let local_agent_records = agents::list_local_agents(home_override.clone()).unwrap_or_default();
    let remote_agent_records = sessions::list_remote_agents(home_override).unwrap_or_default();
    let node = snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.node.as_ref())
        .map(|node| node.node_id.clone())
        .unwrap_or_else(|| "not initialized".to_string());
    let state = snapshot
        .as_ref()
        .map(initialization_label)
        .unwrap_or("unavailable")
        .to_string();
    let runtime_state = runtime_status
        .as_ref()
        .map(runtime_state_label)
        .unwrap_or("unavailable")
        .to_string();

    TerminalMenuStatus {
        node,
        state,
        runtime_state,
        local_agents: local_agent_records.len(),
        remote_agents: remote_agent_records.len(),
    }
}

fn dashboard_local_agents(agents: &[LocalAgentRecord]) -> String {
    if agents.is_empty() {
        return "none registered".to_string();
    }

    preview_items(
        agents
            .iter()
            .map(|agent| format!("{}:{}", agent.agent_id, agent.presence.as_str()))
            .collect(),
    )
}

fn dashboard_remote_agents(agents: &[RemoteAgentRecord]) -> String {
    if agents.is_empty() {
        return "none visible".to_string();
    }

    preview_items(
        agents
            .iter()
            .map(|agent| format!("{}:{}", agent.agent_id, agent.presence.as_str()))
            .collect(),
    )
}

fn preview_items(items: Vec<String>) -> String {
    let total = items.len();
    let mut preview = items.into_iter().take(3).collect::<Vec<_>>().join(", ");
    if total > 3 {
        preview.push_str(&format!(", +{} more", total - 3));
    }
    preview
}

fn latest_room_event_label(events: &[RoomEvent]) -> String {
    events
        .last()
        .map(|event| {
            format!(
                "{} topic {} from {} bytes {}",
                event.room_id, event.topic, event.from_agent_id, event.payload_bytes
            )
        })
        .unwrap_or_else(|| "idle".to_string())
}

fn render_init(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu init");
    }
    if let Some(error) = reject_args(args) {
        return error;
    }

    match state::init_state(home_override) {
        Ok(report) => match security::ensure_security_state_from_paths(&report.paths) {
            Ok(security) => CliOutput::success(render_init_report(&report, &security)),
            Err(error) => CliOutput::failure(1, format!("conU init failed\n\n{error}")),
        },
        Err(error) => CliOutput::failure(1, format!("conU init failed\n\n{error}")),
    }
}

fn render_status(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu status [--json]");
    }
    let snapshot = match state::read_state(home_override.clone()) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let runtime_status = match runtime::read_runtime(home_override.clone()) {
        Ok(status) => status,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let local_agents = match agents::list_local_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let peers = match trust::list_peers(home_override.clone()) {
        Ok(peers) => peers,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let sessions = match sessions::list_remote_sessions(home_override.clone()) {
        Ok(sessions) => sessions,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let remote_agents = match sessions::list_remote_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let stream_records = match streams::list_streams(home_override.clone()) {
        Ok(streams) => streams,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let room_records = match rooms::list_rooms(home_override.clone()) {
        Ok(rooms) => rooms,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let route_records = match routes::list_routes(home_override.clone()) {
        Ok(routes) => routes,
        Err(error) => return CliOutput::failure(1, format!("conU status failed\n\n{error}")),
    };
    let security_audit =
        security::security_audit(home_override).unwrap_or_else(|_| empty_security_audit());
    let view = StatusView {
        snapshot: &snapshot,
        runtime_status: &runtime_status,
        local_agents: &local_agents,
        remote_agents: &remote_agents,
        sessions: &sessions,
        stream_records: &stream_records,
        room_records: &room_records,
        route_records: &route_records,
        peers: &peers,
        security: &security_audit,
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_status_json(&view)),
        Ok(false) => CliOutput::success(render_status_text(&view)),
        Err(error) => error,
    }
}

fn render_agents(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_agents_usage()),
        Some("register") if is_help_request(&args[1..]) => {
            CliOutput::success(render_agents_register_usage())
        }
        Some("prepare") if is_help_request(&args[1..]) => {
            CliOutput::success(render_agents_prepare_usage())
        }
        Some("heartbeat") if is_help_request(&args[1..]) => {
            CliOutput::success(render_agents_heartbeat_usage())
        }
        Some("export") if is_help_request(&args[1..]) => {
            CliOutput::success(render_agents_export_usage())
        }
        Some("trust") if is_help_request(&args[1..]) => {
            CliOutput::success(render_agents_trust_usage())
        }
        Some("register") => render_agent_register(&args[1..], home_override),
        Some("prepare") => render_agent_prepare(&args[1..], home_override),
        Some("heartbeat") => render_agent_heartbeat(&args[1..], home_override),
        Some("export") => render_agent_export(&args[1..], home_override),
        Some("trust") => render_agent_trust(&args[1..], home_override),
        _ => render_agents_list(args, home_override),
    }
}

fn render_agents_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let snapshot = match state::read_state(home_override.clone()) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let local_agents = match agents::list_local_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let remote_agents = match sessions::list_remote_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU agents failed\n\n{error}")),
    };
    let registry_state = ready_label(snapshot.agent_registry_exists);

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_agents_json(
            &local_agents,
            &remote_agents,
            registry_state,
            &snapshot.paths.agent_registry.display().to_string(),
        )),
        Ok(false) => CliOutput::success(render_agents_text(
            &local_agents,
            &remote_agents,
            registry_state,
            &snapshot.paths.agent_registry.display().to_string(),
        )),
        Err(error) => error,
    }
}

fn render_agent_register(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_register_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let mut registration =
        match AgentRegistration::new(&parsed.agent_id, &parsed.display_name, &parsed.kind) {
            Ok(registration) => registration,
            Err(error) => {
                return CliOutput::failure(2, format!("conU agents register failed\n\n{error}"));
            }
        };
    registration.capabilities = parsed.capabilities.clone();

    let submission = match agents::submit_registration(home_override.clone(), registration) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU agents register failed\n\n{error}"));
        }
    };
    let processed = wait_for_agent(home_override.clone(), &parsed.agent_id);
    let status = if processed { "registered" } else { "queued" };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "agentId": "{}",
  "requestId": "{}",
  "processed": {},
  "capabilities": {{
    "messages": {},
    "streams": {},
    "rooms": {},
    "files": {},
    "presence": {}
  }},
  "contentsDisplayed": false
}}"#,
            status,
            json_escape(&parsed.agent_id),
            json_escape(&submission.request_id),
            processed,
            parsed.capabilities.messages,
            parsed.capabilities.streams,
            parsed.capabilities.rooms,
            parsed.capabilities.files,
            parsed.capabilities.presence
        ));
    }

    CliOutput::success(format!(
        r"conU agents register

status: {status}
agent: {}
name: {}
kind: {}
capabilities: {}
request: {}
gateway: file IPC

privacy
  payload view  contents are not displayed by conU",
        parsed.agent_id,
        parsed.display_name,
        parsed.kind,
        capabilities_summary(&parsed.capabilities),
        submission.request_id
    ))
}

fn render_agent_prepare(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_agent_prepare_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match run_agent_prepare(home_override, &parsed) {
        Ok(report) if parsed.json => CliOutput::success(render_agent_prepare_json(&report)),
        Ok(report) => CliOutput::success(render_agent_prepare_text(&report)),
        Err(error) => CliOutput::failure(1, format!("conU agents prepare failed\n\n{error}")),
    }
}

fn render_ready(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if args.is_empty() || is_help_request(args) {
        return CliOutput::success(render_ready_usage());
    }

    retitle_agent_prepare_output(render_agent_prepare(args, home_override))
}

fn retitle_agent_prepare_output(mut output: CliOutput) -> CliOutput {
    output.stdout = output
        .stdout
        .replace("conU agents prepare", "conU ready")
        .replace("conu agents prepare", "conu ready");
    output.stderr = output
        .stderr
        .replace("conU agents prepare", "conU ready")
        .replace("conu agents prepare", "conu ready");
    output
}

fn render_agent_export(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_agent_export_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let card = match agents::export_agent_card(home_override, &parsed.agent_id) {
        Ok(card) => card,
        Err(error) => {
            return CliOutput::failure(1, format!("conU agents export failed\n\n{error}"));
        }
    };

    if parsed.json {
        return CliOutput::success(render_signed_agent_card_json(&card));
    }

    CliOutput::success(render_signed_agent_card_text(&card))
}

fn render_agent_trust(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_agent_trust_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let json = parsed.json;
    let card = SignedAgentCard {
        agent_id: parsed.agent_id,
        display_name: parsed.display_name,
        node_id: parsed.node_id,
        kind: parsed.kind,
        capabilities: parsed.capabilities,
        signature_algorithm: parsed.signature_algorithm,
        signature_key_id: parsed.signature_key_id,
        signing_public_key_hex: parsed.signing_public_key_hex,
        signature_hex: parsed.signature_hex,
    };
    let record = match sessions::trust_remote_agent_card(home_override, card) {
        Ok(record) => record,
        Err(error) => {
            return CliOutput::failure(1, format!("conU agents trust failed\n\n{error}"));
        }
    };

    if json {
        return CliOutput::success(format!(
            r#"{{
  "status": "trusted_remote_agent",
  "agentId": "{}",
  "nodeId": "{}",
  "peerNodeId": "{}",
  "agentCardSigned": {},
  "capabilities": {{
    "messages": {},
    "streams": {},
    "rooms": {},
    "files": {},
    "presence": {}
  }},
  "contentsDisplayed": false
}}"#,
            json_escape(&record.agent_id),
            json_escape(&record.node_id),
            json_escape(&record.peer_node_id),
            record.agent_card_signed(),
            record.capabilities.messages,
            record.capabilities.streams,
            record.capabilities.rooms,
            record.capabilities.files,
            record.capabilities.presence
        ));
    }

    CliOutput::success(format!(
        r"conU agents trust

status: trusted remote agent
agent: {}
node: {}
capabilities: {}
agent card: signed

privacy
  payload view  contents are not displayed by conU",
        record.agent_id,
        record.node_id,
        capabilities_summary(&record.capabilities)
    ))
}

fn render_agent_heartbeat(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_heartbeat_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let heartbeat = match PresenceHeartbeat::new(&parsed.agent_id, parsed.presence) {
        Ok(heartbeat) => heartbeat,
        Err(error) => {
            return CliOutput::failure(2, format!("conU agents heartbeat failed\n\n{error}"));
        }
    };
    let submission = match agents::submit_presence_heartbeat(home_override.clone(), heartbeat) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU agents heartbeat failed\n\n{error}"));
        }
    };
    let processed = wait_for_agent_presence(home_override, &parsed.agent_id, parsed.presence);
    let status = if processed {
        "presence updated"
    } else {
        "queued"
    };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "agentId": "{}",
  "presence": "{}",
  "requestId": "{}",
  "processed": {},
  "contentsDisplayed": false
}}"#,
            status,
            json_escape(&parsed.agent_id),
            parsed.presence.as_str(),
            json_escape(&submission.request_id),
            processed
        ));
    }

    CliOutput::success(format!(
        r"conU agents heartbeat

status: {status}
agent: {}
presence: {}
request: {}
gateway: file IPC

privacy
  payload view  contents are not displayed by conU",
        parsed.agent_id,
        parsed.presence.as_str(),
        submission.request_id
    ))
}

fn render_agents_json(
    agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    registry: &str,
    registry_path: &str,
) -> String {
    let local_items = agents
        .iter()
        .map(|agent| {
            format!(
                r#"    {{
      "agentId": "{}",
      "displayName": "{}",
      "kind": "{}",
      "presence": "{}",
      "nodeId": "{}",
      "agentCardSigned": {},
      "capabilities": {{
        "messages": {},
        "streams": {},
        "rooms": {},
        "files": {},
        "presence": {}
      }}
    }}"#,
                json_escape(&agent.agent_id),
                json_escape(&agent.display_name),
                json_escape(&agent.kind),
                agent.presence.as_str(),
                json_escape(&agent.node_id),
                agent.signature_hex.is_some(),
                agent.capabilities.messages,
                agent.capabilities.streams,
                agent.capabilities.rooms,
                agent.capabilities.files,
                agent.capabilities.presence
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let local = if local_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{local_items}\n  ]")
    };
    let remote_items = remote_agents
        .iter()
        .map(|agent| {
            format!(
                r#"    {{
      "agentId": "{}",
      "displayName": "{}",
      "kind": "{}",
      "presence": "{}",
      "nodeId": "{}",
      "peerNodeId": "{}",
      "agentCardSigned": {},
      "capabilities": {{
        "messages": {},
        "streams": {},
        "rooms": {},
        "files": {},
        "presence": {}
      }}
    }}"#,
                json_escape(&agent.agent_id),
                json_escape(&agent.display_name),
                json_escape(&agent.kind),
                agent.presence.as_str(),
                json_escape(&agent.node_id),
                json_escape(&agent.peer_node_id),
                agent.agent_card_signed(),
                agent.capabilities.messages,
                agent.capabilities.streams,
                agent.capabilities.rooms,
                agent.capabilities.files,
                agent.capabilities.presence
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let remote = if remote_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{remote_items}\n  ]")
    };

    format!(
        r#"{{
  "local": {},
  "remote": {},
  "registry": "{}",
  "registryPath": "{}",
  "status": "agent registry active"
}}"#,
        local,
        remote,
        registry,
        json_escape(registry_path)
    )
}

fn render_agents_text(
    agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    registry: &str,
    registry_path: &str,
) -> String {
    let local = if agents.is_empty() {
        "  none registered yet".to_string()
    } else {
        agents
            .iter()
            .map(|agent| {
                format!(
                    "  {}  {}  {}  kind {}",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.display_name,
                    agent.kind
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let remote = if remote_agents.is_empty() {
        "  none visible yet".to_string()
    } else {
        remote_agents
            .iter()
            .map(|agent| {
                format!(
                    "  {}  {}  {}  peer {}  card {}",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.display_name,
                    agent.peer_node_id,
                    if agent.agent_card_signed() {
                        "signed"
                    } else {
                        "placeholder"
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU agents

local agents
{local}
  registry      {}
  path          {}

remote agents
{remote}

next
  conu agents prepare <agent-id> <display-name> [--connect <agent-id>] [--room room.dev]
  conu agents register <agent-id> <display-name> [--streams true] [--rooms true]
  conu agents export <agent-id> --json
  conu agents trust <agent-id> <display-name> --node <peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id>
  conu agents heartbeat <agent-id>
  conu sessions sync",
        registry, registry_path
    )
}

fn render_agents_usage() -> String {
    r"usage:
  conu agents [--json]
  conu agents prepare <agent-id> <display-name> [--kind <kind>] [--presence <ready|busy|idle|offline>] [--connect <agent-id>] [--stream-kind <kind>] [--room <room-id>] [--room-name <display-name>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence-capability <true|false>] [--json]
  conu agents register <agent-id> <display-name> [--kind <kind>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence <true|false>] [--json]
  conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]
  conu agents export <agent-id> [--json]
  conu agents trust <agent-id> <display-name> --node <peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence <true|false>] [--signature-algorithm <algorithm>] [--json]

quick start:
  conu setup --start
  conu connect

privacy:
  agent commands show ids, presence, capabilities, signatures, and delivery metadata only
  payload contents are never displayed
  contentsDisplayed=false"
        .to_string()
}

struct RegisterArgs {
    agent_id: String,
    display_name: String,
    kind: String,
    capabilities: AgentCapabilities,
    json: bool,
}

struct AgentPrepareArgs {
    agent_id: String,
    display_name: String,
    kind: String,
    capabilities: AgentCapabilities,
    presence: AgentPresence,
    connect_to_agent_id: Option<String>,
    stream_kind: String,
    room_id: Option<String>,
    room_display_name: Option<String>,
    json: bool,
}

struct AgentPrepareReport {
    state_path: PathBuf,
    node_id: String,
    node_created: bool,
    agent_id: String,
    display_name: String,
    kind: String,
    capabilities: AgentCapabilities,
    presence: Option<AgentPresence>,
    registration_request_id: String,
    presence_request_id: Option<String>,
    processed_agents: usize,
    rejected_agents: usize,
    registered_agents: usize,
    heartbeat_updated: bool,
    stream: Option<StreamRecord>,
    stream_created: bool,
    room: Option<RoomRecord>,
    room_created: bool,
    agent_joined_room: bool,
}

struct HeartbeatArgs {
    agent_id: String,
    presence: AgentPresence,
    json: bool,
}

struct AgentExportArgs {
    agent_id: String,
    json: bool,
}

struct AgentTrustArgs {
    agent_id: String,
    display_name: String,
    node_id: String,
    kind: String,
    capabilities: AgentCapabilities,
    signature_algorithm: String,
    signature_key_id: String,
    signing_public_key_hex: String,
    signature_hex: String,
    json: bool,
}

fn parse_agent_export_args(args: &[String]) -> Result<AgentExportArgs, CliOutput> {
    let mut json = false;
    let mut positional = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
    }

    if positional.len() != 1 {
        return Err(CliOutput::failure(2, render_agents_export_usage()));
    }

    Ok(AgentExportArgs {
        agent_id: positional.remove(0),
        json,
    })
}

fn parse_agent_trust_args(args: &[String]) -> Result<AgentTrustArgs, CliOutput> {
    let mut json = false;
    let mut node_id = None;
    let mut kind = None;
    let mut capabilities = AgentCapabilities::basic();
    let mut signature_algorithm = None;
    let mut signature_key_id = None;
    let mut signing_public_key_hex = None;
    let mut signature_hex = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--node" => {
                node_id = Some(required_option_value(
                    args,
                    index,
                    render_agents_trust_usage(),
                )?);
                index += 2;
            }
            "--kind" => {
                kind = Some(required_option_value(
                    args,
                    index,
                    render_agents_trust_usage(),
                )?);
                index += 2;
            }
            "--messages" => {
                capabilities.messages = parse_agent_trust_bool(args.get(index + 1), "--messages")?;
                index += 2;
            }
            "--streams" => {
                capabilities.streams = parse_agent_trust_bool(args.get(index + 1), "--streams")?;
                index += 2;
            }
            "--rooms" => {
                capabilities.rooms = parse_agent_trust_bool(args.get(index + 1), "--rooms")?;
                index += 2;
            }
            "--files" => {
                capabilities.files = parse_agent_trust_bool(args.get(index + 1), "--files")?;
                index += 2;
            }
            "--presence" => {
                capabilities.presence = parse_agent_trust_bool(args.get(index + 1), "--presence")?;
                index += 2;
            }
            "--signature-algorithm" => {
                signature_algorithm = Some(required_option_value(
                    args,
                    index,
                    render_agents_trust_usage(),
                )?);
                index += 2;
            }
            "--signature-key-id" => {
                signature_key_id = Some(required_option_value(
                    args,
                    index,
                    render_agents_trust_usage(),
                )?);
                index += 2;
            }
            "--signing-key" => {
                signing_public_key_hex = Some(required_option_value(
                    args,
                    index,
                    render_agents_trust_usage(),
                )?);
                index += 2;
            }
            "--signature" => {
                signature_hex = Some(required_option_value(
                    args,
                    index,
                    render_agents_trust_usage(),
                )?);
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                positional.push(value.to_string());
                index += 1;
            }
        }
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_agents_trust_usage()));
    }

    Ok(AgentTrustArgs {
        agent_id: positional.remove(0),
        display_name: positional.remove(0),
        node_id: node_id.ok_or_else(|| CliOutput::failure(2, render_agents_trust_usage()))?,
        kind: kind.ok_or_else(|| CliOutput::failure(2, render_agents_trust_usage()))?,
        capabilities,
        signature_algorithm: signature_algorithm
            .unwrap_or_else(|| security::AGENT_CARD_SIGNATURE_ALGORITHM.to_string()),
        signature_key_id: signature_key_id
            .ok_or_else(|| CliOutput::failure(2, render_agents_trust_usage()))?,
        signing_public_key_hex: signing_public_key_hex
            .ok_or_else(|| CliOutput::failure(2, render_agents_trust_usage()))?,
        signature_hex: signature_hex
            .ok_or_else(|| CliOutput::failure(2, render_agents_trust_usage()))?,
        json,
    })
}

fn required_option_value(
    args: &[String],
    index: usize,
    usage: String,
) -> Result<String, CliOutput> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| CliOutput::failure(2, usage))
}

fn render_signed_agent_card_json(card: &SignedAgentCard) -> String {
    format!(
        r#"{{
  "agentId": "{}",
  "displayName": "{}",
  "nodeId": "{}",
  "kind": "{}",
  "capabilities": {{
    "messages": {},
    "streams": {},
    "rooms": {},
    "files": {},
    "presence": {}
  }},
  "signatureAlgorithm": "{}",
  "signatureKeyId": "{}",
  "signingPublicKeyHex": "{}",
  "signatureHex": "{}",
  "agentCardSigned": true,
  "contentsDisplayed": false
}}"#,
        json_escape(&card.agent_id),
        json_escape(&card.display_name),
        json_escape(&card.node_id),
        json_escape(&card.kind),
        card.capabilities.messages,
        card.capabilities.streams,
        card.capabilities.rooms,
        card.capabilities.files,
        card.capabilities.presence,
        json_escape(&card.signature_algorithm),
        json_escape(&card.signature_key_id),
        json_escape(&card.signing_public_key_hex),
        json_escape(&card.signature_hex)
    )
}

fn render_signed_agent_card_text(card: &SignedAgentCard) -> String {
    format!(
        r"conU agents export

agent: {}
name: {}
node: {}
kind: {}
capabilities: {}
signature algorithm: {}
signature key id: {}
signing public key: {}
signature: {}

share this public card with a trusted peer, then import it with:
  conu agents trust <agent-id> <display-name> --node {} --kind {} --signing-key <hex> --signature <hex> --signature-key-id <id>

privacy
  payload view  contents are not displayed by conU",
        card.agent_id,
        card.display_name,
        card.node_id,
        card.kind,
        capabilities_summary(&card.capabilities),
        card.signature_algorithm,
        card.signature_key_id,
        card.signing_public_key_hex,
        card.signature_hex,
        card.node_id,
        card.kind
    )
}

fn render_agents_export_usage() -> String {
    "usage: conu agents export <agent-id> [--json]".to_string()
}

fn render_agents_trust_usage() -> String {
    "usage: conu agents trust <agent-id> <display-name> --node <peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence <true|false>] [--signature-algorithm <algorithm>] [--json]".to_string()
}

fn parse_agent_prepare_args(args: &[String]) -> Result<AgentPrepareArgs, CliOutput> {
    let mut json = false;
    let mut kind = "local-agent".to_string();
    let mut capabilities = setup_agent_capabilities();
    let mut presence = AgentPresence::Ready;
    let mut connect_to_agent_id = None;
    let mut stream_kind = "message".to_string();
    let mut stream_kind_explicit = false;
    let mut room_id = None;
    let mut room_display_name = None;
    let mut room_name_explicit = false;
    let mut presence_explicit = false;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--kind" => {
                kind = required_option_value(args, index, render_agents_prepare_usage())?;
                index += 2;
            }
            "--presence" => {
                let value = required_option_value(args, index, render_agents_prepare_usage())?;
                presence = parse_presence(&value)?;
                presence_explicit = true;
                index += 2;
            }
            "--connect" => {
                connect_to_agent_id = Some(required_option_value(
                    args,
                    index,
                    render_agents_prepare_usage(),
                )?);
                index += 2;
            }
            "--stream-kind" => {
                stream_kind = required_option_value(args, index, render_agents_prepare_usage())?;
                stream_kind_explicit = true;
                index += 2;
            }
            "--room" => {
                room_id = Some(required_option_value(
                    args,
                    index,
                    render_agents_prepare_usage(),
                )?);
                index += 2;
            }
            "--room-name" => {
                room_display_name = Some(required_option_value(
                    args,
                    index,
                    render_agents_prepare_usage(),
                )?);
                room_name_explicit = true;
                index += 2;
            }
            "--messages" => {
                capabilities.messages =
                    parse_agent_prepare_bool(args.get(index + 1), "--messages")?;
                index += 2;
            }
            "--streams" => {
                capabilities.streams = parse_agent_prepare_bool(args.get(index + 1), "--streams")?;
                index += 2;
            }
            "--rooms" => {
                capabilities.rooms = parse_agent_prepare_bool(args.get(index + 1), "--rooms")?;
                index += 2;
            }
            "--files" => {
                capabilities.files = parse_agent_prepare_bool(args.get(index + 1), "--files")?;
                index += 2;
            }
            "--presence-capability" => {
                capabilities.presence =
                    parse_agent_prepare_bool(args.get(index + 1), "--presence-capability")?;
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                positional.push(value.to_string());
                index += 1;
            }
        }
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_agents_prepare_usage()));
    }

    let agent_id = positional.remove(0);
    if matches!(connect_to_agent_id.as_deref(), Some(peer_id) if peer_id == agent_id) {
        return Err(CliOutput::failure(
            2,
            format!(
                "--connect must be different from <agent-id>\n\n{}",
                render_agents_prepare_usage()
            ),
        ));
    }
    if connect_to_agent_id.is_none() && stream_kind_explicit {
        return Err(CliOutput::failure(
            2,
            format!(
                "--stream-kind requires --connect\n\n{}",
                render_agents_prepare_usage()
            ),
        ));
    }
    if connect_to_agent_id.is_some() && !capabilities.streams {
        return Err(CliOutput::failure(
            2,
            format!(
                "--connect requires --streams true\n\n{}",
                render_agents_prepare_usage()
            ),
        ));
    }
    if room_id.is_none() && room_name_explicit {
        return Err(CliOutput::failure(
            2,
            format!(
                "--room-name requires --room\n\n{}",
                render_agents_prepare_usage()
            ),
        ));
    }
    if room_id.is_some() && !capabilities.rooms {
        return Err(CliOutput::failure(
            2,
            format!(
                "--room requires --rooms true\n\n{}",
                render_agents_prepare_usage()
            ),
        ));
    }
    if presence_explicit && !capabilities.presence {
        return Err(CliOutput::failure(
            2,
            format!(
                "--presence requires --presence-capability true\n\n{}",
                render_agents_prepare_usage()
            ),
        ));
    }

    Ok(AgentPrepareArgs {
        agent_id,
        display_name: positional.remove(0),
        kind,
        capabilities,
        presence,
        connect_to_agent_id,
        stream_kind,
        room_id,
        room_display_name,
        json,
    })
}

fn parse_register_args(args: &[String]) -> Result<RegisterArgs, CliOutput> {
    let mut json = false;
    let mut kind = "local-agent".to_string();
    let mut capabilities = AgentCapabilities::basic();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--kind" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_agents_register_usage()));
                };
                kind = value.clone();
                index += 2;
            }
            "--messages" => {
                capabilities.messages = parse_register_bool(args.get(index + 1), "--messages")?;
                index += 2;
            }
            "--streams" => {
                capabilities.streams = parse_register_bool(args.get(index + 1), "--streams")?;
                index += 2;
            }
            "--rooms" => {
                capabilities.rooms = parse_register_bool(args.get(index + 1), "--rooms")?;
                index += 2;
            }
            "--files" => {
                capabilities.files = parse_register_bool(args.get(index + 1), "--files")?;
                index += 2;
            }
            "--presence" => {
                capabilities.presence = parse_register_bool(args.get(index + 1), "--presence")?;
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                positional.push(value.to_string());
                index += 1;
            }
        }
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_agents_register_usage()));
    }

    Ok(RegisterArgs {
        agent_id: positional.remove(0),
        display_name: positional.remove(0),
        kind,
        capabilities,
        json,
    })
}

fn parse_register_bool(value: Option<&String>, option: &'static str) -> Result<bool, CliOutput> {
    parse_bool_option(value, option, render_agents_register_usage())
}

fn parse_agent_prepare_bool(
    value: Option<&String>,
    option: &'static str,
) -> Result<bool, CliOutput> {
    parse_bool_option(value, option, render_agents_prepare_usage())
}

fn parse_agent_trust_bool(value: Option<&String>, option: &'static str) -> Result<bool, CliOutput> {
    parse_bool_option(value, option, render_agents_trust_usage())
}

fn parse_bool_option(
    value: Option<&String>,
    option: &'static str,
    usage: String,
) -> Result<bool, CliOutput> {
    let Some(value) = value else {
        return Err(CliOutput::failure(2, usage));
    };
    match value.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(CliOutput::failure(
            2,
            format!("{option} expects true or false\n\n{usage}"),
        )),
    }
}

fn render_agents_register_usage() -> String {
    "usage: conu agents register <agent-id> <display-name> [--kind <kind>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence <true|false>] [--json]".to_string()
}

fn render_agents_prepare_usage() -> String {
    "usage: conu agents prepare <agent-id> <display-name> [--kind <kind>] [--presence <ready|busy|idle|offline>] [--connect <agent-id>] [--stream-kind <kind>] [--room <room-id>] [--room-name <display-name>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence-capability <true|false>] [--json]".to_string()
}

fn render_ready_usage() -> String {
    r"usage:
  conu ready <agent-id> <display-name> [--kind <kind>] [--presence <ready|busy|idle|offline>] [--connect <agent-id>] [--stream-kind <kind>] [--room <room-id>] [--room-name <display-name>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence-capability <true|false>] [--json]

examples:
  conu ready agent.worker Worker-Agent
  conu ready agent.worker Worker-Agent --connect agent.peer --room room.dev

purpose:
  initialize conU state, register the agent, mark it ready, and optionally open a stream or room
  same engine as conu agents prepare
  contentsDisplayed=false"
        .to_string()
}

fn render_agents_heartbeat_usage() -> String {
    "usage: conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]"
        .to_string()
}

fn capabilities_summary(capabilities: &AgentCapabilities) -> String {
    format!(
        "messages={} streams={} rooms={} files={} presence={}",
        capabilities.messages,
        capabilities.streams,
        capabilities.rooms,
        capabilities.files,
        capabilities.presence
    )
}

fn parse_heartbeat_args(args: &[String]) -> Result<HeartbeatArgs, CliOutput> {
    let mut json = false;
    let mut presence = AgentPresence::Ready;
    let mut agent_id = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--presence" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(
                        2,
                        "usage: conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]",
                    ));
                };
                presence = parse_presence(value)?;
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(
                        2,
                        "usage: conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]",
                    ));
                }
                agent_id = Some(value.to_string());
                index += 1;
            }
        }
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(
            2,
            "usage: conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]",
        ));
    };

    Ok(HeartbeatArgs {
        agent_id,
        presence,
        json,
    })
}

fn parse_presence(value: &str) -> Result<AgentPresence, CliOutput> {
    match value {
        "ready" => Ok(AgentPresence::Ready),
        "busy" => Ok(AgentPresence::Busy),
        "idle" => Ok(AgentPresence::Idle),
        "offline" => Ok(AgentPresence::Offline),
        _ => Err(CliOutput::failure(
            2,
            "presence must be ready, busy, idle, or offline",
        )),
    }
}

fn wait_for_agent(home_override: Option<PathBuf>, agent_id: &str) -> bool {
    if !runtime_is_live(home_override.clone()) {
        return false;
    }

    for _ in 0..40 {
        if agents::agent_exists(home_override.clone(), agent_id).unwrap_or(false) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }

    false
}

fn wait_for_agent_presence(
    home_override: Option<PathBuf>,
    agent_id: &str,
    presence: AgentPresence,
) -> bool {
    if !runtime_is_live(home_override.clone()) {
        return false;
    }

    for _ in 0..40 {
        if agents::list_local_agents(home_override.clone())
            .map(|agents| {
                agents
                    .iter()
                    .any(|agent| agent.agent_id == agent_id && agent.presence == presence)
            })
            .unwrap_or(false)
        {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }

    false
}

fn runtime_is_live(home_override: Option<PathBuf>) -> bool {
    runtime::read_runtime(home_override)
        .map(|status| status.is_live())
        .unwrap_or(false)
}

fn render_messages(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("send") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_send_usage())
        }
        Some("inbox") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_inbox_usage())
        }
        Some("history") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_history_usage())
        }
        Some("reply") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_reply_usage())
        }
        Some("wait") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_wait_usage())
        }
        Some("receive") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_receive_usage())
        }
        Some("pull") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_pull_usage())
        }
        Some("receipts") if is_help_request(&args[1..]) => {
            CliOutput::success(render_messages_usage())
        }
        Some("send") => render_message_send(&args[1..], home_override, stdin_payload),
        Some("inbox") => render_message_inbox(&args[1..], home_override),
        Some("history") => render_message_history(&args[1..], home_override),
        Some("reply") => render_message_reply(&args[1..], home_override, stdin_payload),
        Some("wait") => render_message_wait(&args[1..], home_override),
        Some("receive") => render_message_receive(&args[1..], home_override),
        Some("pull") => render_message_pull(&args[1..], home_override),
        Some("receipts") => render_message_receipts(&args[1..], home_override),
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_messages_usage()),
        _ => CliOutput::failure(2, render_messages_usage()),
    }
}

fn retitle_output(mut output: CliOutput, old: &str, new: &str, simple_usage: &str) -> CliOutput {
    output.stdout = output.stdout.replace(old, new);
    output.stderr = output.stderr.replace(old, new);
    if output.stderr.trim_end() == render_messages_usage() {
        output.stderr = finish(simple_usage.to_string());
    }
    output
}

fn render_send(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let usage = render_send_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_send(args, home_override, stdin_payload),
        "conU messages send",
        "conU send",
        &usage,
    )
}

fn render_inbox(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let usage = render_inbox_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_inbox(args, home_override),
        "conU messages inbox",
        "conU inbox",
        &usage,
    )
}

fn render_history(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let usage = render_history_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_history(args, home_override),
        "conU messages history",
        "conU history",
        &usage,
    )
}

fn render_reply(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let usage = render_reply_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_reply(args, home_override, stdin_payload),
        "conU messages reply",
        "conU reply",
        &usage,
    )
}

fn render_next(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let usage = render_next_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    let parsed = match parse_agent_next_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let agents = match agents::list_local_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU next failed\n\n{error}")),
    };
    let registered = agents
        .iter()
        .find(|agent| agent.agent_id == parsed.agent_id)
        .cloned();
    let inbox = if registered.is_some() {
        match messages::list_agent_inbox(home_override, &parsed.agent_id) {
            Ok(entries) => entries,
            Err(error) => return CliOutput::failure(1, format!("conU next failed\n\n{error}")),
        }
    } else {
        Vec::new()
    };

    if parsed.json {
        return CliOutput::success(render_next_json(
            &parsed.agent_id,
            registered.as_ref(),
            &inbox,
        ));
    }

    CliOutput::success(render_next_text(
        &parsed.agent_id,
        registered.as_ref(),
        &inbox,
    ))
}

fn render_wait(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let usage = render_wait_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_wait(args, home_override),
        "conU messages wait",
        "conU wait",
        &usage,
    )
}

fn render_receive(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let usage = render_receive_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_receive(args, home_override),
        "conU messages receive",
        "conU receive",
        &usage,
    )
}

fn render_pull(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let usage = render_pull_usage();
    if is_help_request(args) {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_pull(args, home_override),
        "conU messages pull",
        "conU pull",
        &usage,
    )
}

fn render_chat(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let usage = render_chat_usage();
    if is_help_request(args) || args.is_empty() {
        return CliOutput::success(usage);
    }
    retitle_output(
        render_message_send(args, home_override, stdin_payload),
        "conU messages send",
        "conU chat",
        &usage,
    )
}

fn render_message_send(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_message_send_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let payload = match read_message_input_payload(parsed.payload_input.as_ref(), stdin_payload) {
        Ok(payload) => payload,
        Err(error) => return error,
    };

    if let Some(peer_node_id) = parsed.peer_node_id.clone() {
        return render_remote_message_send(parsed, &peer_node_id, home_override, payload);
    }

    if let Err(error) = agents::process_gateway_requests(home_override.clone()) {
        return CliOutput::failure(1, format!("conU messages send failed\n\n{error}"));
    }
    let before = inbox_ids(home_override.clone(), &parsed.to_agent_id);
    let payload_bytes = payload.len();
    let message = match LocalMessage::new(
        &parsed.from_agent_id,
        &parsed.to_agent_id,
        OpaquePayload::from_bytes(payload),
    ) {
        Ok(message) => message,
        Err(error) => {
            return CliOutput::failure(2, format!("conU messages send failed\n\n{error}"));
        }
    };
    let submission = match messages::submit_local_message(home_override.clone(), message) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages send failed\n\n{error}"));
        }
    };
    if let Err(error) = messages::process_message_requests(home_override.clone()) {
        return CliOutput::failure(1, format!("conU messages send failed\n\n{error}"));
    }
    let delivered = wait_for_message_delivery(
        home_override,
        &parsed.to_agent_id,
        before,
        submission.payload_bytes,
    );
    let status = if delivered.is_some() {
        "delivered"
    } else {
        "queued"
    };

    if parsed.json {
        let envelope_id = delivered
            .as_ref()
            .map(|entry| json_string(&entry.envelope_id))
            .unwrap_or_else(|| "null".to_string());
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "requestId": "{}",
  "envelopeId": {},
  "payloadBytes": {},
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            status,
            json_escape(&parsed.from_agent_id),
            json_escape(&parsed.to_agent_id),
            json_escape(&submission.request_id),
            envelope_id,
            payload_bytes
        ));
    }

    let envelope_line = delivered
        .as_ref()
        .map(|entry| format!("envelope: {}", entry.envelope_id))
        .unwrap_or_else(|| "envelope: pending".to_string());

    CliOutput::success(format!(
        r"conU messages send

status: {status}
from: {}
to: {}
request: {}
{envelope_line}
bytes: {}

privacy
  input path    pathDisplayed=false
  payload view  contents are not displayed by conU",
        parsed.from_agent_id, parsed.to_agent_id, submission.request_id, payload_bytes
    ))
}

fn render_remote_message_send(
    parsed: MessageSendArgs,
    peer_node_id: &str,
    home_override: Option<PathBuf>,
    payload: Vec<u8>,
) -> CliOutput {
    let payload_bytes = payload.len();
    let message = match RemoteMessage::new(
        &parsed.from_agent_id,
        &parsed.to_agent_id,
        peer_node_id,
        OpaquePayload::from_bytes(payload),
    ) {
        Ok(message) => message,
        Err(error) => {
            return CliOutput::failure(2, format!("conU messages send failed\n\n{error}"));
        }
    };
    let selected_route = routes::selected_route_for_peer(home_override.clone(), peer_node_id)
        .ok()
        .flatten();
    if selected_route
        .as_ref()
        .is_some_and(|route| route.transport == RouteTransport::DirectQuic && route.is_selected())
    {
        match direct_transport::send_direct_message(home_override.clone(), message.clone()) {
            Ok(submission) => {
                if parsed.json {
                    return CliOutput::success(format!(
                        r#"{{
  "status": "sent_remote",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "peerNodeId": "{}",
  "envelopeId": "{}",
  "payloadBytes": {},
  "route": "direct-quic",
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
                        json_escape(&parsed.from_agent_id),
                        json_escape(&parsed.to_agent_id),
                        json_escape(&submission.peer_node_id),
                        json_escape(&submission.envelope_id),
                        payload_bytes
                    ));
                }

                return CliOutput::success(format!(
                    r"conU messages send

status: sent directly
from: {}
to: {}
peer: {}
envelope: {}
bytes: {}
route: direct-quic

privacy
  input path    pathDisplayed=false
  payload view  contents are not displayed by conU",
                    parsed.from_agent_id,
                    parsed.to_agent_id,
                    submission.peer_node_id,
                    submission.envelope_id,
                    payload_bytes
                ));
            }
            Err(error) if error.is_safe_for_relay_fallback() => {}
            Err(error) => {
                return CliOutput::failure(1, format!("conU messages send failed\n\n{error}"));
            }
        }
    }

    let submission = match relay_delivery::submit_remote_message(home_override, message) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages send failed\n\n{error}"));
        }
    };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "queued_remote",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "peerNodeId": "{}",
  "requestId": "{}",
  "envelopeId": "{}",
  "payloadBytes": {},
  "route": "relay-websocket",
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            json_escape(&parsed.from_agent_id),
            json_escape(&parsed.to_agent_id),
            json_escape(&submission.peer_node_id),
            json_escape(&submission.request_id),
            json_escape(&submission.envelope_id),
            payload_bytes
        ));
    }

    CliOutput::success(format!(
        r"conU messages send

status: queued for relay
from: {}
to: {}
peer: {}
request: {}
envelope: {}
bytes: {}
route: relay-websocket

next
  conu start
  optional manual flush: conu relay sync --wait-ms 3000

privacy
  input path    pathDisplayed=false
  payload view  contents are not displayed by conU",
        parsed.from_agent_id,
        parsed.to_agent_id,
        submission.peer_node_id,
        submission.request_id,
        submission.envelope_id,
        payload_bytes
    ))
}

fn render_message_inbox(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_message_inbox_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let Some(agent_id) = parsed.agent_id else {
        return render_message_inbox_overview(home_override, parsed.json);
    };

    let entries = match messages::list_agent_inbox(home_override, &agent_id) {
        Ok(entries) => entries,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages inbox failed\n\n{error}"));
        }
    };

    if parsed.json {
        return CliOutput::success(render_inbox_json(&agent_id, &entries));
    }

    CliOutput::success(render_inbox_text(&agent_id, &entries))
}

fn render_message_inbox_overview(home_override: Option<PathBuf>, json: bool) -> CliOutput {
    let local_agents = match agents::list_local_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages inbox failed\n\n{error}"));
        }
    };
    let mut records = Vec::new();
    for agent in local_agents {
        let entries = match messages::list_agent_inbox(home_override.clone(), &agent.agent_id) {
            Ok(entries) => entries,
            Err(error) => {
                return CliOutput::failure(1, format!("conU messages inbox failed\n\n{error}"));
            }
        };
        records.push(InboxOverviewRecord {
            agent_id: agent.agent_id,
            message_count: entries.len(),
            newest: entries.last().cloned(),
        });
    }

    if json {
        return CliOutput::success(render_inbox_overview_json(&records));
    }

    CliOutput::success(render_inbox_overview_text(&records))
}

fn render_message_history(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_message_history_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let entries = match messages::list_agent_inbox(home_override, &parsed.agent_id) {
        Ok(entries) => entries,
        Err(_) => {
            return CliOutput::failure(
                1,
                "conU messages history failed\n\nmessage metadata could not be read for this local agent; contentsDisplayed=false".to_string(),
            );
        }
    };
    let history =
        match select_history_entries(&entries, parsed.after_envelope_id.as_deref(), parsed.limit) {
            Ok(history) => history,
            Err(error) => return CliOutput::failure(1, error),
        };

    if parsed.json {
        return CliOutput::success(render_history_json(&parsed.agent_id, &history, &parsed));
    }

    CliOutput::success(render_history_text(&parsed.agent_id, &history, &parsed))
}

fn render_message_reply(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_message_reply_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let payload = match read_message_input_payload(parsed.payload_input.as_ref(), stdin_payload) {
        Ok(payload) => payload,
        Err(error) => return error,
    };

    let target = match reply_target_entry(home_override.clone(), &parsed) {
        Ok(target) => target,
        Err(error) => return CliOutput::failure(1, error),
    };
    let before = inbox_ids(home_override.clone(), &target.from_agent_id);
    let payload_bytes = payload.len();
    let message = match LocalMessage::new(
        &parsed.agent_id,
        &target.from_agent_id,
        OpaquePayload::from_bytes(payload),
    ) {
        Ok(message) => message,
        Err(error) => {
            return CliOutput::failure(2, format!("conU messages reply failed\n\n{error}"));
        }
    };
    let submission = match messages::submit_local_message(home_override.clone(), message) {
        Ok(submission) => submission,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages reply failed\n\n{error}"));
        }
    };
    if let Err(error) = messages::process_message_requests(home_override.clone()) {
        return CliOutput::failure(1, format!("conU messages reply failed\n\n{error}"));
    }
    let delivered = wait_for_message_delivery(
        home_override,
        &target.from_agent_id,
        before,
        submission.payload_bytes,
    );
    let status = if delivered.is_some() {
        "delivered"
    } else {
        "queued"
    };

    if parsed.json {
        let envelope_id = delivered
            .as_ref()
            .map(|entry| json_string(&entry.envelope_id))
            .unwrap_or_else(|| "null".to_string());
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "inReplyToEnvelopeId": "{}",
  "requestId": "{}",
  "envelopeId": {},
  "payloadBytes": {},
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            status,
            json_escape(&parsed.agent_id),
            json_escape(&target.from_agent_id),
            json_escape(&target.envelope_id),
            json_escape(&submission.request_id),
            envelope_id,
            payload_bytes
        ));
    }

    let envelope_line = delivered
        .as_ref()
        .map(|entry| format!("envelope: {}", entry.envelope_id))
        .unwrap_or_else(|| "envelope: pending".to_string());

    CliOutput::success(format!(
        r"conU messages reply

status: {status}
from: {}
to: {}
inReplyTo: {}
request: {}
{envelope_line}
bytes: {}

privacy
  input path    pathDisplayed=false
  payload view  contentsDisplayed=false",
        parsed.agent_id,
        target.from_agent_id,
        target.envelope_id,
        submission.request_id,
        payload_bytes
    ))
}

fn render_message_wait(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_message_wait_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let started = std::time::Instant::now();

    loop {
        if parsed.process_ipc
            && let Err(error) = process_wait_ipc(home_override.clone())
        {
            return CliOutput::failure(1, format!("conU messages wait failed\n\n{error}"));
        }

        let entries = match messages::list_agent_inbox(home_override.clone(), &parsed.agent_id) {
            Ok(entries) => entries,
            Err(error) => {
                return CliOutput::failure(1, format!("conU messages wait failed\n\n{error}"));
            }
        };
        match newest_wait_entry(&entries, parsed.after_envelope_id.as_deref()) {
            WaitEntrySearch::Found(entry) => {
                let waited_ms = waited_millis(started);
                if parsed.json {
                    return CliOutput::success(render_wait_json(
                        &parsed.agent_id,
                        Some(&entry),
                        "delivered",
                        waited_ms,
                        parsed.process_ipc,
                    ));
                }
                return CliOutput::success(render_wait_text(
                    &parsed.agent_id,
                    Some(&entry),
                    "delivered",
                    waited_ms,
                    parsed.process_ipc,
                ));
            }
            WaitEntrySearch::MissingAfter => {
                return CliOutput::failure(
                    1,
                    "conU messages wait failed\n\nafter envelope was not found in this agent inbox; contentsDisplayed=false",
                );
            }
            WaitEntrySearch::None => {}
        }

        let elapsed = waited_millis(started);
        if elapsed >= parsed.timeout_ms {
            if parsed.json {
                return CliOutput::success(render_wait_json(
                    &parsed.agent_id,
                    None,
                    "timeout",
                    elapsed,
                    parsed.process_ipc,
                ));
            }
            return CliOutput::success(render_wait_text(
                &parsed.agent_id,
                None,
                "timeout",
                elapsed,
                parsed.process_ipc,
            ));
        }

        let remaining = parsed.timeout_ms.saturating_sub(elapsed);
        thread::sleep(Duration::from_millis(
            parsed.interval_ms.min(remaining).max(1),
        ));
    }
}

fn process_wait_ipc(home_override: Option<PathBuf>) -> Result<(), String> {
    agents::process_gateway_requests(home_override.clone()).map_err(|error| error.to_string())?;
    messages::process_message_requests(home_override.clone()).map_err(|error| error.to_string())?;
    sessions::sync_remote_sessions(home_override).map_err(|error| error.to_string())?;
    Ok(())
}

fn render_message_receipts(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let receipts = match messages::list_receipts(home_override) {
        Ok(receipts) => receipts,
        Err(error) => {
            return CliOutput::failure(1, format!("conU messages receipts failed\n\n{error}"));
        }
    };

    if json {
        return CliOutput::success(render_receipts_json(&receipts));
    }

    CliOutput::success(render_receipts_text(&receipts))
}

fn render_message_receive(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_message_receive_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if parsed.latest {
        return render_message_receive_latest(parsed, home_override);
    }

    let envelope_id = parsed
        .envelope_id
        .as_deref()
        .expect("non-latest receive has envelope id");
    let payload = match messages::read_message_payload(home_override, &parsed.agent_id, envelope_id)
    {
        Ok(payload) => payload,
        Err(_) => {
            return CliOutput::failure(
                1,
                "conU messages receive failed\n\npayload could not be read for the addressed local agent; pathDisplayed=false contentsDisplayed=false".to_string(),
            );
        }
    };
    if let Err(error) = write_message_receive_output(&parsed.output_path, payload.as_bytes()) {
        return CliOutput::failure(1, format!("conU messages receive failed\n\n{error}"));
    }

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "written",
  "agentId": "{}",
  "envelopeId": "{}",
  "payloadBytes": {},
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            json_escape(&parsed.agent_id),
            json_escape(envelope_id),
            payload.len()
        ));
    }

    CliOutput::success(format!(
        r"conU messages receive

status: written
agent: {}
envelope: {}
bytes: {}
output: local; pathDisplayed=false

privacy
  payload view  contentsDisplayed=false",
        parsed.agent_id,
        envelope_id,
        payload.len()
    ))
}

fn render_message_pull(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_message_pull_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let started = std::time::Instant::now();

    loop {
        if parsed.process_ipc
            && let Err(error) = process_wait_ipc(home_override.clone())
        {
            return CliOutput::failure(1, format!("conU messages pull failed\n\n{error}"));
        }

        let entries = match messages::list_agent_inbox(home_override.clone(), &parsed.agent_id) {
            Ok(entries) => entries,
            Err(error) => {
                return CliOutput::failure(1, format!("conU messages pull failed\n\n{error}"));
            }
        };
        match newest_wait_entry(&entries, parsed.after_envelope_id.as_deref()) {
            WaitEntrySearch::Found(entry) => {
                return write_pull_entry(parsed, home_override, entry, started);
            }
            WaitEntrySearch::MissingAfter => {
                return CliOutput::failure(
                    1,
                    "conU messages pull failed\n\nafter envelope was not found in this agent inbox; contentsDisplayed=false pathDisplayed=false",
                );
            }
            WaitEntrySearch::None => {}
        }

        let elapsed = waited_millis(started);
        if elapsed >= parsed.timeout_ms {
            return render_pull_timeout(&parsed, elapsed);
        }

        let remaining = parsed.timeout_ms.saturating_sub(elapsed);
        thread::sleep(Duration::from_millis(
            parsed.interval_ms.min(remaining).max(1),
        ));
    }
}

fn write_pull_entry(
    parsed: MessagePullArgs,
    home_override: Option<PathBuf>,
    entry: InboxEntry,
    started: std::time::Instant,
) -> CliOutput {
    let payload = match messages::read_message_payload(
        home_override,
        &parsed.agent_id,
        &entry.envelope_id,
    ) {
        Ok(payload) => payload,
        Err(_) => {
            return CliOutput::failure(
                1,
                "conU messages pull failed\n\npayload could not be read for the addressed local agent; pathDisplayed=false contentsDisplayed=false".to_string(),
            );
        }
    };
    let file_name = pull_output_file_name(&entry);
    if let Err(error) = ensure_pull_output_dir(&parsed.output_dir) {
        return CliOutput::failure(1, format!("conU messages pull failed\n\n{error}"));
    }
    let output_path = parsed.output_dir.join(&file_name);
    if let Err(error) = write_message_receive_output(&output_path, payload.as_bytes()) {
        return CliOutput::failure(1, format!("conU messages pull failed\n\n{error}"));
    }
    let waited_ms = waited_millis(started);

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "written",
  "mode": "pull",
  "agentId": "{}",
  "envelopeId": "{}",
  "fromAgentId": "{}",
  "fileName": "{}",
  "payloadBytes": {},
  "waitedMs": {},
  "processIpc": {},
  "outputDirDisplayed": false,
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            json_escape(&parsed.agent_id),
            json_escape(&entry.envelope_id),
            json_escape(&entry.from_agent_id),
            json_escape(&file_name),
            payload.len(),
            waited_ms,
            parsed.process_ipc
        ));
    }

    CliOutput::success(format!(
        r"conU messages pull

status: written
mode: pull
agent: {}
from: {}
envelope: {}
file: {}
bytes: {}
waitedMs: {}
output: local directory; outputDirDisplayed=false pathDisplayed=false

privacy
  payload view  contentsDisplayed=false",
        parsed.agent_id,
        entry.from_agent_id,
        entry.envelope_id,
        file_name,
        payload.len(),
        waited_ms
    ))
}

fn render_pull_timeout(parsed: &MessagePullArgs, waited_ms: u64) -> CliOutput {
    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "timeout",
  "mode": "pull",
  "agentId": "{}",
  "envelopeId": null,
  "waitedMs": {},
  "processIpc": {},
  "outputWritten": false,
  "outputDirDisplayed": false,
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            json_escape(&parsed.agent_id),
            waited_ms,
            parsed.process_ipc
        ));
    }

    CliOutput::success(format!(
        r"conU messages pull

status: timeout
mode: pull
agent: {}
waitedMs: {}
output: not written; outputDirDisplayed=false pathDisplayed=false

privacy
  payload view  contentsDisplayed=false",
        parsed.agent_id, waited_ms
    ))
}

fn pull_output_file_name(entry: &InboxEntry) -> String {
    format!("conu-message-{}.bin", entry.envelope_id)
}

fn ensure_pull_output_dir(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err(
            "output directory is empty; outputDirDisplayed=false pathDisplayed=false contentsDisplayed=false"
                .to_string(),
        );
    }
    if path.exists() {
        if !path.is_dir() {
            return Err(
                "output directory is not a directory; outputDirDisplayed=false pathDisplayed=false contentsDisplayed=false"
                    .to_string(),
            );
        }
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|_| {
        "could not create output directory; outputDirDisplayed=false pathDisplayed=false contentsDisplayed=false"
            .to_string()
    })
}

fn render_message_receive_latest(
    parsed: MessageReceiveArgs,
    home_override: Option<PathBuf>,
) -> CliOutput {
    let started = std::time::Instant::now();

    loop {
        if parsed.process_ipc
            && let Err(error) = process_wait_ipc(home_override.clone())
        {
            return CliOutput::failure(1, format!("conU messages receive failed\n\n{error}"));
        }

        let entries = match messages::list_agent_inbox(home_override.clone(), &parsed.agent_id) {
            Ok(entries) => entries,
            Err(error) => {
                return CliOutput::failure(1, format!("conU messages receive failed\n\n{error}"));
            }
        };
        match newest_wait_entry(&entries, parsed.after_envelope_id.as_deref()) {
            WaitEntrySearch::Found(entry) => {
                return write_latest_receive_entry(parsed, home_override, entry, started);
            }
            WaitEntrySearch::MissingAfter => {
                return CliOutput::failure(
                    1,
                    "conU messages receive failed\n\nafter envelope was not found in this agent inbox; contentsDisplayed=false pathDisplayed=false",
                );
            }
            WaitEntrySearch::None => {}
        }

        let elapsed = waited_millis(started);
        if elapsed >= parsed.timeout_ms {
            return render_latest_receive_timeout(&parsed, elapsed);
        }

        let remaining = parsed.timeout_ms.saturating_sub(elapsed);
        thread::sleep(Duration::from_millis(
            parsed.interval_ms.min(remaining).max(1),
        ));
    }
}

fn write_latest_receive_entry(
    parsed: MessageReceiveArgs,
    home_override: Option<PathBuf>,
    entry: InboxEntry,
    started: std::time::Instant,
) -> CliOutput {
    let payload = match messages::read_message_payload(
        home_override,
        &parsed.agent_id,
        &entry.envelope_id,
    ) {
        Ok(payload) => payload,
        Err(_) => {
            return CliOutput::failure(
                1,
                "conU messages receive failed\n\npayload could not be read for the addressed local agent; pathDisplayed=false contentsDisplayed=false".to_string(),
            );
        }
    };
    if let Err(error) = write_message_receive_output(&parsed.output_path, payload.as_bytes()) {
        return CliOutput::failure(1, format!("conU messages receive failed\n\n{error}"));
    }
    let waited_ms = waited_millis(started);

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "written",
  "mode": "latest",
  "agentId": "{}",
  "envelopeId": "{}",
  "fromAgentId": "{}",
  "payloadBytes": {},
  "waitedMs": {},
  "processIpc": {},
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            json_escape(&parsed.agent_id),
            json_escape(&entry.envelope_id),
            json_escape(&entry.from_agent_id),
            payload.len(),
            waited_ms,
            parsed.process_ipc
        ));
    }

    CliOutput::success(format!(
        r"conU messages receive

status: written
mode: latest
agent: {}
from: {}
envelope: {}
bytes: {}
waitedMs: {}
output: local; pathDisplayed=false

privacy
  payload view  contentsDisplayed=false",
        parsed.agent_id,
        entry.from_agent_id,
        entry.envelope_id,
        payload.len(),
        waited_ms
    ))
}

fn render_latest_receive_timeout(parsed: &MessageReceiveArgs, waited_ms: u64) -> CliOutput {
    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "timeout",
  "mode": "latest",
  "agentId": "{}",
  "envelopeId": null,
  "waitedMs": {},
  "processIpc": {},
  "outputWritten": false,
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
            json_escape(&parsed.agent_id),
            waited_ms,
            parsed.process_ipc
        ));
    }

    CliOutput::success(format!(
        r"conU messages receive

status: timeout
mode: latest
agent: {}
waitedMs: {}
output: not written; pathDisplayed=false

privacy
  payload view  contentsDisplayed=false",
        parsed.agent_id, waited_ms
    ))
}

enum WaitEntrySearch {
    Found(InboxEntry),
    MissingAfter,
    None,
}

fn newest_wait_entry(entries: &[InboxEntry], after_envelope_id: Option<&str>) -> WaitEntrySearch {
    let Some(after_envelope_id) = after_envelope_id else {
        return entries
            .last()
            .cloned()
            .map(WaitEntrySearch::Found)
            .unwrap_or(WaitEntrySearch::None);
    };

    let Some(position) = entries
        .iter()
        .position(|entry| entry.envelope_id == after_envelope_id)
    else {
        return WaitEntrySearch::MissingAfter;
    };

    entries
        .get(position + 1..)
        .and_then(|entries| entries.last())
        .cloned()
        .map(WaitEntrySearch::Found)
        .unwrap_or(WaitEntrySearch::None)
}

fn waited_millis(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn render_wait_json(
    agent_id: &str,
    entry: Option<&InboxEntry>,
    status: &str,
    waited_ms: u64,
    process_ipc: bool,
) -> String {
    let message = entry
        .map(render_wait_message_json)
        .unwrap_or_else(|| "null".to_string());

    format!(
        r#"{{
  "agentId": "{}",
  "status": "{}",
  "message": {},
  "waitedMs": {},
  "processIpc": {},
  "contentsDisplayed": false
}}"#,
        json_escape(agent_id),
        json_escape(status),
        message,
        waited_ms,
        process_ipc
    )
}

fn render_wait_message_json(entry: &InboxEntry) -> String {
    format!(
        r#"{{
    "envelopeId": "{}",
    "fromAgentId": "{}",
    "toAgentId": "{}",
    "kind": "{}",
    "streamId": {},
    "receiptId": "{}",
    "payloadBytes": {},
    "deliveredAtUnix": {}
  }}"#,
        json_escape(&entry.envelope_id),
        json_escape(&entry.from_agent_id),
        json_escape(&entry.to_agent_id),
        json_escape(&entry.kind),
        optional_json_string(entry.stream_id.as_deref()),
        json_escape(&entry.receipt_id),
        entry.payload_bytes,
        entry.delivered_at_unix
    )
}

fn render_wait_text(
    agent_id: &str,
    entry: Option<&InboxEntry>,
    status: &str,
    waited_ms: u64,
    process_ipc: bool,
) -> String {
    let message = entry
        .map(|entry| {
            let stream = entry
                .stream_id
                .as_deref()
                .map(|stream_id| format!("\nstream: {stream_id}"))
                .unwrap_or_default();
            format!(
                r"message
  envelope: {}
  kind: {}{stream}
  from: {}
  to: {}
  receipt: {}
  bytes: {}
  deliveredAtUnix: {}",
                entry.envelope_id,
                entry.kind,
                entry.from_agent_id,
                entry.to_agent_id,
                entry.receipt_id,
                entry.payload_bytes,
                entry.delivered_at_unix
            )
        })
        .unwrap_or_else(|| "message\n  none".to_string());

    format!(
        r"conU messages wait

status: {status}
agent: {agent_id}
waitedMs: {waited_ms}
processIpc: {process_ipc}
{message}

privacy
  payload view  contents are not displayed by conU"
    )
}

fn render_inbox_json(agent_id: &str, entries: &[InboxEntry]) -> String {
    let messages = entries
        .iter()
        .map(|entry| {
            format!(
                r#"    {{
      "envelopeId": "{}",
      "fromAgentId": "{}",
      "toAgentId": "{}",
      "kind": "{}",
      "streamId": {},
      "receiptId": "{}",
      "payloadBytes": {},
      "deliveredAtUnix": {}
    }}"#,
                json_escape(&entry.envelope_id),
                json_escape(&entry.from_agent_id),
                json_escape(&entry.to_agent_id),
                json_escape(&entry.kind),
                optional_json_string(entry.stream_id.as_deref()),
                json_escape(&entry.receipt_id),
                entry.payload_bytes,
                entry.delivered_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let messages = if messages.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{messages}\n  ]")
    };

    format!(
        r#"{{
  "agentId": "{}",
  "messages": {},
  "contentsDisplayed": false
}}"#,
        json_escape(agent_id),
        messages
    )
}

fn render_inbox_overview_json(records: &[InboxOverviewRecord]) -> String {
    let agents = records
        .iter()
        .map(|record| {
            let newest = record
                .newest
                .as_ref()
                .map(render_inbox_overview_newest_json)
                .unwrap_or_else(|| "null".to_string());
            format!(
                r#"    {{
      "agentId": "{}",
      "messageCount": {},
      "newestMessage": {}
    }}"#,
                json_escape(&record.agent_id),
                record.message_count,
                newest
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let agents = if agents.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{agents}\n  ]")
    };
    let total_messages = records
        .iter()
        .map(|record| record.message_count)
        .sum::<usize>();

    format!(
        r#"{{
  "agents": {},
  "totalAgents": {},
  "totalMessages": {},
  "contentsDisplayed": false
}}"#,
        agents,
        records.len(),
        total_messages
    )
}

fn render_inbox_overview_newest_json(entry: &InboxEntry) -> String {
    format!(
        r#"{{"envelopeId":"{}","fromAgentId":"{}","toAgentId":"{}","kind":"{}","streamId":{},"receiptId":"{}","payloadBytes":{},"deliveredAtUnix":{}}}"#,
        json_escape(&entry.envelope_id),
        json_escape(&entry.from_agent_id),
        json_escape(&entry.to_agent_id),
        json_escape(&entry.kind),
        optional_json_string(entry.stream_id.as_deref()),
        json_escape(&entry.receipt_id),
        entry.payload_bytes,
        entry.delivered_at_unix
    )
}

fn render_next_json(
    agent_id: &str,
    agent: Option<&LocalAgentRecord>,
    entries: &[InboxEntry],
) -> String {
    let newest = entries
        .last()
        .map(render_inbox_overview_newest_json)
        .unwrap_or_else(|| "null".to_string());
    let commands = render_next_command_json(agent_id, agent.is_some(), !entries.is_empty());
    let display_name = agent
        .map(|agent| json_string(&agent.display_name))
        .unwrap_or_else(|| "null".to_string());
    let presence = agent
        .map(|agent| json_string(agent.presence.as_str()))
        .unwrap_or_else(|| "null".to_string());

    format!(
        r#"{{
  "agentId": "{}",
  "registered": {},
  "displayName": {},
  "presence": {},
  "inboxMessages": {},
  "newestMessage": {},
  "commands": {},
  "pathDisplayed": false,
  "contentsDisplayed": false
}}"#,
        json_escape(agent_id),
        agent.is_some(),
        display_name,
        presence,
        entries.len(),
        newest,
        commands
    )
}

fn render_next_command_json(agent_id: &str, registered: bool, has_messages: bool) -> String {
    let commands = next_commands(agent_id, registered, has_messages)
        .into_iter()
        .map(|command| format!(r#"    "{}""#, json_escape(&command)))
        .collect::<Vec<_>>()
        .join(",\n");

    if commands.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{commands}\n  ]")
    }
}

fn render_next_text(
    agent_id: &str,
    agent: Option<&LocalAgentRecord>,
    entries: &[InboxEntry],
) -> String {
    let registered = yes_no(agent.is_some());
    let display_name = agent
        .map(|agent| agent.display_name.as_str())
        .unwrap_or("not registered");
    let presence = agent
        .map(|agent| agent.presence.as_str())
        .unwrap_or("not registered");
    let newest = entries
        .last()
        .map(|entry| {
            format!(
                "{} from {} bytes {}",
                entry.envelope_id, entry.from_agent_id, entry.payload_bytes
            )
        })
        .unwrap_or_else(|| "none".to_string());
    let commands = next_commands(agent_id, agent.is_some(), !entries.is_empty())
        .into_iter()
        .map(|command| format!("  {command}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r"conU next

agent: {agent_id}
registered: {registered}
displayName: {display_name}
presence: {presence}
inboxMessages: {}
newest: {newest}

next commands
{commands}

privacy
  payload view  contentsDisplayed=false
  local paths    pathDisplayed=false",
        entries.len()
    )
}

fn next_commands(agent_id: &str, registered: bool, has_messages: bool) -> Vec<String> {
    if !registered {
        return vec![
            format!("conu ready {agent_id} <display-name> --json"),
            "conu setup --start".to_string(),
            "conu status --json".to_string(),
        ];
    }

    let mut commands = vec![
        format!("conu agents heartbeat {agent_id} --presence ready --json"),
        format!("conu inbox {agent_id} --json"),
        format!("conu history {agent_id} --limit 20 --json"),
    ];

    if has_messages {
        commands.push(format!(
            "conu pull {agent_id} --dir ./agent-inbox --process-ipc --json"
        ));
        commands.push(format!(
            "conu reply {agent_id} --latest --file ./reply.bin --json"
        ));
    } else {
        commands.push(format!(
            "conu wait {agent_id} --process-ipc --timeout-ms 30000 --json"
        ));
    }

    commands.push("conu status --json".to_string());
    commands
}

fn render_inbox_overview_text(records: &[InboxOverviewRecord]) -> String {
    let agents = if records.is_empty() {
        "  none registered yet".to_string()
    } else {
        records
            .iter()
            .map(|record| match record.newest.as_ref() {
                Some(entry) => format!(
                    "  {}  messages {}  newest {}  from {}  bytes {}",
                    record.agent_id,
                    record.message_count,
                    entry.envelope_id,
                    entry.from_agent_id,
                    entry.payload_bytes
                ),
                None => format!(
                    "  {}  messages {}  newest none",
                    record.agent_id, record.message_count
                ),
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU messages inbox

agent inboxes
{agents}

next
  conu inbox
  conu inbox <agent-id>
  conu history <agent-id>
  conu wait <agent-id> --process-ipc --timeout-ms 30000 --json
  conu receive <agent-id> <envelope-id> --output <file>

privacy
  payload view  contents are not displayed by conU
  contentsDisplayed=false"
    )
}

fn render_inbox_text(agent_id: &str, entries: &[InboxEntry]) -> String {
    let messages = if entries.is_empty() {
        "  none delivered yet".to_string()
    } else {
        entries
            .iter()
            .map(|entry| {
                let stream = entry
                    .stream_id
                    .as_deref()
                    .map(|stream_id| format!("  stream {stream_id}"))
                    .unwrap_or_default();
                format!(
                    "  {}  {}{}  from {}  bytes {}  receipt {}",
                    entry.envelope_id,
                    entry.kind,
                    stream,
                    entry.from_agent_id,
                    entry.payload_bytes,
                    entry.receipt_id
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU messages inbox

agent: {agent_id}
messages
{messages}

privacy
  payload view  contents are not displayed by conU"
    )
}

struct MessageHistory {
    entries: Vec<InboxEntry>,
    total_messages: usize,
    truncated_before: usize,
    truncated_after: usize,
}

fn select_history_entries(
    entries: &[InboxEntry],
    after_envelope_id: Option<&str>,
    limit: usize,
) -> Result<MessageHistory, String> {
    let total_messages = entries.len();
    let (candidates, truncated_before) = if let Some(after_envelope_id) = after_envelope_id {
        let Some(position) = entries
            .iter()
            .position(|entry| entry.envelope_id == after_envelope_id)
        else {
            return Err(
                "conU messages history failed\n\nafter envelope was not found in this agent inbox; contentsDisplayed=false"
                    .to_string(),
            );
        };
        (&entries[position + 1..], position + 1)
    } else if entries.len() > limit {
        (&entries[entries.len() - limit..], entries.len() - limit)
    } else {
        (entries, 0)
    };

    let selected_count = candidates.len().min(limit);
    let selected = candidates[..selected_count].to_vec();
    Ok(MessageHistory {
        entries: selected,
        total_messages,
        truncated_before,
        truncated_after: candidates.len().saturating_sub(selected_count),
    })
}

fn render_history_json(
    agent_id: &str,
    history: &MessageHistory,
    parsed: &MessageHistoryArgs,
) -> String {
    let mut entries = history.entries.clone();
    if parsed.newest_first {
        entries.reverse();
    }
    let messages = entries
        .iter()
        .map(render_wait_message_json)
        .collect::<Vec<_>>()
        .join(",\n");
    let messages = if messages.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{messages}\n  ]")
    };

    format!(
        r#"{{
  "agentId": "{}",
  "totalMessages": {},
  "returnedMessages": {},
  "limit": {},
  "afterEnvelopeId": {},
  "newestFirst": {},
  "truncatedBefore": {},
  "truncatedAfter": {},
  "messages": {},
  "contentsDisplayed": false
}}"#,
        json_escape(agent_id),
        history.total_messages,
        history.entries.len(),
        parsed.limit,
        optional_json_string(parsed.after_envelope_id.as_deref()),
        parsed.newest_first,
        history.truncated_before,
        history.truncated_after,
        messages
    )
}

fn render_history_text(
    agent_id: &str,
    history: &MessageHistory,
    parsed: &MessageHistoryArgs,
) -> String {
    let mut entries = history.entries.clone();
    if parsed.newest_first {
        entries.reverse();
    }
    let order = if parsed.newest_first {
        "newest-first"
    } else {
        "oldest-first"
    };
    let after = parsed.after_envelope_id.as_deref().unwrap_or("none");
    let messages = if entries.is_empty() {
        "  none matched".to_string()
    } else {
        entries
            .iter()
            .map(|entry| {
                let stream = entry
                    .stream_id
                    .as_deref()
                    .map(|stream_id| format!("  stream {stream_id}"))
                    .unwrap_or_default();
                format!(
                    "  {}  {}{}  from {}  bytes {}  receipt {}  deliveredAtUnix {}",
                    entry.envelope_id,
                    entry.kind,
                    stream,
                    entry.from_agent_id,
                    entry.payload_bytes,
                    entry.receipt_id,
                    entry.delivered_at_unix
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU messages history

agent: {agent_id}
totalMessages: {}
returnedMessages: {}
limit: {}
after: {after}
order: {order}
truncatedBefore: {}
truncatedAfter: {}
messages
{messages}

privacy
  payload view  contentsDisplayed=false",
        history.total_messages,
        history.entries.len(),
        parsed.limit,
        history.truncated_before,
        history.truncated_after
    )
}

fn reply_target_entry(
    home_override: Option<PathBuf>,
    parsed: &MessageReplyArgs,
) -> Result<InboxEntry, String> {
    let entries = messages::list_agent_inbox(home_override, &parsed.agent_id).map_err(|_| {
        "conU messages reply failed\n\nreply metadata could not be read for this local agent; contentsDisplayed=false".to_string()
    })?;
    if parsed.latest {
        return entries
            .into_iter()
            .rev()
            .find(|entry| entry.to_agent_id == parsed.agent_id.as_str())
            .ok_or_else(|| {
                "conU messages reply failed\n\nlatest reply target was not found in this agent inbox; contentsDisplayed=false"
                    .to_string()
            });
    }

    let Some(envelope_id) = parsed.envelope_id.as_deref() else {
        return Err(
            "conU messages reply failed\n\nreply target was not provided; contentsDisplayed=false"
                .to_string(),
        );
    };

    entries
        .into_iter()
        .find(|entry| {
            entry.envelope_id == envelope_id && entry.to_agent_id == parsed.agent_id.as_str()
        })
        .ok_or_else(|| {
            "conU messages reply failed\n\nreply target was not found in this agent inbox; contentsDisplayed=false"
                .to_string()
        })
}

fn render_receipts_json(receipts: &[DeliveryReceipt]) -> String {
    let receipts = receipts
        .iter()
        .map(|receipt| {
            format!(
                r#"    {{
      "receiptId": "{}",
      "envelopeId": "{}",
      "fromAgentId": "{}",
      "toAgentId": "{}",
      "kind": "{}",
      "streamId": {},
      "status": "{}",
      "payloadBytes": {},
      "deliveredAtUnix": {}
    }}"#,
                json_escape(&receipt.receipt_id),
                json_escape(&receipt.envelope_id),
                json_escape(&receipt.from_agent_id),
                json_escape(&receipt.to_agent_id),
                json_escape(&receipt.kind),
                optional_json_string(receipt.stream_id.as_deref()),
                json_escape(&receipt.status),
                receipt.payload_bytes,
                receipt.delivered_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let receipts = if receipts.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{receipts}\n  ]")
    };

    format!(
        r#"{{
  "receipts": {},
  "contentsDisplayed": false
}}"#,
        receipts
    )
}

fn render_receipts_text(receipts: &[DeliveryReceipt]) -> String {
    let receipts = if receipts.is_empty() {
        "  none recorded yet".to_string()
    } else {
        receipts
            .iter()
            .map(|receipt| {
                let stream = receipt
                    .stream_id
                    .as_deref()
                    .map(|stream_id| format!("  stream {stream_id}"))
                    .unwrap_or_default();
                format!(
                    "  {}  {}  {}{}  {} -> {}  bytes {}",
                    receipt.receipt_id,
                    receipt.status,
                    receipt.kind,
                    stream,
                    receipt.from_agent_id,
                    receipt.to_agent_id,
                    receipt.payload_bytes
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU messages receipts

receipts
{receipts}

privacy
  payload view  contents are not displayed by conU"
    )
}

struct MessageSendArgs {
    from_agent_id: String,
    to_agent_id: String,
    peer_node_id: Option<String>,
    payload_input: Option<MessagePayloadInput>,
    json: bool,
}

enum MessagePayloadInput {
    Stdin,
    File(PathBuf),
}

fn read_message_input_payload(
    input: Option<&MessagePayloadInput>,
    stdin_payload: Vec<u8>,
) -> Result<Vec<u8>, CliOutput> {
    match input {
        Some(MessagePayloadInput::Stdin) => {
            if stdin_payload.is_empty() {
                Err(CliOutput::failure(2, "stdin payload is empty"))
            } else {
                Ok(stdin_payload)
            }
        }
        Some(MessagePayloadInput::File(path)) => read_message_payload_file(path).map_err(|error| {
            CliOutput::failure(2, format!("payload file could not be read\n\n{error}"))
        }),
        None => Err(CliOutput::failure(2, render_messages_usage())),
    }
}

fn read_message_payload_file(path: &Path) -> Result<Vec<u8>, String> {
    if path.as_os_str().is_empty() {
        return Err(
            "payload file path is empty; pathDisplayed=false contentsDisplayed=false".to_string(),
        );
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "payload file is not readable; pathDisplayed=false contentsDisplayed=false")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(
            "payload input is not a regular file; pathDisplayed=false contentsDisplayed=false"
                .to_string(),
        );
    }
    if metadata.len() == 0 {
        return Err(
            "payload file is empty; pathDisplayed=false contentsDisplayed=false".to_string(),
        );
    }
    if metadata.len() > MAX_CLI_PAYLOAD_FILE_BYTES {
        return Err(format!(
            "payload file exceeds {MAX_CLI_PAYLOAD_FILE_BYTES} bytes; pathDisplayed=false contentsDisplayed=false"
        ));
    }

    let mut file = fs::File::open(path)
        .map_err(|_| "payload file is not readable; pathDisplayed=false contentsDisplayed=false")?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| "payload file is not readable; pathDisplayed=false contentsDisplayed=false")?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_CLI_PAYLOAD_FILE_BYTES {
        return Err("payload file changed before it could be read; pathDisplayed=false contentsDisplayed=false".to_string());
    }

    let mut payload = Vec::new();
    let limit = MAX_CLI_PAYLOAD_FILE_BYTES.saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut payload)
        .map_err(|_| "payload file is not readable; pathDisplayed=false contentsDisplayed=false")?;
    if payload.is_empty() {
        return Err(
            "payload file is empty; pathDisplayed=false contentsDisplayed=false".to_string(),
        );
    }
    if payload.len() as u64 > MAX_CLI_PAYLOAD_FILE_BYTES {
        return Err(format!(
            "payload file exceeds {MAX_CLI_PAYLOAD_FILE_BYTES} bytes; pathDisplayed=false contentsDisplayed=false"
        ));
    }
    Ok(payload)
}

struct MessageInboxArgs {
    agent_id: Option<String>,
    json: bool,
}

struct InboxOverviewRecord {
    agent_id: String,
    message_count: usize,
    newest: Option<InboxEntry>,
}

struct MessageHistoryArgs {
    agent_id: String,
    after_envelope_id: Option<String>,
    limit: usize,
    newest_first: bool,
    json: bool,
}

struct AgentNextArgs {
    agent_id: String,
    json: bool,
}

struct MessageReplyArgs {
    agent_id: String,
    envelope_id: Option<String>,
    latest: bool,
    payload_input: Option<MessagePayloadInput>,
    json: bool,
}

struct MessageWaitArgs {
    agent_id: String,
    after_envelope_id: Option<String>,
    timeout_ms: u64,
    interval_ms: u64,
    process_ipc: bool,
    json: bool,
}

struct MessageReceiveArgs {
    agent_id: String,
    envelope_id: Option<String>,
    output_path: PathBuf,
    latest: bool,
    after_envelope_id: Option<String>,
    timeout_ms: u64,
    interval_ms: u64,
    process_ipc: bool,
    json: bool,
}

struct MessagePullArgs {
    agent_id: String,
    output_dir: PathBuf,
    after_envelope_id: Option<String>,
    timeout_ms: u64,
    interval_ms: u64,
    process_ipc: bool,
    json: bool,
}

fn parse_message_send_args(args: &[String]) -> Result<MessageSendArgs, CliOutput> {
    let mut json = false;
    let mut payload_input = None;
    let mut peer_node_id = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--stdin" => set_payload_input(&mut payload_input, MessagePayloadInput::Stdin)?,
            "--file" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                set_payload_input(
                    &mut payload_input,
                    MessagePayloadInput::File(PathBuf::from(value)),
                )?;
                index += 1;
            }
            "--peer" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                peer_node_id = Some(value.clone());
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_messages_usage()));
    }

    Ok(MessageSendArgs {
        from_agent_id: positional.remove(0),
        to_agent_id: positional.remove(0),
        peer_node_id,
        payload_input,
        json,
    })
}

fn parse_message_inbox_args(args: &[String]) -> Result<MessageInboxArgs, CliOutput> {
    let mut json = false;
    let mut agent_id = None;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                }
                agent_id = Some(value.to_string());
            }
        }
    }

    Ok(MessageInboxArgs { agent_id, json })
}

fn parse_message_history_args(args: &[String]) -> Result<MessageHistoryArgs, CliOutput> {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 1_000;

    let mut json = false;
    let mut newest_first = false;
    let mut after_envelope_id = None;
    let mut limit = DEFAULT_LIMIT;
    let mut agent_id = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--newest-first" => newest_first = true,
            "--after" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                after_envelope_id = Some(value.clone());
                index += 1;
            }
            "--limit" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                limit = match value.parse::<usize>() {
                    Ok(value) if (1..=MAX_LIMIT).contains(&value) => value,
                    _ => return Err(CliOutput::failure(2, render_messages_usage())),
                };
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                }
                agent_id = Some(value.to_string());
            }
        }
        index += 1;
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(2, render_messages_usage()));
    };

    Ok(MessageHistoryArgs {
        agent_id,
        after_envelope_id,
        limit,
        newest_first,
        json,
    })
}

fn parse_agent_next_args(args: &[String]) -> Result<AgentNextArgs, CliOutput> {
    let mut json = false;
    let mut agent_id = None;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(2, render_next_usage()));
                }
                agent_id = Some(value.to_string());
            }
        }
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(2, render_next_usage()));
    };

    Ok(AgentNextArgs { agent_id, json })
}

fn parse_message_reply_args(args: &[String]) -> Result<MessageReplyArgs, CliOutput> {
    let mut json = false;
    let mut latest = false;
    let mut payload_input = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--latest" => {
                if latest {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                }
                latest = true;
            }
            "--stdin" => set_payload_input(&mut payload_input, MessagePayloadInput::Stdin)?,
            "--file" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                set_payload_input(
                    &mut payload_input,
                    MessagePayloadInput::File(PathBuf::from(value)),
                )?;
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if latest && positional.len() != 1 {
        return Err(CliOutput::failure(2, render_messages_usage()));
    }
    if !latest && positional.len() != 2 {
        return Err(CliOutput::failure(2, render_messages_usage()));
    }

    Ok(MessageReplyArgs {
        agent_id: positional.remove(0),
        envelope_id: if latest {
            None
        } else {
            Some(positional.remove(0))
        },
        latest,
        payload_input,
        json,
    })
}

fn set_payload_input(
    target: &mut Option<MessagePayloadInput>,
    value: MessagePayloadInput,
) -> Result<(), CliOutput> {
    if target.is_some() {
        return Err(CliOutput::failure(
            2,
            "choose exactly one of --stdin or --file; pathDisplayed=false contentsDisplayed=false",
        ));
    }
    *target = Some(value);
    Ok(())
}

fn parse_message_wait_args(args: &[String]) -> Result<MessageWaitArgs, CliOutput> {
    const MAX_TIMEOUT_MS: u64 = 300_000;
    const MAX_INTERVAL_MS: u64 = 10_000;

    let mut json = false;
    let mut process_ipc = false;
    let mut timeout_ms = 30_000;
    let mut interval_ms = 250;
    let mut after_envelope_id = None;
    let mut agent_id = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--process-ipc" => process_ipc = true,
            "--after" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                after_envelope_id = Some(value.clone());
                index += 1;
            }
            "--timeout-ms" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                timeout_ms = match value.parse::<u64>() {
                    Ok(value) if value <= MAX_TIMEOUT_MS => value,
                    _ => return Err(CliOutput::failure(2, render_messages_usage())),
                };
                index += 1;
            }
            "--interval-ms" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                interval_ms = match value.parse::<u64>() {
                    Ok(value) if (1..=MAX_INTERVAL_MS).contains(&value) => value,
                    _ => return Err(CliOutput::failure(2, render_messages_usage())),
                };
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                }
                agent_id = Some(value.to_string());
            }
        }
        index += 1;
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(2, render_messages_usage()));
    };

    Ok(MessageWaitArgs {
        agent_id,
        after_envelope_id,
        timeout_ms,
        interval_ms,
        process_ipc,
        json,
    })
}

fn parse_message_receive_args(args: &[String]) -> Result<MessageReceiveArgs, CliOutput> {
    const MAX_TIMEOUT_MS: u64 = 300_000;
    const MAX_INTERVAL_MS: u64 = 10_000;

    let mut json = false;
    let mut latest = false;
    let mut process_ipc = false;
    let mut timeout_ms = 30_000;
    let mut interval_ms = 250;
    let mut after_envelope_id = None;
    let mut wait_option_used = false;
    let mut output_path = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--latest" => latest = true,
            "--process-ipc" => {
                process_ipc = true;
                wait_option_used = true;
            }
            "--after" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                after_envelope_id = Some(value.clone());
                wait_option_used = true;
                index += 1;
            }
            "--timeout-ms" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                timeout_ms = match value.parse::<u64>() {
                    Ok(value) if value <= MAX_TIMEOUT_MS => value,
                    _ => return Err(CliOutput::failure(2, render_messages_usage())),
                };
                wait_option_used = true;
                index += 1;
            }
            "--interval-ms" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                interval_ms = match value.parse::<u64>() {
                    Ok(value) if (1..=MAX_INTERVAL_MS).contains(&value) => value,
                    _ => return Err(CliOutput::failure(2, render_messages_usage())),
                };
                wait_option_used = true;
                index += 1;
            }
            "--output" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                output_path = Some(PathBuf::from(value));
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if !latest && wait_option_used {
        return Err(CliOutput::failure(2, render_messages_usage()));
    }
    if latest && positional.len() != 1 {
        return Err(CliOutput::failure(2, render_messages_usage()));
    }
    if !latest && positional.len() != 2 {
        return Err(CliOutput::failure(2, render_messages_usage()));
    }
    let Some(output_path) = output_path else {
        return Err(CliOutput::failure(2, render_messages_usage()));
    };

    let agent_id = positional.remove(0);
    let envelope_id = if latest {
        None
    } else {
        Some(positional.remove(0))
    };

    Ok(MessageReceiveArgs {
        agent_id,
        envelope_id,
        output_path,
        latest,
        after_envelope_id,
        timeout_ms,
        interval_ms,
        process_ipc,
        json,
    })
}

fn parse_message_pull_args(args: &[String]) -> Result<MessagePullArgs, CliOutput> {
    const MAX_TIMEOUT_MS: u64 = 300_000;
    const MAX_INTERVAL_MS: u64 = 10_000;

    let mut json = false;
    let mut process_ipc = false;
    let mut timeout_ms = 30_000;
    let mut interval_ms = 250;
    let mut after_envelope_id = None;
    let mut output_dir = None;
    let mut agent_id = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--process-ipc" => process_ipc = true,
            "--after" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                after_envelope_id = Some(value.clone());
                index += 1;
            }
            "--timeout-ms" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                timeout_ms = match value.parse::<u64>() {
                    Ok(value) if value <= MAX_TIMEOUT_MS => value,
                    _ => return Err(CliOutput::failure(2, render_messages_usage())),
                };
                index += 1;
            }
            "--interval-ms" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                interval_ms = match value.parse::<u64>() {
                    Ok(value) if (1..=MAX_INTERVAL_MS).contains(&value) => value,
                    _ => return Err(CliOutput::failure(2, render_messages_usage())),
                };
                index += 1;
            }
            "--dir" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                };
                output_dir = Some(PathBuf::from(value));
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if agent_id.is_some() {
                    return Err(CliOutput::failure(2, render_messages_usage()));
                }
                agent_id = Some(value.to_string());
            }
        }
        index += 1;
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(2, render_messages_usage()));
    };
    let Some(output_dir) = output_dir else {
        return Err(CliOutput::failure(2, render_messages_usage()));
    };

    Ok(MessagePullArgs {
        agent_id,
        output_dir,
        after_envelope_id,
        timeout_ms,
        interval_ms,
        process_ipc,
        json,
    })
}

fn write_message_receive_output(path: &Path, payload: &[u8]) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err(
            "output path is empty; pathDisplayed=false contentsDisplayed=false".to_string(),
        );
    }
    if path.exists() {
        return Err(
            "output file already exists; pathDisplayed=false contentsDisplayed=false".to_string(),
        );
    }
    if path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty() && !parent.exists())
    {
        return Err(
            "output directory does not exist; pathDisplayed=false contentsDisplayed=false"
                .to_string(),
        );
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "could not create output file; pathDisplayed=false contentsDisplayed=false")?;
    file.write_all(payload)
        .map_err(|_| "could not write output file; pathDisplayed=false contentsDisplayed=false")?;
    Ok(())
}

fn render_messages_usage() -> String {
    r"usage:
  conu messages send <from-agent> <to-agent> (--stdin|--file <path>) [--json]
  conu messages send <from-agent> <to-agent> --peer <peer-node-id> (--stdin|--file <path>) [--json]
  conu messages inbox [agent-id] [--json]
  conu messages history <agent-id> [--after <envelope-id>] [--limit <count>] [--newest-first] [--json]
  conu messages reply <agent-id> <envelope-id> (--stdin|--file <path>) [--json]
  conu messages reply <agent-id> --latest (--stdin|--file <path>) [--json]
  conu messages wait <agent-id> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu messages receive <agent-id> <envelope-id> --output <file> [--json]
  conu messages receive <agent-id> --latest --output <file> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu messages pull <agent-id> --dir <directory> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu messages receipts [--json]"
        .to_string()
}

fn render_send_usage() -> String {
    r"usage:
  conu send <from-agent> <to-agent> (--stdin|--file <path>) [--json]
  conu send <from-agent> <to-agent> --peer <peer-node-id> (--stdin|--file <path>) [--json]

example:
  echo <message> | conu send agent.alpha agent.beta --stdin
  conu send agent.alpha agent.beta --file ./message.bin --json

privacy:
  message bytes are read from stdin or a local file
  stdout shows metadata only
  pathDisplayed=false contentsDisplayed=false"
        .to_string()
}

fn render_messages_send_usage() -> String {
    render_send_usage().replace("conu send", "conu messages send")
}

fn render_inbox_usage() -> String {
    r"usage:
  conu inbox [agent-id] [--json]

shows:
  all local agent inbox counts when no agent is passed
  delivered message metadata for one local agent when an agent is passed
  envelope ids, sender ids, byte counts, and delivery times only
  contentsDisplayed=false"
        .to_string()
}

fn render_messages_inbox_usage() -> String {
    render_inbox_usage().replace("conu inbox", "conu messages inbox")
}

fn render_next_usage() -> String {
    r"usage:
  conu next <agent-id> [--json]

example:
  conu next agent.beta --json

shows:
  metadata-only readiness, inbox count, newest message metadata, and safe next commands for one agent
  message contents are never printed
  pathDisplayed=false contentsDisplayed=false"
        .to_string()
}

fn render_history_usage() -> String {
    r"usage:
  conu history <agent-id> [--after <envelope-id>] [--limit <count>] [--newest-first] [--json]

shows:
  persisted inbox history for one local agent
  message contents are never printed
  contentsDisplayed=false"
        .to_string()
}

fn render_messages_history_usage() -> String {
    render_history_usage().replace("conu history", "conu messages history")
}

fn render_wait_usage() -> String {
    r"usage:
  conu wait <agent-id> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]

example:
  conu wait agent.beta --process-ipc --timeout-ms 30000 --json"
        .to_string()
}

fn render_messages_wait_usage() -> String {
    render_wait_usage().replace("conu wait", "conu messages wait")
}

fn render_receive_usage() -> String {
    r"usage:
  conu receive <agent-id> <envelope-id> --output <file> [--json]
  conu receive <agent-id> --latest --output <file> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]

example:
  conu receive agent.beta --latest --output message.bin --process-ipc --json

purpose:
  write addressed local payload bytes to a new file
  --latest waits for the newest available message, or the next one after --after
  stdout still shows metadata only
  pathDisplayed=false contentsDisplayed=false"
        .to_string()
}

fn render_pull_usage() -> String {
    r"usage:
  conu pull <agent-id> --dir <directory> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]

example:
  conu pull agent.beta --dir ./agent-inbox --process-ipc --json

purpose:
  wait for the newest addressed payload, or the next one after --after
  write bytes to <directory>/conu-message-<envelope-id>.bin
  stdout still shows metadata and the generated file name only
  outputDirDisplayed=false pathDisplayed=false contentsDisplayed=false"
        .to_string()
}

fn render_messages_receive_usage() -> String {
    render_receive_usage().replace("conu receive", "conu messages receive")
}

fn render_messages_pull_usage() -> String {
    render_pull_usage().replace("conu pull", "conu messages pull")
}

fn render_reply_usage() -> String {
    r"usage:
  conu reply <agent-id> <envelope-id> (--stdin|--file <path>) [--json]
  conu reply <agent-id> --latest (--stdin|--file <path>) [--json]

example:
  echo <reply> | conu reply agent.beta <envelope-id> --stdin
  conu reply agent.beta --latest --file ./reply.bin --json"
        .to_string()
}

fn render_messages_reply_usage() -> String {
    render_reply_usage().replace("conu reply", "conu messages reply")
}

fn render_chat_usage() -> String {
    r"usage:
  conu chat
  conu chat <from-agent> <to-agent>
  conu chat <from-agent> <to-agent> --stdin [--json]
  conu chat <from-agent> <to-agent> --file <path> [--json]
  conu chat <from-agent> <to-agent> --peer <peer-node-id> --stdin [--json]
  conu chat <from-agent> <to-agent> --peer <peer-node-id> --file <path> [--json]

interactive:
  run plain `conu chat` in a terminal to enter sender, receiver, optional peer node, and one message.
  run `conu chat <from-agent> <to-agent>` in a terminal to prompt for one local message.

privacy:
  interactive chat sends one message through the same opaque inbox path
  message bytes are not printed by conU
  contentsDisplayed=false"
        .to_string()
}

fn render_streams(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_streams_usage()),
        Some("open") if is_help_request(&args[1..]) => CliOutput::success(render_streams_usage()),
        Some("write") if is_help_request(&args[1..]) => CliOutput::success(render_streams_usage()),
        Some("close") if is_help_request(&args[1..]) => CliOutput::success(render_streams_usage()),
        Some("open") => render_stream_open(&args[1..], home_override),
        Some("write") => render_stream_write(&args[1..], home_override, stdin_payload),
        Some("close") => render_stream_close(&args[1..], home_override),
        _ => render_streams_list(args, home_override),
    }
}

fn render_stream_open(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_stream_open_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    match streams::open_stream(
        home_override,
        &parsed.from_agent_id,
        &parsed.to_agent_id,
        &parsed.kind,
    ) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_stream_json(&report.stream, "opened"))
            } else {
                CliOutput::success(render_stream_open_text(&report.stream))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU streams open failed\n\n{error}")),
    }
}

fn render_stream_write(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_stream_io_args(args, "write") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.stdin {
        return CliOutput::failure(2, "usage: conu streams write <stream-id> --stdin [--json]");
    }
    if stdin_payload.is_empty() {
        return CliOutput::failure(2, "stdin payload is empty");
    }

    match streams::write_stream(
        home_override,
        &parsed.stream_id,
        OpaquePayload::from_bytes(stdin_payload),
    ) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_stream_event_json(&report.stream, &report.event))
            } else {
                CliOutput::success(render_stream_write_text(&report.stream, &report.event))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU streams write failed\n\n{error}")),
    }
}

fn render_stream_close(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_stream_io_args(args, "close") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    match streams::close_stream(home_override, &parsed.stream_id) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_stream_event_json(&report.stream, &report.event))
            } else {
                CliOutput::success(render_stream_close_text(&report.stream))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU streams close failed\n\n{error}")),
    }
}

fn render_streams_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let streams = match streams::list_streams(home_override) {
        Ok(streams) => streams,
        Err(error) => return CliOutput::failure(1, format!("conU streams failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_streams_json(&streams)),
        Ok(false) => CliOutput::success(render_streams_text(&streams)),
        Err(error) => error,
    }
}

fn render_streams_json(streams: &[StreamRecord]) -> String {
    let items = streams
        .iter()
        .map(|stream| {
            format!(
                r#"    {{
      "streamId": "{}",
      "fromAgentId": "{}",
      "toAgentId": "{}",
      "kind": "{}",
      "state": "{}",
      "route": "{}",
      "chunksWritten": {},
      "bytesWritten": {},
      "backpressureWindow": {}
    }}"#,
                json_escape(&stream.stream_id),
                json_escape(&stream.from_agent_id),
                json_escape(&stream.to_agent_id),
                json_escape(&stream.kind),
                stream.state.as_str(),
                json_escape(&stream.route),
                stream.chunks_written,
                stream.bytes_written,
                stream.backpressure_window
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let streams_json = if items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{items}\n  ]")
    };

    format!(
        r#"{{
  "streams": {},
  "contentsDisplayed": false
}}"#,
        streams_json
    )
}

fn render_streams_text(streams: &[StreamRecord]) -> String {
    let lines = if streams.is_empty() {
        "  none opened yet".to_string()
    } else {
        streams
            .iter()
            .map(|stream| {
                format!(
                    "  {}  {} -> {}  {}  chunks {}  bytes {}",
                    stream.stream_id,
                    stream.from_agent_id,
                    stream.to_agent_id,
                    stream.state.as_str(),
                    stream.chunks_written,
                    stream.bytes_written
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU streams

streams
{lines}

privacy
  payload view  contents are not displayed by conU

next
  conu streams open <from-agent> <to-agent>"
    )
}

fn render_stream_open_text(stream: &StreamRecord) -> String {
    format!(
        r"conU streams open

status: opened
stream: {}
from: {}
to: {}
kind: {}
route: {}
backpressure window: {}

privacy
  payload view  contents are not displayed by conU",
        stream.stream_id,
        stream.from_agent_id,
        stream.to_agent_id,
        stream.kind,
        stream.route,
        stream.backpressure_window
    )
}

fn render_stream_write_text(stream: &StreamRecord, event: &StreamEvent) -> String {
    format!(
        r"conU streams write

status: chunk recorded
stream: {}
bytes: {}
chunks: {}
total bytes: {}

privacy
  payload view  contents are not displayed by conU",
        stream.stream_id, event.payload_bytes, stream.chunks_written, stream.bytes_written
    )
}

fn render_stream_close_text(stream: &StreamRecord) -> String {
    format!(
        r"conU streams close

status: closed
stream: {}
chunks: {}
bytes: {}

privacy
  payload view  contents are not displayed by conU",
        stream.stream_id, stream.chunks_written, stream.bytes_written
    )
}

fn render_stream_json(stream: &StreamRecord, status: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "streamId": "{}",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "kind": "{}",
  "state": "{}",
  "route": "{}",
  "chunksWritten": {},
  "bytesWritten": {},
  "backpressureWindow": {},
  "contentsDisplayed": false
}}"#,
        status,
        json_escape(&stream.stream_id),
        json_escape(&stream.from_agent_id),
        json_escape(&stream.to_agent_id),
        json_escape(&stream.kind),
        stream.state.as_str(),
        json_escape(&stream.route),
        stream.chunks_written,
        stream.bytes_written,
        stream.backpressure_window
    )
}

fn render_stream_event_json(stream: &StreamRecord, event: &StreamEvent) -> String {
    format!(
        r#"{{
  "status": "{}",
  "streamId": "{}",
  "eventId": "{}",
  "payloadBytes": {},
  "chunksWritten": {},
  "bytesWritten": {},
  "contentsDisplayed": false
}}"#,
        json_escape(&event.event_type),
        json_escape(&stream.stream_id),
        json_escape(&event.event_id),
        event.payload_bytes,
        stream.chunks_written,
        stream.bytes_written
    )
}

struct StreamOpenArgs {
    from_agent_id: String,
    to_agent_id: String,
    kind: String,
    json: bool,
}

struct StreamIoArgs {
    stream_id: String,
    stdin: bool,
    json: bool,
}

fn parse_stream_open_args(args: &[String]) -> Result<StreamOpenArgs, CliOutput> {
    let mut json = false;
    let mut kind = "message".to_string();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--kind" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_streams_usage()));
                };
                kind = value.clone();
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_streams_usage()));
    }

    Ok(StreamOpenArgs {
        from_agent_id: positional[0].clone(),
        to_agent_id: positional[1].clone(),
        kind,
        json,
    })
}

fn parse_stream_io_args(args: &[String], command: &'static str) -> Result<StreamIoArgs, CliOutput> {
    let mut json = false;
    let mut stdin = false;
    let mut stream_id = None;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--stdin" => stdin = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if stream_id.is_some() {
                    return Err(CliOutput::failure(2, render_streams_usage()));
                }
                stream_id = Some(value.to_string());
            }
        }
    }

    let Some(stream_id) = stream_id else {
        return Err(CliOutput::failure(
            2,
            format!("usage: conu streams {command} <stream-id> [--stdin] [--json]"),
        ));
    };

    Ok(StreamIoArgs {
        stream_id,
        stdin,
        json,
    })
}

fn render_streams_usage() -> String {
    r"usage:
  conu streams [--json]
  conu streams open <from-agent> <to-agent> [--kind <kind>] [--json]
  conu streams write <stream-id> --stdin [--json]
  conu streams close <stream-id> [--json]"
        .to_string()
}

fn render_rooms(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_rooms_usage()),
        Some("create") if is_help_request(&args[1..]) => CliOutput::success(render_rooms_usage()),
        Some("join") if is_help_request(&args[1..]) => CliOutput::success(render_rooms_usage()),
        Some("publish") if is_help_request(&args[1..]) => CliOutput::success(render_rooms_usage()),
        Some("events") if is_help_request(&args[1..]) => CliOutput::success(render_rooms_usage()),
        Some("policy") if is_help_request(&args[1..]) => CliOutput::success(render_rooms_usage()),
        Some("create") => render_room_create(&args[1..], home_override),
        Some("join") => render_room_join(&args[1..], home_override),
        Some("publish") => render_room_publish(&args[1..], home_override, stdin_payload),
        Some("events") => render_room_events(&args[1..], home_override),
        Some("policy") => render_room_policy(&args[1..], home_override),
        _ => render_rooms_list(args, home_override),
    }
}

fn render_room_create(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_room_create_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match rooms::create_room(
        home_override,
        &parsed.room_id,
        &parsed.display_name,
        &parsed.agent_id,
    ) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_room_json(&report.room, "created"))
            } else {
                CliOutput::success(render_room_created_text(&report.room))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU rooms create failed\n\n{error}")),
    }
}

fn render_room_join(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_room_join_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match rooms::join_room(home_override, &parsed.room_id, &parsed.agent_id) {
        Ok(report) => {
            let status = if report.joined {
                "joined"
            } else {
                "already_joined"
            };
            if parsed.json {
                CliOutput::success(render_room_json(&report.room, status))
            } else {
                CliOutput::success(render_room_join_text(
                    &report.room,
                    status,
                    &parsed.agent_id,
                ))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU rooms join failed\n\n{error}")),
    }
}

fn render_room_publish(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_room_publish_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.stdin {
        return CliOutput::failure(
            2,
            "usage: conu rooms publish <room-id> <from-agent> <topic> --stdin [--json]",
        );
    }
    if stdin_payload.is_empty() {
        return CliOutput::failure(2, "stdin payload is empty");
    }

    match rooms::publish_room_event(
        home_override,
        &parsed.room_id,
        &parsed.from_agent_id,
        &parsed.topic,
        OpaquePayload::from_bytes(stdin_payload),
    ) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_room_event_json(
                    &report.room,
                    &report.event,
                    report.local_deliveries,
                    report.remote_deliveries,
                ))
            } else {
                CliOutput::success(render_room_publish_text(
                    &report.room,
                    &report.event,
                    report.local_deliveries,
                    report.remote_deliveries,
                ))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU rooms publish failed\n\n{error}")),
    }
}

fn render_rooms_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let rooms = match rooms::list_rooms(home_override) {
        Ok(rooms) => rooms,
        Err(error) => return CliOutput::failure(1, format!("conU rooms failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_rooms_json(&rooms)),
        Ok(false) => CliOutput::success(render_rooms_text(&rooms)),
        Err(error) => error,
    }
}

fn render_room_events(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let events = match rooms::list_room_events(home_override) {
        Ok(events) => events,
        Err(error) => return CliOutput::failure(1, format!("conU rooms events failed\n\n{error}")),
    };

    if json {
        CliOutput::success(render_room_events_json(&events))
    } else {
        CliOutput::success(render_room_events_text(&events))
    }
}

fn render_room_policy(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_room_policy_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match (&parsed.room_id, &parsed.agent_id, &parsed.topic) {
        (Some(room_id), Some(agent_id), Some(topic)) if parsed.update.has_changes() => {
            let record = match rooms::set_room_topic_policy(
                home_override,
                room_id,
                agent_id,
                topic,
                parsed.update,
            ) {
                Ok(record) => record,
                Err(error) => {
                    return CliOutput::failure(1, format!("conU rooms policy failed\n\n{error}"));
                }
            };
            if parsed.json {
                CliOutput::success(render_room_policy_json(&record, "updated"))
            } else {
                CliOutput::success(render_room_policy_text(&record, "updated"))
            }
        }
        (Some(room_id), Some(agent_id), Some(topic)) => {
            let record = match rooms::room_topic_policy(home_override, room_id, agent_id, topic) {
                Ok(Some(record)) => record,
                Ok(None) => {
                    return CliOutput::failure(
                        1,
                        "conU rooms policy failed\n\nroom topic policy is not configured",
                    );
                }
                Err(error) => {
                    return CliOutput::failure(1, format!("conU rooms policy failed\n\n{error}"));
                }
            };
            if parsed.json {
                CliOutput::success(render_room_policy_json(&record, "read"))
            } else {
                CliOutput::success(render_room_policy_text(&record, "read"))
            }
        }
        (None, None, None) => {
            let policies = match rooms::list_room_topic_policies(home_override) {
                Ok(policies) => policies,
                Err(error) => {
                    return CliOutput::failure(1, format!("conU rooms policy failed\n\n{error}"));
                }
            };
            if parsed.json {
                CliOutput::success(render_room_policies_json(&policies))
            } else {
                CliOutput::success(render_room_policies_text(&policies))
            }
        }
        _ => CliOutput::failure(2, render_rooms_usage()),
    }
}

fn render_rooms_json(rooms: &[RoomRecord]) -> String {
    let items = rooms
        .iter()
        .map(room_json_object)
        .collect::<Vec<_>>()
        .join(",\n");
    let rooms_json = if items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{items}\n  ]")
    };

    format!(
        r#"{{
  "rooms": {},
  "contentsDisplayed": false
}}"#,
        rooms_json
    )
}

fn render_room_events_json(events: &[RoomEvent]) -> String {
    let items = events
        .iter()
        .map(room_event_json_object)
        .collect::<Vec<_>>()
        .join(",\n");
    let events_json = if items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{items}\n  ]")
    };

    format!(
        r#"{{
  "events": {},
  "contentsDisplayed": false
}}"#,
        events_json
    )
}

fn render_rooms_text(rooms: &[RoomRecord]) -> String {
    let lines = if rooms.is_empty() {
        "  none created yet".to_string()
    } else {
        rooms
            .iter()
            .map(|room| {
                format!(
                    "  {}  {}  participants {}  topics {}  events {}  bytes {}",
                    room.room_id,
                    room.state.as_str(),
                    room.participants.len(),
                    room.topics.len(),
                    room.events_published,
                    room.bytes_published
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU rooms

rooms
{lines}

privacy
  payload view  contents are not displayed by conU

next
  conu rooms create <room-id> <display-name> --agent <agent-id>"
    )
}

fn render_room_events_text(events: &[RoomEvent]) -> String {
    let lines = if events.is_empty() {
        "  none published yet".to_string()
    } else {
        events
            .iter()
            .map(|event| {
                format!(
                    "  {}  room {}  topic {}  from {}  bytes {}  route {}",
                    event.event_id,
                    event.room_id,
                    event.topic,
                    event.from_agent_id,
                    event.payload_bytes,
                    event.route
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU rooms events

events
{lines}

privacy
  payload view  contents are not displayed by conU"
    )
}

fn render_room_created_text(room: &RoomRecord) -> String {
    format!(
        r"conU rooms create

status: created
room: {}
name: {}
created by: {}
participants: {}

privacy
  payload view  contents are not displayed by conU",
        room.room_id,
        room.display_name,
        room.created_by_agent_id,
        room.participants.len()
    )
}

fn render_room_join_text(room: &RoomRecord, status: &str, agent_id: &str) -> String {
    format!(
        r"conU rooms join

status: {status}
room: {}
agent: {agent_id}
participants: {}

privacy
  payload view  contents are not displayed by conU",
        room.room_id,
        room.participants.len()
    )
}

fn render_room_publish_text(
    room: &RoomRecord,
    event: &RoomEvent,
    local_deliveries: usize,
    remote_deliveries: usize,
) -> String {
    format!(
        r"conU rooms publish

status: published
room: {}
topic: {}
from: {}
event: {}
route: {}
bytes: {}
room events: {}
local deliveries: {}
remote deliveries: {}

privacy
  payload view  contents are not displayed by conU",
        room.room_id,
        event.topic,
        event.from_agent_id,
        event.event_id,
        event.route,
        event.payload_bytes,
        room.events_published,
        local_deliveries,
        remote_deliveries
    )
}

fn render_room_json(room: &RoomRecord, status: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "participants": {},
  "room": {},
  "contentsDisplayed": false
}}"#,
        json_escape(status),
        room.participants.len(),
        room_json_object(room)
    )
}

fn render_room_event_json(
    room: &RoomRecord,
    event: &RoomEvent,
    local_deliveries: usize,
    remote_deliveries: usize,
) -> String {
    format!(
        r#"{{
  "status": "published",
  "roomId": "{}",
  "eventsPublished": {},
  "bytesPublished": {},
  "localDeliveries": {},
  "remoteDeliveries": {},
  "event": {},
  "contentsDisplayed": false
}}"#,
        json_escape(&room.room_id),
        room.events_published,
        room.bytes_published,
        local_deliveries,
        remote_deliveries,
        room_event_json_object(event)
    )
}

fn render_room_policy_json(record: &RoomTopicPolicyRecord, status: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "roomId": "{}",
  "agentId": "{}",
  "topic": "{}",
  "policy": {{
    "publish": {},
    "subscribe": {}
  }},
  "updatedAtUnix": {},
  "contentsDisplayed": false
}}"#,
        json_escape(status),
        json_escape(&record.room_id),
        json_escape(&record.agent_id),
        json_escape(&record.topic),
        record.publish,
        record.subscribe,
        record.updated_at_unix
    )
}

fn render_room_policy_text(record: &RoomTopicPolicyRecord, status: &str) -> String {
    format!(
        r"conU rooms policy

status: {}
room: {}
agent: {}
topic: {}
publish: {}
subscribe: {}

privacy
  payload view  contents are not displayed by conU",
        status, record.room_id, record.agent_id, record.topic, record.publish, record.subscribe
    )
}

fn render_room_policies_json(policies: &[RoomTopicPolicyRecord]) -> String {
    let items = policies
        .iter()
        .map(|policy| {
            format!(
                r#"    {{
      "roomId": "{}",
      "agentId": "{}",
      "topic": "{}",
      "publish": {},
      "subscribe": {},
      "updatedAtUnix": {}
    }}"#,
                json_escape(&policy.room_id),
                json_escape(&policy.agent_id),
                json_escape(&policy.topic),
                policy.publish,
                policy.subscribe,
                policy.updated_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let policies = if items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{items}\n  ]")
    };

    format!(
        r#"{{
  "topicPolicies": {},
  "contentsDisplayed": false
}}"#,
        policies
    )
}

fn render_room_policies_text(policies: &[RoomTopicPolicyRecord]) -> String {
    let rows = if policies.is_empty() {
        "  no room topic policies configured".to_string()
    } else {
        policies
            .iter()
            .map(|policy| {
                format!(
                    "  {}  topic={} agent={} publish={} subscribe={}",
                    policy.room_id, policy.topic, policy.agent_id, policy.publish, policy.subscribe
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU rooms policy

topic policies
{rows}

next
  conu rooms policy <room-id> <agent-id> <topic> --publish true --subscribe true"
    )
}

fn room_json_object(room: &RoomRecord) -> String {
    let participants = room
        .participants
        .iter()
        .map(|participant| {
            format!(
                r#"        {{
          "agentId": "{}",
          "scope": "{}",
          "joinedAtUnix": {}
        }}"#,
                json_escape(&participant.agent_id),
                participant.scope.as_str(),
                participant.joined_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let participants = if participants.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{participants}\n      ]")
    };
    let topics = room
        .topics
        .iter()
        .map(|topic| json_string(topic))
        .collect::<Vec<_>>()
        .join(", ");
    let topics = if topics.is_empty() {
        "[]".to_string()
    } else {
        format!("[{topics}]")
    };

    format!(
        r#"    {{
      "roomId": "{}",
      "displayName": "{}",
      "state": "{}",
      "createdByAgentId": "{}",
      "participants": {},
      "topics": {},
      "eventsPublished": {},
      "bytesPublished": {},
      "createdAtUnix": {},
      "updatedAtUnix": {},
      "contentsDisplayed": false
    }}"#,
        json_escape(&room.room_id),
        json_escape(&room.display_name),
        room.state.as_str(),
        json_escape(&room.created_by_agent_id),
        participants,
        topics,
        room.events_published,
        room.bytes_published,
        room.created_at_unix,
        room.updated_at_unix
    )
}

fn room_event_json_object(event: &RoomEvent) -> String {
    format!(
        r#"    {{
      "eventId": "{}",
      "roomId": "{}",
      "topic": "{}",
      "fromAgentId": "{}",
      "eventType": "{}",
      "route": "{}",
      "payloadBytes": {},
      "createdAtUnix": {},
      "contentsDisplayed": false
    }}"#,
        json_escape(&event.event_id),
        json_escape(&event.room_id),
        json_escape(&event.topic),
        json_escape(&event.from_agent_id),
        json_escape(&event.event_type),
        json_escape(&event.route),
        event.payload_bytes,
        event.created_at_unix
    )
}

struct RoomCreateArgs {
    room_id: String,
    display_name: String,
    agent_id: String,
    json: bool,
}

struct RoomJoinArgs {
    room_id: String,
    agent_id: String,
    json: bool,
}

struct RoomPublishArgs {
    room_id: String,
    from_agent_id: String,
    topic: String,
    stdin: bool,
    json: bool,
}

struct RoomPolicyArgs {
    room_id: Option<String>,
    agent_id: Option<String>,
    topic: Option<String>,
    update: RoomTopicPolicyUpdate,
    json: bool,
}

fn parse_room_create_args(args: &[String]) -> Result<RoomCreateArgs, CliOutput> {
    let mut json = false;
    let mut agent_id = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--agent" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_rooms_usage()));
                };
                agent_id = Some(value.clone());
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    let Some(agent_id) = agent_id else {
        return Err(CliOutput::failure(2, render_rooms_usage()));
    };
    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_rooms_usage()));
    }

    Ok(RoomCreateArgs {
        room_id: positional.remove(0),
        display_name: positional.remove(0),
        agent_id,
        json,
    })
}

fn parse_room_join_args(args: &[String]) -> Result<RoomJoinArgs, CliOutput> {
    let mut json = false;
    let mut positional = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_rooms_usage()));
    }

    Ok(RoomJoinArgs {
        room_id: positional.remove(0),
        agent_id: positional.remove(0),
        json,
    })
}

fn parse_room_publish_args(args: &[String]) -> Result<RoomPublishArgs, CliOutput> {
    let mut json = false;
    let mut stdin = false;
    let mut positional = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--stdin" => stdin = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
    }

    if positional.len() != 3 {
        return Err(CliOutput::failure(2, render_rooms_usage()));
    }

    Ok(RoomPublishArgs {
        room_id: positional.remove(0),
        from_agent_id: positional.remove(0),
        topic: positional.remove(0),
        stdin,
        json,
    })
}

fn parse_room_policy_args(args: &[String]) -> Result<RoomPolicyArgs, CliOutput> {
    let mut json = false;
    let mut update = RoomTopicPolicyUpdate::empty();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--publish" => {
                update.publish = Some(parse_bool_option(
                    args.get(index + 1),
                    "--publish",
                    render_rooms_usage(),
                )?);
                index += 2;
            }
            "--subscribe" => {
                update.subscribe = Some(parse_bool_option(
                    args.get(index + 1),
                    "--subscribe",
                    render_rooms_usage(),
                )?);
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                positional.push(value.to_string());
                index += 1;
            }
        }
    }

    if !(positional.is_empty() || positional.len() == 3) {
        return Err(CliOutput::failure(2, render_rooms_usage()));
    }
    if positional.is_empty() && update.has_changes() {
        return Err(CliOutput::failure(2, render_rooms_usage()));
    }

    let mut positional = positional.into_iter();
    Ok(RoomPolicyArgs {
        room_id: positional.next(),
        agent_id: positional.next(),
        topic: positional.next(),
        update,
        json,
    })
}

fn render_rooms_usage() -> String {
    r"usage:
  conu rooms [--json]
  conu rooms create <room-id> <display-name> --agent <agent-id> [--json]
  conu rooms join <room-id> <agent-id> [--json]
  conu rooms publish <room-id> <from-agent> <topic> --stdin [--json]
  conu rooms policy [<room-id> <agent-id> <topic> [--publish <true|false>] [--subscribe <true|false>]] [--json]
  conu rooms events [--json]"
        .to_string()
}

fn render_sessions(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_sessions_usage()),
        Some("sync") if is_help_request(&args[1..]) => CliOutput::success(render_sessions_usage()),
        Some("sync") => render_sessions_sync(&args[1..], home_override),
        _ => render_sessions_list(args, home_override),
    }
}

fn render_sessions_sync(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match json_flag(args) {
        Ok(json) => match sessions::sync_remote_sessions(home_override) {
            Ok(report) => {
                if json {
                    CliOutput::success(render_sessions_report_json(&report))
                } else {
                    CliOutput::success(render_sessions_report_text(&report))
                }
            }
            Err(error) => CliOutput::failure(1, format!("conU sessions sync failed\n\n{error}")),
        },
        Err(error) => error,
    }
}

fn render_sessions_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let remote_sessions = match sessions::list_remote_sessions(home_override.clone()) {
        Ok(sessions) => sessions,
        Err(error) => return CliOutput::failure(1, format!("conU sessions failed\n\n{error}")),
    };
    let remote_agents = match sessions::list_remote_agents(home_override) {
        Ok(agents) => agents,
        Err(error) => return CliOutput::failure(1, format!("conU sessions failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_sessions_json(&remote_sessions, &remote_agents)),
        Ok(false) => CliOutput::success(render_sessions_text(&remote_sessions, &remote_agents)),
        Err(error) => error,
    }
}

fn display_network_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    let (scheme, rest) = if let Some(rest) = trimmed.strip_prefix("ws://") {
        ("ws://", rest)
    } else if let Some(rest) = trimmed.strip_prefix("wss://") {
        ("wss://", rest)
    } else if let Some(rest) = trimmed.strip_prefix("quic://") {
        ("quic://", rest)
    } else {
        return "endpointDisplayed=false".to_string();
    };
    let rest = rest
        .split('#')
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let authority = authority.rsplit('@').next().unwrap_or(authority).trim();
    if authority.is_empty() || authority.chars().any(char::is_whitespace) {
        return "endpointDisplayed=false".to_string();
    }
    if path.is_empty() {
        format!("{scheme}{authority}")
    } else {
        format!("{scheme}{authority}; endpointPathDisplayed=false")
    }
}

fn display_optional_network_endpoint(endpoint: Option<&str>, fallback: &str) -> String {
    endpoint
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(display_network_endpoint)
        .unwrap_or_else(|| fallback.to_string())
}

fn render_sessions_json(
    remote_sessions: &[RemoteSession],
    remote_agents: &[RemoteAgentRecord],
) -> String {
    let session_items = remote_sessions
        .iter()
        .map(|session| {
            format!(
                r#"    {{
      "peerNodeId": "{}",
      "displayName": "{}",
      "state": "{}",
      "route": "{}",
      "relayEndpoint": "{}",
      "reconnectAttempts": {},
      "remoteAgentCount": {}
    }}"#,
                json_escape(&session.peer_node_id),
                json_escape(&session.display_name),
                session.state.as_str(),
                json_escape(&session.route),
                json_escape(&display_network_endpoint(&session.relay_endpoint)),
                session.reconnect_attempts,
                session.remote_agent_count
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let sessions_json = if session_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{session_items}\n  ]")
    };

    format!(
        r#"{{
  "sessions": {},
  "remoteAgents": {},
  "contentsDisplayed": false
}}"#,
        sessions_json,
        remote_agents.len()
    )
}

fn render_sessions_text(
    remote_sessions: &[RemoteSession],
    remote_agents: &[RemoteAgentRecord],
) -> String {
    let sessions_text = if remote_sessions.is_empty() {
        "  none synced yet".to_string()
    } else {
        remote_sessions
            .iter()
            .map(|session| {
                format!(
                    "  {}  {}  route {}  agents {}",
                    session.peer_node_id,
                    session.state.as_str(),
                    session.route,
                    session.remote_agent_count
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU sessions

remote sessions
{sessions_text}

remote agents
  visible       {}

privacy
  payload view  contents are not displayed by conU

next
  conu sessions sync",
        remote_agents.len()
    )
}

fn render_sessions_usage() -> String {
    r"usage:
  conu sessions [--json]
  conu sessions sync [--json]"
        .to_string()
}

fn render_sessions_report_json(report: &SessionSyncReport) -> String {
    format!(
        r#"{{
  "status": "synced",
  "sessionsSynced": {},
  "remoteAgentsSynced": {},
  "connected": {},
  "reconnecting": {},
  "offline": {},
  "contentsDisplayed": false
}}"#,
        report.sessions_synced,
        report.remote_agents_synced,
        report.connected,
        report.reconnecting,
        report.offline
    )
}

fn render_sessions_report_text(report: &SessionSyncReport) -> String {
    format!(
        r"conU sessions sync

status: synced
sessions: {}
remote agents: {}
connected: {}
reconnecting: {}
offline: {}

privacy
  payload view  contents are not displayed by conU",
        report.sessions_synced,
        report.remote_agents_synced,
        report.connected,
        report.reconnecting,
        report.offline
    )
}

fn render_routes(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_routes_usage()),
        Some("sync") if is_help_request(&args[1..]) => CliOutput::success(render_routes_usage()),
        Some("probes") if is_help_request(&args[1..]) => CliOutput::success(render_routes_usage()),
        Some("sync") => render_routes_sync(&args[1..], home_override),
        Some("probes") => render_route_probes(&args[1..], home_override),
        None | Some("--json") => render_routes_list(args, home_override),
        Some(_) => CliOutput::failure(2, render_routes_usage()),
    }
}

fn render_routes_sync(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    match routes::sync_routes(home_override) {
        Ok(report) => {
            if json {
                CliOutput::success(render_routes_report_json(&report))
            } else {
                CliOutput::success(render_routes_report_text(&report))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU routes sync failed\n\n{error}")),
    }
}

fn render_routes_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let route_records = match routes::list_routes(home_override) {
        Ok(routes) => routes,
        Err(error) => return CliOutput::failure(1, format!("conU routes failed\n\n{error}")),
    };

    if json {
        CliOutput::success(render_routes_json(&route_records))
    } else {
        CliOutput::success(render_routes_text(&route_records))
    }
}

fn render_route_probes(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let probes = match routes::list_route_probes(home_override) {
        Ok(probes) => probes,
        Err(error) => {
            return CliOutput::failure(1, format!("conU routes probes failed\n\n{error}"));
        }
    };

    if json {
        CliOutput::success(render_route_probes_json(&probes))
    } else {
        CliOutput::success(render_route_probes_text(&probes))
    }
}

fn render_routes_json(route_records: &[RouteRecord]) -> String {
    let route_items = route_records
        .iter()
        .map(|route| {
            format!(
                r#"    {{
      "routeId": "{}",
      "peerNodeId": "{}",
      "displayName": "{}",
      "transport": "{}",
      "endpoint": "{}",
      "state": "{}",
      "score": {},
      "latencyMs": {},
      "directAttempted": {},
      "relayFallback": {},
      "natProfile": "{}",
      "candidateSource": "{}",
      "candidateKind": "{}",
      "rendezvousState": "{}",
      "failureReason": {},
      "updatedAtUnix": {}
    }}"#,
                json_escape(&route.route_id),
                json_escape(&route.peer_node_id),
                json_escape(&route.display_name),
                route.transport.as_str(),
                json_escape(&display_network_endpoint(&route.endpoint)),
                route.state.as_str(),
                route.score,
                json_u64(route.latency_ms),
                route.direct_attempted,
                route.relay_fallback,
                route.nat_profile.as_str(),
                json_escape(&route.candidate_source),
                json_escape(&route.candidate_kind),
                json_escape(&route.rendezvous_state),
                json_optional_string(route.failure_reason.as_deref()),
                route.updated_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let routes_json = if route_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{route_items}\n  ]")
    };

    format!(
        r#"{{
  "routes": {},
  "selectedDirect": {},
  "selectedRelay": {},
  "relayFallbacks": {},
  "contentsDisplayed": false
}}"#,
        routes_json,
        selected_direct_route_count(route_records),
        selected_relay_route_count(route_records),
        relay_fallback_route_count(route_records)
    )
}

fn render_routes_text(route_records: &[RouteRecord]) -> String {
    let selected_text = route_records
        .iter()
        .filter(|route| route.is_selected())
        .map(render_route_line)
        .collect::<Vec<_>>()
        .join("\n");
    let selected_text = if selected_text.is_empty() {
        "  none selected yet".to_string()
    } else {
        selected_text
    };

    let candidates_text = route_records
        .iter()
        .filter(|route| !route.is_selected())
        .map(render_route_line)
        .collect::<Vec<_>>()
        .join("\n");
    let candidates_text = if candidates_text.is_empty() {
        "  none recorded yet".to_string()
    } else {
        candidates_text
    };

    format!(
        r"conU routes

selected
{selected_text}

candidates
{candidates_text}

summary
  selected direct  {}
  selected relay   {}
  relay fallbacks  {}
  nat unavailable  {}

privacy
  payload view     contents are not displayed by conU

next
  conu routes sync",
        selected_direct_route_count(route_records),
        selected_relay_route_count(route_records),
        relay_fallback_route_count(route_records),
        nat_traversal_unavailable_count(route_records)
    )
}

fn render_route_line(route: &RouteRecord) -> String {
    let latency = route
        .latency_ms
        .map(|latency| format!("{latency}ms"))
        .unwrap_or_else(|| "n/a".to_string());
    let state = if route.relay_fallback {
        "fallback"
    } else {
        route.state.as_str()
    };
    let reason = route
        .failure_reason
        .as_deref()
        .filter(|reason| !reason.trim().is_empty())
        .map(|reason| format!("  reason {reason}"))
        .unwrap_or_default();

    format!(
        "  {}  {}  {}  score {}  latency {}  source {}  kind {}  rendezvous {}  endpoint {}{}",
        route.peer_node_id,
        route.transport.as_str(),
        state,
        route.score,
        latency,
        route.candidate_source,
        route.candidate_kind,
        route.rendezvous_state,
        display_network_endpoint(&route.endpoint),
        reason
    )
}

fn render_route_probes_json(probes: &[RouteProbe]) -> String {
    let probe_items = probes
        .iter()
        .map(|probe| {
            format!(
                r#"    {{
      "probeId": "{}",
      "routeId": "{}",
      "peerNodeId": "{}",
      "transport": "{}",
      "endpoint": "{}",
      "outcome": "{}",
      "score": {},
      "latencyMs": {},
      "candidateSource": "{}",
      "candidateKind": "{}",
      "rendezvousState": "{}",
      "createdAtUnix": {}
    }}"#,
                json_escape(&probe.probe_id),
                json_escape(&probe.route_id),
                json_escape(&probe.peer_node_id),
                probe.transport.as_str(),
                json_escape(&display_network_endpoint(&probe.endpoint)),
                json_escape(&probe.outcome),
                probe.score,
                json_u64(probe.latency_ms),
                json_escape(&probe.candidate_source),
                json_escape(&probe.candidate_kind),
                json_escape(&probe.rendezvous_state),
                probe.created_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let probes_json = if probe_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{probe_items}\n  ]")
    };

    format!(
        r#"{{
  "probes": {},
  "contentsDisplayed": false
}}"#,
        probes_json
    )
}

fn render_route_probes_text(probes: &[RouteProbe]) -> String {
    let mut recent = probes.iter().rev().take(12).collect::<Vec<_>>();
    recent.reverse();
    let probes_text = recent
        .iter()
        .map(|probe| {
            let latency = probe
                .latency_ms
                .map(|latency| format!("{latency}ms"))
                .unwrap_or_else(|| "n/a".to_string());
            format!(
                "  {}  {}  {}  score {}  latency {}  source {}  kind {}  rendezvous {}",
                probe.peer_node_id,
                probe.transport.as_str(),
                probe.outcome,
                probe.score,
                latency,
                probe.candidate_source,
                probe.candidate_kind,
                probe.rendezvous_state
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let probes_text = if probes_text.is_empty() {
        "  none recorded yet".to_string()
    } else {
        probes_text
    };

    format!(
        r"conU route probes

recent probes
{probes_text}

privacy
  payload view  contents are not displayed by conU"
    )
}

fn render_routes_report_json(report: &RouteSyncReport) -> String {
    format!(
        r#"{{
  "status": "synced",
  "peers": {},
  "candidates": {},
  "directAttempts": {},
  "directAvailable": {},
  "selectedDirect": {},
  "selectedRelay": {},
  "relayFallbacks": {},
  "natTraversalUnavailable": {},
  "probesRecorded": {},
  "contentsDisplayed": false
}}"#,
        report.peers,
        report.candidates,
        report.direct_attempts,
        report.direct_available,
        report.selected_direct,
        report.selected_relay,
        report.relay_fallbacks,
        report.nat_traversal_unavailable,
        report.probes_recorded
    )
}

fn render_routes_report_text(report: &RouteSyncReport) -> String {
    format!(
        r"conU routes sync

status: synced
trusted peers: {}
candidates: {}
direct attempts: {}
direct available: {}
selected direct: {}
selected relay: {}
relay fallbacks: {}
nat unavailable: {}
probes recorded: {}

privacy
  payload view  contents are not displayed by conU",
        report.peers,
        report.candidates,
        report.direct_attempts,
        report.direct_available,
        report.selected_direct,
        report.selected_relay,
        report.relay_fallbacks,
        report.nat_traversal_unavailable,
        report.probes_recorded
    )
}

fn render_routes_usage() -> String {
    r"usage:
  conu routes [--json]
  conu routes sync [--json]
  conu routes probes [--json]"
        .to_string()
}

fn render_relay(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("sync") => render_relay_sync(&args[1..], home_override),
        Some("credential") => render_relay_credential(&args[1..], home_override, stdin_payload),
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_relay_usage()),
        _ => CliOutput::failure(2, render_relay_usage()),
    }
}

fn render_relay_credential(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("set") if is_help_request(&args[1..]) => {
            CliOutput::success(render_relay_credential_set_usage())
        }
        Some("clear") if is_help_request(&args[1..]) => {
            CliOutput::success(render_relay_credential_clear_usage())
        }
        Some("status") if is_help_request(&args[1..]) => {
            CliOutput::success(render_relay_credential_status_usage())
        }
        Some("set") => render_relay_credential_set(&args[1..], home_override, stdin_payload),
        Some("clear") => render_relay_credential_clear(&args[1..], home_override),
        Some("status") | None => render_relay_credential_status(&args[1..], home_override),
        Some("--help") | Some("-h") | Some("help") => {
            CliOutput::success(render_relay_credential_usage())
        }
        _ => CliOutput::failure(2, render_relay_usage()),
    }
}

fn render_relay_credential_set(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_relay_credential_set_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.stdin {
        return CliOutput::failure(2, render_relay_usage());
    }
    let token = match String::from_utf8(stdin_payload) {
        Ok(token) => token.trim().to_string(),
        Err(_) => {
            return CliOutput::failure(
                2,
                "conU relay credential set failed\n\nrelay token must be UTF-8",
            );
        }
    };
    let status = match security::store_relay_credential(home_override, &token) {
        Ok(status) => status,
        Err(error) => {
            return CliOutput::failure(1, format!("conU relay credential set failed\n\n{error}"));
        }
    };

    if parsed.json {
        return CliOutput::success(render_relay_credential_status_json("stored", &status));
    }

    CliOutput::success(render_relay_credential_status_text("stored", &status))
}

fn render_relay_credential_clear(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let status = match security::clear_relay_credential(home_override) {
        Ok(status) => status,
        Err(error) => {
            return CliOutput::failure(1, format!("conU relay credential clear failed\n\n{error}"));
        }
    };

    if json {
        return CliOutput::success(render_relay_credential_status_json("cleared", &status));
    }

    CliOutput::success(render_relay_credential_status_text("cleared", &status))
}

fn render_relay_credential_status(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };
    let status = match security::relay_credential_status(home_override) {
        Ok(status) => status,
        Err(error) => {
            return CliOutput::failure(
                1,
                format!("conU relay credential status failed\n\n{error}"),
            );
        }
    };

    if json {
        return CliOutput::success(render_relay_credential_status_json("status", &status));
    }

    CliOutput::success(render_relay_credential_status_text("status", &status))
}

fn render_relay_credential_status_json(
    status_label: &str,
    status: &security::RelayCredentialStatus,
) -> String {
    format!(
        r#"{{
  "status": "{}",
  "configured": {},
  "secretStorageBackend": "{}",
  "secretsOsProtected": {},
  "contentsDisplayed": false
}}"#,
        json_escape(status_label),
        status.configured,
        json_escape(&status.secret_storage_backend),
        status.os_protected
    )
}

fn render_relay_credential_status_text(
    status_label: &str,
    status: &security::RelayCredentialStatus,
) -> String {
    format!(
        r"conU relay credential

status: {status_label}
configured: {}
secret store: {}
os protected: {}

privacy
  token view     not displayed
  runtime use    env CONU_RELAY_TOKEN overrides stored credential",
        yes_no(status.configured),
        status.secret_storage_backend,
        yes_no(status.os_protected)
    )
}

fn render_relay_sync(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_relay_sync_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let report =
        match relay_delivery::sync_relay_once(home_override, Duration::from_millis(parsed.wait_ms))
        {
            Ok(report) => report,
            Err(error) => {
                return CliOutput::failure(1, format!("conU relay sync failed\n\n{error}"));
            }
        };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "synced",
  "endpoint": "{}",
  "connected": {},
  "queued": {},
  "sent": {},
  "received": {},
  "undelivered": {},
  "rejected": {},
  "contentsDisplayed": false
}}"#,
            json_escape(&display_network_endpoint(&report.endpoint)),
            report.connected,
            report.queued,
            report.sent,
            report.received,
            report.undelivered,
            report.rejected
        ));
    }

    CliOutput::success(format!(
        r"conU relay sync

endpoint: {}
connected: {}
queued: {}
sent: {}
received: {}
undelivered: {}
rejected: {}

flow
  [agent] -> {{conUD}} == peer-encrypted ws ==> {{relay}} ==> {{remote conUD}} -> [agent]

privacy
  payload view  contents are not displayed by conU
  relay view    encrypted body plus route metadata only

note
  conUD runs this relay pump automatically when a relay or trusted relay peer is configured",
        display_network_endpoint(&report.endpoint),
        yes_no(report.connected),
        report.queued,
        report.sent,
        report.received,
        report.undelivered,
        report.rejected
    ))
}

struct RelaySyncArgs {
    wait_ms: u64,
    json: bool,
}

struct RelayCredentialSetArgs {
    stdin: bool,
    json: bool,
}

fn parse_relay_sync_args(args: &[String]) -> Result<RelaySyncArgs, CliOutput> {
    let mut wait_ms = 1000;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--wait-ms" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_relay_usage()));
                };
                wait_ms = match value.parse::<u64>() {
                    Ok(value) if value <= 60_000 => value,
                    _ => return Err(CliOutput::failure(2, render_relay_usage())),
                };
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            _ => return Err(CliOutput::failure(2, render_relay_usage())),
        }
        index += 1;
    }

    Ok(RelaySyncArgs { wait_ms, json })
}

fn parse_relay_credential_set_args(args: &[String]) -> Result<RelayCredentialSetArgs, CliOutput> {
    let mut stdin = false;
    let mut json = false;

    for arg in args {
        match arg.as_str() {
            "--stdin" => stdin = true,
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            _ => return Err(CliOutput::failure(2, render_relay_usage())),
        }
    }

    Ok(RelayCredentialSetArgs { stdin, json })
}

fn render_relay_usage() -> String {
    r"usage:
  conu relay sync [--wait-ms <milliseconds>] [--json]
  conu relay credential status [--json]
  conu relay credential set --stdin [--json]
  conu relay credential clear [--json]"
        .to_string()
}

fn render_relay_credential_usage() -> String {
    r"usage:
  conu relay credential status [--json]
  conu relay credential set --stdin [--json]
  conu relay credential clear [--json]

privacy:
  relay tokens are read from stdin for set
  relay tokens are never displayed
  CONU_RELAY_TOKEN overrides the stored credential at runtime"
        .to_string()
}

fn render_relay_credential_set_usage() -> String {
    r"usage: conu relay credential set --stdin [--json]

example:
  printf <token> | conu relay credential set --stdin

privacy:
  token bytes are read from stdin, not command history
  stdout shows credential status only
  contentsDisplayed=false"
        .to_string()
}

fn render_relay_credential_status_usage() -> String {
    r"usage: conu relay credential status [--json]

privacy:
  token bytes are never displayed
  status output reports only whether a stored credential exists
  contentsDisplayed=false"
        .to_string()
}

fn render_relay_credential_clear_usage() -> String {
    r"usage: conu relay credential clear [--json]

privacy:
  token bytes are removed without display
  stdout shows credential status only
  contentsDisplayed=false"
        .to_string()
}

fn render_security(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        None | Some("audit") => {
            let remaining = if args.is_empty() { args } else { &args[1..] };
            render_security_audit(remaining, home_override)
        }
        Some("rotate") => render_security_rotate(&args[1..], home_override),
        Some("retire") => render_security_retire(&args[1..], home_override),
        Some("--help") | Some("-h") => CliOutput::success(render_security_usage()),
        Some(_) => CliOutput::failure(2, render_security_usage()),
    }
}

fn render_security_audit(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let init = match state::init_state(home_override.clone()) {
        Ok(init) => init,
        Err(error) => {
            return CliOutput::failure(1, format!("conU security audit failed\n\n{error}"));
        }
    };
    let report = match security::ensure_security_state_from_paths(&init.paths) {
        Ok(report) => report,
        Err(error) => {
            return CliOutput::failure(1, format!("conU security audit failed\n\n{error}"));
        }
    };
    let audit = match security::security_audit(home_override) {
        Ok(audit) => audit,
        Err(error) => {
            return CliOutput::failure(1, format!("conU security audit failed\n\n{error}"));
        }
    };

    if json {
        CliOutput::success(render_security_json(&audit, &report))
    } else {
        CliOutput::success(render_security_text(&audit, &report))
    }
}

fn render_security_rotate(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("storage") => render_security_rotate_storage(&args[1..], home_override),
        Some("identity") => render_security_rotate_identity(&args[1..], home_override),
        Some("--help") | Some("-h") => CliOutput::success(render_security_usage()),
        _ => CliOutput::failure(2, render_security_usage()),
    }
}

fn render_security_retire(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("storage") => render_security_retire_storage(&args[1..], home_override),
        Some("identity") => render_security_retire_identity(&args[1..], home_override),
        Some("--help") | Some("-h") => CliOutput::success(render_security_usage()),
        _ => CliOutput::failure(2, render_security_usage()),
    }
}

fn render_security_rotate_storage(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_security_rotate_storage_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.confirm {
        return CliOutput::failure(
            2,
            "conU security rotate storage requires --confirm\n\n".to_string()
                + &render_security_usage(),
        );
    }

    let report = match security::rotate_storage_key(home_override) {
        Ok(report) => report,
        Err(error) => {
            return CliOutput::failure(
                1,
                format!("conU security rotate storage failed\n\n{error}"),
            );
        }
    };

    if parsed.json {
        CliOutput::success(render_security_rotate_storage_json(&report))
    } else {
        CliOutput::success(render_security_rotate_storage_text(&report))
    }
}

fn render_security_rotate_identity(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_security_rotate_identity_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.confirm_peer_refresh {
        return CliOutput::failure(
            2,
            "conU security rotate identity requires --confirm-peer-refresh\n\n".to_string()
                + &render_security_usage(),
        );
    }

    let report = match security::rotate_identity_keys(home_override) {
        Ok(report) => report,
        Err(error) => {
            return CliOutput::failure(
                1,
                format!("conU security rotate identity failed\n\n{error}"),
            );
        }
    };

    if parsed.json {
        CliOutput::success(render_security_rotate_identity_json(&report))
    } else {
        CliOutput::success(render_security_rotate_identity_text(&report))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityRotateStorageArgs {
    confirm: bool,
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityRotateIdentityArgs {
    confirm_peer_refresh: bool,
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityRetireStorageArgs {
    confirm: bool,
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityRetireIdentityArgs {
    confirm_peer_refresh_complete: bool,
    json: bool,
}

fn parse_security_rotate_storage_args(
    args: &[String],
) -> Result<SecurityRotateStorageArgs, CliOutput> {
    let mut confirm = false;
    let mut json = false;

    for arg in args {
        match arg.as_str() {
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(CliOutput::success(render_security_usage())),
            _ => return Err(CliOutput::failure(2, render_security_usage())),
        }
    }

    Ok(SecurityRotateStorageArgs { confirm, json })
}

fn parse_security_rotate_identity_args(
    args: &[String],
) -> Result<SecurityRotateIdentityArgs, CliOutput> {
    let mut confirm_peer_refresh = false;
    let mut json = false;

    for arg in args {
        match arg.as_str() {
            "--confirm-peer-refresh" => confirm_peer_refresh = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(CliOutput::success(render_security_usage())),
            _ => return Err(CliOutput::failure(2, render_security_usage())),
        }
    }

    Ok(SecurityRotateIdentityArgs {
        confirm_peer_refresh,
        json,
    })
}

fn render_security_retire_storage(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_security_retire_storage_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.confirm {
        return CliOutput::failure(
            2,
            "conU security retire storage requires --confirm\n\n".to_string()
                + &render_security_usage(),
        );
    }

    let report = match security::retire_unused_storage_keys(home_override) {
        Ok(report) => report,
        Err(error) => {
            return CliOutput::failure(
                1,
                format!("conU security retire storage failed\n\n{error}"),
            );
        }
    };

    if parsed.json {
        CliOutput::success(render_security_retire_storage_json(&report))
    } else {
        CliOutput::success(render_security_retire_storage_text(&report))
    }
}

fn render_security_retire_identity(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_security_retire_identity_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    if !parsed.confirm_peer_refresh_complete {
        return CliOutput::failure(
            2,
            "conU security retire identity requires --confirm-peer-refresh-complete\n\n"
                .to_string()
                + &render_security_usage(),
        );
    }

    let report = match security::retire_archived_identity_keys(home_override) {
        Ok(report) => report,
        Err(error) => {
            return CliOutput::failure(
                1,
                format!("conU security retire identity failed\n\n{error}"),
            );
        }
    };

    if parsed.json {
        CliOutput::success(render_security_retire_identity_json(&report))
    } else {
        CliOutput::success(render_security_retire_identity_text(&report))
    }
}

fn parse_security_retire_storage_args(
    args: &[String],
) -> Result<SecurityRetireStorageArgs, CliOutput> {
    let mut confirm = false;
    let mut json = false;

    for arg in args {
        match arg.as_str() {
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(CliOutput::success(render_security_usage())),
            _ => return Err(CliOutput::failure(2, render_security_usage())),
        }
    }

    Ok(SecurityRetireStorageArgs { confirm, json })
}

fn parse_security_retire_identity_args(
    args: &[String],
) -> Result<SecurityRetireIdentityArgs, CliOutput> {
    let mut confirm_peer_refresh_complete = false;
    let mut json = false;

    for arg in args {
        match arg.as_str() {
            "--confirm-peer-refresh-complete" => confirm_peer_refresh_complete = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(CliOutput::success(render_security_usage())),
            _ => return Err(CliOutput::failure(2, render_security_usage())),
        }
    }

    Ok(SecurityRetireIdentityArgs {
        confirm_peer_refresh_complete,
        json,
    })
}

fn render_security_json(audit: &SecurityAudit, report: &SecurityReport) -> String {
    format!(
        r#"{{
  "initialized": {},
  "identitySigningKey": {},
  "identityExchangeKey": {},
  "storageKey": {},
  "replayCache": {},
  "keyRotationPlan": {},
  "localPayloadEncryption": {},
  "signedAgentCards": {},
  "peerKeyExchange": {},
  "secretStorageBackend": "{}",
  "secretsOsProtected": {},
  "signingKeyId": "{}",
  "exchangeKeyId": "{}",
  "storageKeyId": "{}",
  "contentsDisplayed": false
}}"#,
        audit.initialized,
        audit.identity_signing_key,
        audit.identity_exchange_key,
        audit.storage_key,
        audit.replay_cache,
        audit.key_rotation_plan,
        audit.local_payload_encryption,
        audit.signed_agent_cards,
        audit.peer_key_exchange,
        json_escape(&audit.secret_storage_backend),
        audit.secrets_os_protected,
        json_escape(&report.signing_key_id),
        json_escape(&report.exchange_key_id),
        json_escape(&report.storage_key_id)
    )
}

fn render_security_text(audit: &SecurityAudit, report: &SecurityReport) -> String {
    format!(
        r"conU security audit

status: {}

keys
  signing key   {}  {}
  exchange key  {}  {}
  storage key   {}  {}
  secret store  {}  os_protected={}

controls
  local payloads  {}
  agent cards     {}
  peer exchange   {}
  replay cache    {}
  rotation plan   {}

privacy
  payload view    contents are not displayed by conU
  key view        private keys are not displayed",
        ready_label(audit.initialized),
        ready_label(audit.identity_signing_key),
        report.signing_key_id,
        ready_label(audit.identity_exchange_key),
        report.exchange_key_id,
        ready_label(audit.storage_key),
        report.storage_key_id,
        audit.secret_storage_backend,
        yes_no(audit.secrets_os_protected),
        if audit.local_payload_encryption {
            "encrypted at rest"
        } else {
            "not ready"
        },
        if audit.signed_agent_cards {
            "signed with Ed25519"
        } else {
            "not ready"
        },
        if audit.peer_key_exchange {
            "X25519 ready"
        } else {
            "not ready"
        },
        ready_label(audit.replay_cache),
        ready_label(audit.key_rotation_plan)
    )
}

fn render_security_rotate_storage_json(report: &StorageKeyRotationReport) -> String {
    format!(
        r#"{{
  "status": "rotated",
  "oldStorageKeyId": "{}",
  "newStorageKeyId": "{}",
  "filesScanned": {},
  "filesMigrated": {},
  "filesSkipped": {},
  "archivedStorageKeys": {},
  "contentsDisplayed": false
}}"#,
        json_escape(&report.old_storage_key_id),
        json_escape(&report.new_storage_key_id),
        report.files_scanned,
        report.files_migrated,
        report.files_skipped,
        report.archived_storage_keys
    )
}

fn render_security_rotate_storage_text(report: &StorageKeyRotationReport) -> String {
    format!(
        r"conU security rotate storage

status: rotated
old storage key: {}
new storage key: {}
files scanned: {}
files migrated: {}
files skipped: {}
archived keys: {}

privacy
  payload view    contents are not displayed by conU
  key view        private keys are not displayed",
        report.old_storage_key_id,
        report.new_storage_key_id,
        report.files_scanned,
        report.files_migrated,
        report.files_skipped,
        report.archived_storage_keys
    )
}

fn render_security_rotate_identity_json(report: &IdentityKeyRotationReport) -> String {
    format!(
        r#"{{
  "status": "rotated",
  "oldSigningKeyId": "{}",
  "newSigningKeyId": "{}",
  "oldExchangeKeyId": "{}",
  "newExchangeKeyId": "{}",
  "archivedIdentityKeys": {},
  "peerCardRefreshRequired": {},
  "signedAgentCardRefreshRequired": {},
  "contentsDisplayed": false
}}"#,
        json_escape(&report.old_signing_key_id),
        json_escape(&report.new_signing_key_id),
        json_escape(&report.old_exchange_key_id),
        json_escape(&report.new_exchange_key_id),
        report.archived_identity_keys,
        report.peer_card_refresh_required,
        report.signed_agent_card_refresh_required
    )
}

fn render_security_rotate_identity_text(report: &IdentityKeyRotationReport) -> String {
    format!(
        r"conU security rotate identity

status: rotated
old signing key: {}
new signing key: {}
old exchange key: {}
new exchange key: {}
archived identity keys: {}
peer card refresh required: {}
signed agent-card refresh required: {}

next
  run conu identity export and share the refreshed public peer card with trusted peers
  export or re-register signed local agent cards before peers import new cards

privacy
  payload view    contents are not displayed by conU
  key view        private keys are not displayed",
        report.old_signing_key_id,
        report.new_signing_key_id,
        report.old_exchange_key_id,
        report.new_exchange_key_id,
        report.archived_identity_keys,
        yes_no(report.peer_card_refresh_required),
        yes_no(report.signed_agent_card_refresh_required)
    )
}

fn render_security_retire_storage_json(report: &StorageKeyRetirementReport) -> String {
    format!(
        r#"{{
  "status": "retired",
  "archivedStorageKeysScanned": {},
  "retiredStorageKeys": {},
  "retainedStorageKeys": {},
  "filesScanned": {},
  "dependentFiles": {},
  "contentsDisplayed": false
}}"#,
        report.archived_storage_keys_scanned,
        report.retired_storage_keys,
        report.retained_storage_keys,
        report.files_scanned,
        report.dependent_files
    )
}

fn render_security_retire_identity_json(report: &IdentityKeyRetirementReport) -> String {
    format!(
        r#"{{
  "status": "retired",
  "archivedIdentityKeysScanned": {},
  "retiredIdentityKeys": {},
  "retainedIdentityKeys": {},
  "peerCardRefreshConfirmed": {},
  "oldKeyDecryptCompatibilityRetired": {},
  "contentsDisplayed": false
}}"#,
        report.archived_identity_keys_scanned,
        report.retired_identity_keys,
        report.retained_identity_keys,
        report.peer_card_refresh_confirmed,
        report.old_key_decrypt_compatibility_retired
    )
}

fn render_security_retire_identity_text(report: &IdentityKeyRetirementReport) -> String {
    format!(
        r"conU security retire identity

status: retired
archived identity keys scanned: {}
identity keys retired: {}
identity keys retained: {}
peer card refresh confirmed: {}
old-key decrypt compatibility retired: {}

privacy
  payload view    contents are not displayed by conU
  key view        private keys are not displayed",
        report.archived_identity_keys_scanned,
        report.retired_identity_keys,
        report.retained_identity_keys,
        yes_no(report.peer_card_refresh_confirmed),
        yes_no(report.old_key_decrypt_compatibility_retired)
    )
}

fn render_security_retire_storage_text(report: &StorageKeyRetirementReport) -> String {
    format!(
        r"conU security retire storage

status: retired
archived keys scanned: {}
keys retired: {}
keys retained: {}
files scanned: {}
dependent files: {}

privacy
  payload view    contents are not displayed by conU
  key view        private keys are not displayed",
        report.archived_storage_keys_scanned,
        report.retired_storage_keys,
        report.retained_storage_keys,
        report.files_scanned,
        report.dependent_files
    )
}

fn render_security_usage() -> String {
    r"usage:
  conu security audit [--json]
  conu security rotate storage --confirm [--json]
  conu security rotate identity --confirm-peer-refresh [--json]
  conu security retire identity --confirm-peer-refresh-complete [--json]
  conu security retire storage --confirm [--json]"
        .to_string()
}

fn render_identity(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_identity_usage()),
        Some("export") if is_help_request(&args[1..]) => {
            CliOutput::success(render_identity_usage())
        }
        Some("export") => render_identity_export(&args[1..], home_override),
        _ => CliOutput::failure(2, render_identity_usage()),
    }
}

fn render_identity_export(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_identity_export_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let card = match trust::export_peer_card_with_endpoints(
        home_override,
        parsed.relay_endpoint,
        parsed.direct_endpoint,
    ) {
        Ok(card) => card,
        Err(error) => {
            return CliOutput::failure(1, format!("conU identity export failed\n\n{error}"));
        }
    };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "nodeId": "{}",
  "displayName": "{}",
  "exchangePublicKeyHex": "{}",
  "relayEndpoint": "{}",
  "directQuicEndpoint": "{}",
  "signingPublicKeyHex": "{}",
  "signatureAlgorithm": "{}",
  "signatureKeyId": "{}",
  "signatureHex": "{}",
  "peerCardSigned": {},
  "contentsDisplayed": false
}}"#,
            json_escape(&card.node_id),
            json_escape(&card.display_name),
            json_escape(&card.exchange_public_key_hex),
            json_escape(&card.relay_endpoint),
            json_escape(card.direct_quic_endpoint.as_deref().unwrap_or("")),
            json_escape(card.signing_public_key_hex.as_deref().unwrap_or("")),
            json_escape(card.signature_algorithm.as_deref().unwrap_or("")),
            json_escape(card.signature_key_id.as_deref().unwrap_or("")),
            json_escape(card.signature_hex.as_deref().unwrap_or("")),
            card.signature_hex.is_some()
        ));
    }

    CliOutput::success(format!(
        r"conU identity export

node: {}
name: {}
exchange public key: {}
relay: {}
direct QUIC: {}
signing public key: {}
signature key id: {}
signature: {}

share this public card with a peer, then import their card with:
  conu identity export --relay {} --json > my-peer-card.json
  conu peers trust --card their-peer-card.json

privacy
  key view      public exchange key only
  signature     public integrity proof only
  payload view  contents are not displayed by conU",
        card.node_id,
        card.display_name,
        card.exchange_public_key_hex,
        card.relay_endpoint,
        card.direct_quic_endpoint
            .as_deref()
            .unwrap_or("not configured"),
        card.signing_public_key_hex
            .as_deref()
            .unwrap_or("not available"),
        card.signature_key_id.as_deref().unwrap_or("not available"),
        card.signature_hex.as_deref().unwrap_or("not available"),
        card.relay_endpoint
    ))
}

fn render_identity_usage() -> String {
    r"usage:
  conu identity export [--relay <ws://host:port|wss://host/path>] [--direct <quic://host:port>] [--json]

privacy:
  identity commands show public peer-card material only
  private keys, relay tokens, and payload contents are never displayed
  contentsDisplayed=false"
        .to_string()
}

struct IdentityExportArgs {
    json: bool,
    relay_endpoint: Option<String>,
    direct_endpoint: Option<String>,
}

fn parse_identity_export_args(args: &[String]) -> Result<IdentityExportArgs, CliOutput> {
    let mut json = false;
    let mut relay_endpoint = None;
    let mut direct_endpoint = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--relay" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_identity_usage()));
                };
                relay_endpoint = Some(value.clone());
                index += 1;
            }
            "--direct" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_identity_usage()));
                };
                direct_endpoint = Some(value.clone());
                index += 1;
            }
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(CliOutput::failure(2, render_identity_usage())),
        }
        index += 1;
    }

    Ok(IdentityExportArgs {
        json,
        relay_endpoint,
        direct_endpoint,
    })
}

fn inbox_ids(home_override: Option<PathBuf>, agent_id: &str) -> HashSet<String> {
    messages::list_agent_inbox(home_override, agent_id)
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| entry.envelope_id)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default()
}

fn wait_for_message_delivery(
    home_override: Option<PathBuf>,
    to_agent_id: &str,
    before: HashSet<String>,
    payload_bytes: usize,
) -> Option<InboxEntry> {
    let attempts = if runtime_is_live(home_override.clone()) {
        40
    } else {
        1
    };
    for attempt in 0..attempts {
        if let Ok(entries) = messages::list_agent_inbox(home_override.clone(), to_agent_id)
            && let Some(entry) = entries.into_iter().find(|entry| {
                !before.contains(&entry.envelope_id) && entry.payload_bytes == payload_bytes
            })
        {
            return Some(entry);
        }
        if attempt + 1 < attempts {
            thread::sleep(Duration::from_millis(100));
        }
    }

    None
}

fn render_peers(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_peers_usage()),
        Some("policy") if is_help_request(&args[1..]) => {
            CliOutput::success(render_peer_policy_usage())
        }
        Some("policy") => render_peer_policy(&args[1..], home_override),
        Some("revoke") if is_help_request(&args[1..]) => {
            CliOutput::success(render_peer_revoke_usage())
        }
        Some("revoke") => render_peer_revoke(&args[1..], home_override),
        Some("trust") if is_help_request(&args[1..]) => {
            CliOutput::success(render_peer_trust_usage())
        }
        Some("trust") => render_peer_trust(&args[1..], home_override, stdin_payload),
        _ => render_peer_list(args, home_override),
    }
}

fn render_peer_list(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let peers = match trust::list_peers(home_override) {
        Ok(peers) => peers,
        Err(error) => return CliOutput::failure(1, format!("conU peers failed\n\n{error}")),
    };

    match json_flag(args) {
        Ok(true) => CliOutput::success(render_peers_json(&peers)),
        Ok(false) => CliOutput::success(render_peers_text(&peers)),
        Err(error) => error,
    }
}

fn render_peer_trust(
    args: &[String],
    home_override: Option<PathBuf>,
    stdin_payload: Vec<u8>,
) -> CliOutput {
    let parsed = match parse_peer_trust_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let card = match parsed.card_source {
        Some(source) => {
            match peer_card_from_source(
                &source,
                stdin_payload,
                parsed.relay_endpoint,
                parsed.direct_endpoint,
            ) {
                Ok(card) => card,
                Err(error) => return error,
            }
        }
        None => PeerCard {
            node_id: parsed.peer_node_id.expect("manual peer node parsed"),
            display_name: parsed.display_name.expect("manual display name parsed"),
            exchange_public_key_hex: parsed.exchange_key.expect("manual exchange key parsed"),
            relay_endpoint: parsed
                .relay_endpoint
                .unwrap_or_else(|| "ws://127.0.0.1:8787".to_string()),
            direct_quic_endpoint: parsed.direct_endpoint,
            signing_public_key_hex: parsed.signing_key,
            signature_algorithm: parsed.signature_algorithm,
            signature_key_id: parsed.signature_key_id,
            signature_hex: parsed.signature,
        },
    };
    let peer = match trust::trust_peer_card(home_override, card) {
        Ok(peer) => peer,
        Err(error) => return CliOutput::failure(1, format!("conU peers trust failed\n\n{error}")),
    };

    if parsed.json {
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "peerNodeId": "{}",
  "displayName": "{}",
  "exchangeKeyTrusted": {},
  "peerCardSigned": {},
  "relayEndpoint": "{}",
  "directQuicEndpoint": "{}",
  "contentsDisplayed": false
}}"#,
            peer.status.as_str(),
            json_escape(&peer.peer_node_id),
            json_escape(&peer.display_name),
            peer.exchange_public_key_hex.is_some(),
            peer.signature_hex.is_some(),
            json_escape(&display_optional_network_endpoint(
                peer.relay_endpoint.as_deref(),
                ""
            )),
            json_escape(&display_optional_network_endpoint(
                peer.direct_quic_endpoint.as_deref(),
                ""
            ))
        ));
    }

    CliOutput::success(format!(
        r"conU peers trust

status: {}
peer: {}
name: {}
exchange key: trusted
peer card signature: {}
relay: {}
direct QUIC: {}

next
  conu start
  optional manual sync: conu relay sync --wait-ms 3000

privacy
  payload view  contents are not displayed by conU",
        peer.status.as_str(),
        peer.peer_node_id,
        peer.display_name,
        if peer.signature_hex.is_some() {
            "verified"
        } else {
            "not provided"
        },
        display_optional_network_endpoint(peer.relay_endpoint.as_deref(), "not configured"),
        display_optional_network_endpoint(peer.direct_quic_endpoint.as_deref(), "not configured")
    ))
}

fn render_peer_revoke(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let (peer_node_id, json) = match parse_peer_revoke_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let report = match trust::revoke_peer(home_override, &peer_node_id) {
        Ok(report) => report,
        Err(error) => return CliOutput::failure(1, format!("conU peers revoke failed\n\n{error}")),
    };

    if json {
        return CliOutput::success(format!(
            r#"{{
  "status": "{}",
  "peerNodeId": "{}",
  "changed": {},
  "contentsDisplayed": false
}}"#,
            report.peer.status.as_str(),
            json_escape(&report.peer.peer_node_id),
            report.changed
        ));
    }

    CliOutput::success(format!(
        r"conU peers revoke

status: {}
peer: {}
changed: {}

privacy
  payload view  contents are not displayed by conU",
        report.peer.status.as_str(),
        report.peer.peer_node_id,
        report.changed
    ))
}

fn render_peer_policy(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_peer_policy_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match parsed.peer_node_id {
        Some(peer_node_id) if parsed.update.has_changes() => {
            let record = match policy::set_peer_policy(home_override, &peer_node_id, parsed.update)
            {
                Ok(record) => record,
                Err(error) => {
                    return CliOutput::failure(1, format!("conU peers policy failed\n\n{error}"));
                }
            };
            if parsed.json {
                return CliOutput::success(render_peer_policy_json(&record, "updated"));
            }
            CliOutput::success(render_peer_policy_text(&record, "updated"))
        }
        Some(peer_node_id) => {
            let record = match policy::peer_policy(home_override, &peer_node_id) {
                Ok(record) => record,
                Err(error) => {
                    return CliOutput::failure(1, format!("conU peers policy failed\n\n{error}"));
                }
            };
            if parsed.json {
                return CliOutput::success(render_peer_policy_json(&record, "read"));
            }
            CliOutput::success(render_peer_policy_text(&record, "read"))
        }
        None => {
            let policies = match policy::list_peer_policies(home_override) {
                Ok(policies) => policies,
                Err(error) => {
                    return CliOutput::failure(1, format!("conU peers policy failed\n\n{error}"));
                }
            };
            if parsed.json {
                return CliOutput::success(render_peer_policies_json(&policies));
            }
            CliOutput::success(render_peer_policies_text(&policies))
        }
    }
}

fn render_peers_json(peers: &[TrustedPeer]) -> String {
    let trusted = trusted_peer_count(peers);
    let peer_items = peers
        .iter()
        .map(|peer| {
            format!(
                r#"    {{
      "peerNodeId": "{}",
      "displayName": "{}",
      "status": "{}",
      "source": "{}",
      "exchangeKeyTrusted": {},
      "peerCardSigned": {},
      "relayEndpoint": "{}",
      "directQuicEndpoint": "{}",
      "updatedAtUnix": {}
    }}"#,
                json_escape(&peer.peer_node_id),
                json_escape(&peer.display_name),
                peer.status.as_str(),
                json_escape(&peer.source),
                peer.exchange_public_key_hex.is_some(),
                peer.signature_hex.is_some(),
                json_escape(&display_optional_network_endpoint(
                    peer.relay_endpoint.as_deref(),
                    ""
                )),
                json_escape(&display_optional_network_endpoint(
                    peer.direct_quic_endpoint.as_deref(),
                    ""
                )),
                peer.updated_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let peers = if peer_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{peer_items}\n  ]")
    };

    format!(
        r#"{{
  "peers": {},
  "trusted": {},
  "contentsDisplayed": false
}}"#,
        peers, trusted
    )
}

fn render_peers_text(peers: &[TrustedPeer]) -> String {
    let rows = if peers.is_empty() {
        "  none trusted yet".to_string()
    } else {
        peers
            .iter()
            .map(|peer| {
                format!(
                    "  {}  {}  {}  key {}  signed {}  relay {}  direct {}",
                    peer.peer_node_id,
                    peer.status.as_str(),
                    peer.display_name,
                    if peer.exchange_public_key_hex.is_some() {
                        "yes"
                    } else {
                        "no"
                    },
                    if peer.signature_hex.is_some() {
                        "yes"
                    } else {
                        "no"
                    },
                    display_optional_network_endpoint(peer.relay_endpoint.as_deref(), "-"),
                    display_optional_network_endpoint(peer.direct_quic_endpoint.as_deref(), "-")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU peers

trusted peers
{rows}

next
  conu pair
  conu join <code>
  conu identity export --json > peer-card.json
  conu peers trust --card peer-card.json
  conu peers trust <peer-node-id> <display-name> --exchange-key <hex> [--relay <ws://host:port|wss://host/path>] [--direct <quic://host:port>] [--signing-key <hex> --signature <hex> --signature-key-id <id>]
  conu peers policy <peer-node-id> --messages true --streams true
  conu peers revoke <peer-node-id>"
    )
}

fn render_peers_usage() -> String {
    r"usage:
  conu peers [--json]
  conu peers trust --card <file|-> [--relay <ws://host:port|wss://host/path>] [--direct <quic://host:port>] [--json]
  conu peers trust <peer-node-id> <display-name> --exchange-key <hex> [--relay <ws://host:port|wss://host/path>] [--direct <quic://host:port>] [--json]
  conu peers policy [<peer-node-id> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>]] [--json]
  conu peers revoke <peer-node-id> [--json]

quick start:
  conu identity export --json > my-peer-card.json
  conu peers trust --card their-peer-card.json
  conu peers policy <peer-node-id> --messages true --streams true --rooms true

privacy:
  peer commands show public card, trust, route, and policy metadata only
  payload contents, private keys, and relay tokens are never displayed
  contentsDisplayed=false"
        .to_string()
}

fn render_peer_policy_json(record: &PeerPolicyRecord, status: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "peerNodeId": "{}",
  "policy": {{
    "messages": {},
    "streams": {},
    "rooms": {},
    "files": {},
    "mailbox": {}
  }},
  "updatedAtUnix": {},
  "contentsDisplayed": false
}}"#,
        status,
        json_escape(&record.peer_node_id),
        record.messages,
        record.streams,
        record.rooms,
        record.files,
        record.mailbox,
        record.updated_at_unix
    )
}

fn render_peer_policy_text(record: &PeerPolicyRecord, status: &str) -> String {
    format!(
        r"conU peers policy

status: {}
peer: {}
messages: {}
streams: {}
rooms: {}
files: {}
mailbox: {}

privacy
  payload view  contents are not displayed by conU",
        status,
        record.peer_node_id,
        record.messages,
        record.streams,
        record.rooms,
        record.files,
        record.mailbox
    )
}

fn render_peer_policies_json(policies: &[PeerPolicyRecord]) -> String {
    let items = policies
        .iter()
        .map(|policy| {
            format!(
                r#"    {{
      "peerNodeId": "{}",
      "messages": {},
      "streams": {},
      "rooms": {},
      "files": {},
      "mailbox": {},
      "updatedAtUnix": {}
    }}"#,
                json_escape(&policy.peer_node_id),
                policy.messages,
                policy.streams,
                policy.rooms,
                policy.files,
                policy.mailbox,
                policy.updated_at_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let policies = if items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{items}\n  ]")
    };

    format!(
        r#"{{
  "policies": {},
  "contentsDisplayed": false
}}"#,
        policies
    )
}

fn render_peer_policies_text(policies: &[PeerPolicyRecord]) -> String {
    let rows = if policies.is_empty() {
        "  no peer policies granted".to_string()
    } else {
        policies
            .iter()
            .map(|policy| {
                format!(
                    "  {}  messages={} streams={} rooms={} files={} mailbox={}",
                    policy.peer_node_id,
                    policy.messages,
                    policy.streams,
                    policy.rooms,
                    policy.files,
                    policy.mailbox
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r"conU peers policy

peer policies
{rows}

next
  conu peers policy <peer-node-id> --messages true --streams true --rooms false"
    )
}

const MAX_PEER_CARD_BYTES: usize = 64 * 1024;

struct PeerTrustArgs {
    peer_node_id: Option<String>,
    display_name: Option<String>,
    exchange_key: Option<String>,
    relay_endpoint: Option<String>,
    direct_endpoint: Option<String>,
    signing_key: Option<String>,
    signature_algorithm: Option<String>,
    signature_key_id: Option<String>,
    signature: Option<String>,
    card_source: Option<PeerCardSource>,
    json: bool,
}

enum PeerCardSource {
    File(PathBuf),
    Stdin,
}

struct PeerPolicyArgs {
    peer_node_id: Option<String>,
    update: PeerPolicyUpdate,
    json: bool,
}

fn parse_peer_policy_args(args: &[String]) -> Result<PeerPolicyArgs, CliOutput> {
    let mut json = false;
    let mut update = PeerPolicyUpdate::empty();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
                index += 1;
            }
            "--messages" => {
                update.messages = Some(parse_peer_policy_bool(args.get(index + 1), "--messages")?);
                index += 2;
            }
            "--streams" => {
                update.streams = Some(parse_peer_policy_bool(args.get(index + 1), "--streams")?);
                index += 2;
            }
            "--rooms" => {
                update.rooms = Some(parse_peer_policy_bool(args.get(index + 1), "--rooms")?);
                index += 2;
            }
            "--files" => {
                update.files = Some(parse_peer_policy_bool(args.get(index + 1), "--files")?);
                index += 2;
            }
            "--mailbox" => {
                update.mailbox = Some(parse_peer_policy_bool(args.get(index + 1), "--mailbox")?);
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                positional.push(value.to_string());
                index += 1;
            }
        }
    }

    if positional.len() > 1 {
        return Err(CliOutput::failure(2, render_peer_policy_usage()));
    }
    if positional.is_empty() && update.has_changes() {
        return Err(CliOutput::failure(2, render_peer_policy_usage()));
    }

    Ok(PeerPolicyArgs {
        peer_node_id: positional.into_iter().next(),
        update,
        json,
    })
}

fn parse_peer_policy_bool(value: Option<&String>, option: &'static str) -> Result<bool, CliOutput> {
    parse_bool_option(value, option, render_peer_policy_usage())
}

fn render_peer_policy_usage() -> String {
    "usage: conu peers policy [<peer-node-id> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>]] [--json]".to_string()
}

fn parse_peer_trust_args(args: &[String]) -> Result<PeerTrustArgs, CliOutput> {
    let mut json = false;
    let mut exchange_key = None;
    let mut relay_endpoint = None;
    let mut direct_endpoint = None;
    let mut signing_key = None;
    let mut signature_algorithm = None;
    let mut signature_key_id = None;
    let mut signature = None;
    let mut card_source = None;
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--exchange-key" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                exchange_key = Some(value.clone());
                index += 1;
            }
            "--relay" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                relay_endpoint = Some(value.clone());
                index += 1;
            }
            "--direct" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                direct_endpoint = Some(value.clone());
                index += 1;
            }
            "--signing-key" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                signing_key = Some(value.clone());
                index += 1;
            }
            "--signature-algorithm" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                signature_algorithm = Some(value.clone());
                index += 1;
            }
            "--signature-key-id" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                signature_key_id = Some(value.clone());
                index += 1;
            }
            "--signature" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                signature = Some(value.clone());
                index += 1;
            }
            "--card" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                };
                if card_source.is_some() {
                    return Err(CliOutput::failure(2, render_peer_trust_usage()));
                }
                card_source = Some(if value == "-" {
                    PeerCardSource::Stdin
                } else {
                    PeerCardSource::File(PathBuf::from(value.as_str()))
                });
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if let Some(card_source) = card_source {
        if !positional.is_empty()
            || exchange_key.is_some()
            || signing_key.is_some()
            || signature_algorithm.is_some()
            || signature_key_id.is_some()
            || signature.is_some()
        {
            return Err(CliOutput::failure(2, render_peer_trust_usage()));
        }
        return Ok(PeerTrustArgs {
            peer_node_id: None,
            display_name: None,
            exchange_key: None,
            relay_endpoint,
            direct_endpoint,
            signing_key: None,
            signature_algorithm: None,
            signature_key_id: None,
            signature: None,
            card_source: Some(card_source),
            json,
        });
    }

    let Some(exchange_key) = exchange_key else {
        return Err(CliOutput::failure(2, render_peer_trust_usage()));
    };
    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_peer_trust_usage()));
    }
    if signature_algorithm.is_none()
        && (signing_key.is_some() || signature_key_id.is_some() || signature.is_some())
    {
        signature_algorithm = Some(security::AGENT_CARD_SIGNATURE_ALGORITHM.to_string());
    }

    Ok(PeerTrustArgs {
        peer_node_id: Some(positional.remove(0)),
        display_name: Some(positional.remove(0)),
        exchange_key: Some(exchange_key),
        relay_endpoint: Some(relay_endpoint.unwrap_or_else(|| "ws://127.0.0.1:8787".to_string())),
        direct_endpoint,
        signing_key,
        signature_algorithm,
        signature_key_id,
        signature,
        card_source: None,
        json,
    })
}

fn render_peer_trust_usage() -> String {
    "usage: conu peers trust --card <file|-> [--json]\n       conu peers trust <peer-node-id> <display-name> --exchange-key <hex> [--relay <ws://host:port|wss://host/path>] [--direct <quic://host:port>] [--signing-key <hex> --signature <hex> --signature-key-id <id>] [--signature-algorithm <algorithm>] [--json]".to_string()
}

fn render_peer_revoke_usage() -> String {
    "usage: conu peers revoke <peer-node-id> [--json]".to_string()
}

fn peer_card_from_source(
    source: &PeerCardSource,
    stdin_payload: Vec<u8>,
    relay_override: Option<String>,
    direct_override: Option<String>,
) -> Result<PeerCard, CliOutput> {
    let bytes = match source {
        PeerCardSource::Stdin => {
            if stdin_payload.is_empty() {
                return Err(CliOutput::failure(
                    2,
                    "peer card stdin is empty; contentsDisplayed=false",
                ));
            }
            if stdin_payload.len() > MAX_PEER_CARD_BYTES {
                return Err(CliOutput::failure(
                    2,
                    format!(
                        "peer card exceeds {MAX_PEER_CARD_BYTES} bytes; contentsDisplayed=false"
                    ),
                ));
            }
            stdin_payload
        }
        PeerCardSource::File(path) => read_peer_card_file(path)?,
    };

    let mut card = parse_peer_card_json(&bytes).map_err(|error| {
        CliOutput::failure(2, format!("conU peer card import failed\n\n{error}"))
    })?;
    let signed = peer_card_has_signature_fields(&card);
    if let Some(relay_endpoint) = relay_override {
        if signed && relay_endpoint != card.relay_endpoint {
            return Err(CliOutput::failure(
                2,
                "signed peer-card relay overrides are not supported; re-export with conu identity export --relay <endpoint> --json\ncontentsDisplayed=false",
            ));
        }
        card.relay_endpoint = relay_endpoint;
    }
    if let Some(direct_endpoint) = direct_override {
        if signed && card.direct_quic_endpoint.as_deref() != Some(direct_endpoint.as_str()) {
            return Err(CliOutput::failure(
                2,
                "signed peer-card direct endpoint overrides are not supported; re-export with conu identity export --direct <quic://host:port> --json\ncontentsDisplayed=false",
            ));
        }
        card.direct_quic_endpoint = Some(direct_endpoint);
    }
    Ok(card)
}

fn peer_card_has_signature_fields(card: &PeerCard) -> bool {
    card.signing_public_key_hex.is_some()
        || card.signature_algorithm.is_some()
        || card.signature_key_id.is_some()
        || card.signature_hex.is_some()
}

fn read_peer_card_file(path: &Path) -> Result<Vec<u8>, CliOutput> {
    if path.as_os_str().is_empty() {
        return Err(CliOutput::failure(
            2,
            "peer card file path is empty; contentsDisplayed=false",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CliOutput::failure(
            2,
            format!("could not inspect peer card file: {error}; contentsDisplayed=false"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliOutput::failure(
            2,
            "peer card path must be a regular file; contentsDisplayed=false",
        ));
    }
    if metadata.len() > MAX_PEER_CARD_BYTES as u64 {
        return Err(CliOutput::failure(
            2,
            format!("peer card exceeds {MAX_PEER_CARD_BYTES} bytes; contentsDisplayed=false"),
        ));
    }

    let file = fs::File::open(path).map_err(|error| {
        CliOutput::failure(
            2,
            format!("could not open peer card file: {error}; contentsDisplayed=false"),
        )
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        CliOutput::failure(
            2,
            format!("could not inspect opened peer card file: {error}; contentsDisplayed=false"),
        )
    })?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_PEER_CARD_BYTES as u64 {
        return Err(CliOutput::failure(
            2,
            format!("peer card exceeds {MAX_PEER_CARD_BYTES} bytes; contentsDisplayed=false"),
        ));
    }

    let mut bytes = Vec::new();
    file.take((MAX_PEER_CARD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliOutput::failure(
                2,
                format!("could not read peer card file: {error}; contentsDisplayed=false"),
            )
        })?;
    if bytes.is_empty() {
        return Err(CliOutput::failure(
            2,
            "peer card file is empty; contentsDisplayed=false",
        ));
    }
    if bytes.len() > MAX_PEER_CARD_BYTES {
        return Err(CliOutput::failure(
            2,
            format!("peer card exceeds {MAX_PEER_CARD_BYTES} bytes; contentsDisplayed=false"),
        ));
    }
    Ok(bytes)
}

fn parse_peer_card_json(bytes: &[u8]) -> Result<PeerCard, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = DuplicateKeyCheckedJson
        .deserialize(&mut deserializer)
        .map_err(|error| format!("peer card JSON is invalid: {error}; contentsDisplayed=false"))?;
    deserializer
        .end()
        .map_err(|error| format!("peer card JSON is invalid: {error}; contentsDisplayed=false"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "peer card JSON must be an object; contentsDisplayed=false".to_string())?;

    Ok(PeerCard {
        node_id: peer_card_required_string(object, "nodeId")?,
        display_name: peer_card_required_string(object, "displayName")?,
        exchange_public_key_hex: peer_card_required_string(object, "exchangePublicKeyHex")?,
        relay_endpoint: peer_card_required_string(object, "relayEndpoint")?,
        direct_quic_endpoint: peer_card_optional_string(object, "directQuicEndpoint")?,
        signing_public_key_hex: peer_card_optional_string(object, "signingPublicKeyHex")?,
        signature_algorithm: peer_card_optional_string(object, "signatureAlgorithm")?,
        signature_key_id: peer_card_optional_string(object, "signatureKeyId")?,
        signature_hex: peer_card_optional_string(object, "signatureHex")?,
    })
}

fn peer_card_required_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            format!("peer card is missing non-empty string field {field}; contentsDisplayed=false")
        })
}

fn peer_card_optional_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(text) = value.as_str() else {
        return Err(format!(
            "peer card field {field} must be a string; contentsDisplayed=false"
        ));
    };
    let text = text.trim();
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(text.to_string()))
    }
}

fn parse_peer_revoke_args(args: &[String]) -> Result<(String, bool), CliOutput> {
    let mut json = false;
    let mut peer = None;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => {
                if peer.is_some() {
                    return Err(CliOutput::failure(2, render_peer_revoke_usage()));
                }
                peer = Some(value.to_string());
            }
        }
    }

    let Some(peer) = peer else {
        return Err(CliOutput::failure(2, render_peer_revoke_usage()));
    };

    Ok((peer, json))
}

fn render_pair(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu pair [--json]");
    }
    match json_flag(args) {
        Ok(json) => match trust::create_pairing_invite(home_override) {
            Ok(invite) => {
                if json {
                    CliOutput::success(format!(
                        r#"{{
  "status": "pairing_code_created",
  "code": "{}",
  "peerNodeId": "{}",
  "expiresAtUnix": {},
  "relay": "service_available",
  "contentsDisplayed": false
}}"#,
                        invite.code,
                        json_escape(&invite.peer_node_id),
                        invite.expires_at_unix
                    ))
                } else {
                    CliOutput::success(format!(
                        r"conU pair

status: pairing code created
code: {}
peer: {}
expires at unix: {}
relay: service available; pairing rendezvous still local

next
  conu join {}",
                        invite.code, invite.peer_node_id, invite.expires_at_unix, invite.code
                    ))
                }
            }
            Err(error) => CliOutput::failure(1, format!("conU pair failed\n\n{error}")),
        },
        Err(error) => error,
    }
}

fn render_join(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu join <code> [--json]");
    }
    let json = args.iter().any(|arg| arg == "--json");

    match join_code(args) {
        Ok(code) => match trust::join_pairing_code(home_override, code) {
            Ok(report) => {
                if json {
                    CliOutput::success(format!(
                        r#"{{
  "status": "trusted",
  "peerNodeId": "{}",
  "displayName": "{}",
  "contentsDisplayed": false
}}"#,
                        json_escape(&report.peer.peer_node_id),
                        json_escape(&report.peer.display_name)
                    ))
                } else {
                    CliOutput::success(format!(
                        r"conU join

status: trusted
peer: {}
name: {}
source: local pairing code

next
  conu peers",
                        report.peer.peer_node_id, report.peer.display_name
                    ))
                }
            }
            Err(error) => CliOutput::failure(1, format!("conU join failed\n\n{error}")),
        },
        Err(error) => error,
    }
}

fn render_connect(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_connect_usage()),
        Some("local") if is_help_request(&args[1..]) => CliOutput::success(render_connect_usage()),
        Some("room") if is_help_request(&args[1..]) => CliOutput::success(render_connect_usage()),
        Some("local") => render_connect_local(&args[1..], home_override),
        Some("room") => render_connect_room(&args[1..], home_override),
        Some(value) if value.starts_with("--") => {
            if let Some(error) = reject_args(args) {
                error
            } else {
                render_connect_selector(home_override)
            }
        }
        Some(_) => CliOutput::failure(2, render_connect_usage()),
        None => render_connect_selector(home_override),
    }
}

fn render_connect_local(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_connect_local_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match agents::agent_exists(home_override.clone(), &parsed.to_agent_id) {
        Ok(true) => {}
        Ok(false) => {
            return CliOutput::failure(
                1,
                "conU connect local failed\n\ntarget local agent is not registered locally",
            );
        }
        Err(error) => {
            return CliOutput::failure(1, format!("conU connect local failed\n\n{error}"));
        }
    }

    match streams::open_stream(
        home_override,
        &parsed.from_agent_id,
        &parsed.to_agent_id,
        &parsed.kind,
    ) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(format!(
                    r#"{{
  "status": "connected",
  "mode": "local-stream",
  "streamId": "{}",
  "fromAgentId": "{}",
  "toAgentId": "{}",
  "kind": "{}",
  "route": "{}",
  "contentsDisplayed": false
}}"#,
                    json_escape(&report.stream.stream_id),
                    json_escape(&report.stream.from_agent_id),
                    json_escape(&report.stream.to_agent_id),
                    json_escape(&report.stream.kind),
                    json_escape(&report.stream.route)
                ))
            } else {
                CliOutput::success(format!(
                    r"conU connect local

status: connected
mode: local stream
stream: {}
from: {}
to: {}
kind: {}
route: {}

privacy
  payload view  contents are not displayed by conU
  contentsDisplayed=false

next
  conu streams write {} --stdin",
                    report.stream.stream_id,
                    report.stream.from_agent_id,
                    report.stream.to_agent_id,
                    report.stream.kind,
                    report.stream.route,
                    report.stream.stream_id
                ))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU connect local failed\n\n{error}")),
    }
}

fn render_connect_room(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_connect_room_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match rooms::join_room(home_override, &parsed.room_id, &parsed.agent_id) {
        Ok(report) => {
            let status = if report.joined {
                "connected"
            } else {
                "already_connected"
            };
            if parsed.json {
                CliOutput::success(format!(
                    r#"{{
  "status": "{}",
  "mode": "room",
  "roomId": "{}",
  "agentId": "{}",
  "participants": {},
  "contentsDisplayed": false
}}"#,
                    status,
                    json_escape(&report.room.room_id),
                    json_escape(&parsed.agent_id),
                    report.room.participants.len()
                ))
            } else {
                CliOutput::success(format!(
                    r"conU connect room

status: {status}
room: {}
agent: {}
participants: {}

privacy
  payload view  contents are not displayed by conU
  contentsDisplayed=false

next
  conu rooms publish {} {} <topic> --stdin",
                    report.room.room_id,
                    parsed.agent_id,
                    report.room.participants.len(),
                    report.room.room_id,
                    parsed.agent_id
                ))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU connect room failed\n\n{error}")),
    }
}

fn render_connect_selector(home_override: Option<PathBuf>) -> CliOutput {
    let local_agents = agents::list_local_agents(home_override.clone()).unwrap_or_default();
    let route_records = routes::list_routes(home_override.clone()).unwrap_or_default();
    let rooms = rooms::list_rooms(home_override.clone()).unwrap_or_default();
    let remote_agents = sessions::list_remote_agents(home_override).unwrap_or_default();
    let local = if local_agents.is_empty() {
        "none registered".to_string()
    } else {
        local_agents
            .iter()
            .map(|agent| {
                format!(
                    "{} ({}, {})",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.kind
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let remote = if remote_agents.is_empty() {
        "none visible".to_string()
    } else {
        remote_agents
            .iter()
            .map(|agent| {
                format!(
                    "{} ({}, peer {})",
                    agent.agent_id,
                    agent.presence.as_str(),
                    agent.peer_node_id
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let room_list = if rooms.is_empty() {
        "none created".to_string()
    } else {
        rooms
            .iter()
            .map(|room| {
                format!(
                    "{} ({} participants, {} topics)",
                    room.room_id,
                    room.participants.len(),
                    room.topics.len()
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let next_steps = connect_next_steps(&local_agents, &remote_agents, &rooms);

    CliOutput::success(format!(
        r"conU connect

selector
  source local agent   {local}
  target remote agent  {remote}
  room bus             {room_list}
  route plan           direct {} | relay {}
  mode                 local stream | room | remote relay message

next
{next_steps}

privacy
  payload view  contents are not displayed by conU
  contentsDisplayed=false",
        selected_direct_route_count(&route_records),
        selected_relay_route_count(&route_records)
    ))
}

fn connect_next_steps(
    local_agents: &[LocalAgentRecord],
    remote_agents: &[RemoteAgentRecord],
    rooms: &[RoomRecord],
) -> String {
    let mut steps = Vec::new();

    if local_agents.len() < 2 {
        steps.push("conu setup --start".to_string());
    } else {
        steps.push(format!(
            "conu connect local {} {}",
            local_agents[0].agent_id, local_agents[1].agent_id
        ));
        steps.push(format!(
            "conu chat {} {}",
            local_agents[0].agent_id, local_agents[1].agent_id
        ));
    }

    if let Some((room, agent)) = rooms.iter().find_map(|room| {
        local_agents
            .iter()
            .find(|agent| {
                !room
                    .participants
                    .iter()
                    .any(|participant| participant.agent_id == agent.agent_id)
            })
            .map(|agent| (room, agent))
    }) {
        steps.push(format!(
            "conu connect room {} {}",
            room.room_id, agent.agent_id
        ));
    } else if let (Some(room), Some(agent)) = (rooms.first(), local_agents.first()) {
        steps.push(format!(
            "conu rooms publish {} {} <topic> --stdin",
            room.room_id, agent.agent_id
        ));
    } else if let Some(agent) = local_agents.first() {
        steps.push(format!(
            "conu rooms create room.dev \"Dev Room\" --agent {}",
            agent.agent_id
        ));
    }

    if let (Some(local), Some(remote)) = (local_agents.first(), remote_agents.first()) {
        steps.push(format!(
            "conu send {} {} --peer {} --file ./message.bin --json",
            local.agent_id, remote.agent_id, remote.peer_node_id
        ));
    } else {
        steps.push("conu pair".to_string());
        steps.push("conu join <code>".to_string());
    }

    steps.push("conu watch".to_string());

    steps
        .into_iter()
        .map(|step| format!("  {step}"))
        .collect::<Vec<_>>()
        .join("\n")
}

struct ConnectLocalArgs {
    from_agent_id: String,
    to_agent_id: String,
    kind: String,
    json: bool,
}

struct ConnectRoomArgs {
    room_id: String,
    agent_id: String,
    json: bool,
}

fn parse_connect_local_args(args: &[String]) -> Result<ConnectLocalArgs, CliOutput> {
    let mut json = false;
    let mut kind = "message".to_string();
    let mut positional = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--kind" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(CliOutput::failure(2, render_connect_usage()));
                };
                kind = value.clone();
                index += 1;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_connect_usage()));
    }

    Ok(ConnectLocalArgs {
        from_agent_id: positional.remove(0),
        to_agent_id: positional.remove(0),
        kind,
        json,
    })
}

fn parse_connect_room_args(args: &[String]) -> Result<ConnectRoomArgs, CliOutput> {
    let mut json = false;
    let mut positional = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            value => positional.push(value.to_string()),
        }
    }

    if positional.len() != 2 {
        return Err(CliOutput::failure(2, render_connect_usage()));
    }

    Ok(ConnectRoomArgs {
        room_id: positional.remove(0),
        agent_id: positional.remove(0),
        json,
    })
}

fn render_connect_usage() -> String {
    r"usage:
  conu connect
  conu connect local <from-agent> <to-agent> [--kind <kind>] [--json]
  conu connect room <room-id> <agent-id> [--json]

quick start:
  conu setup --start
  conu connect

privacy:
  connect shows agents, rooms, routes, and commands only
  payload contents are never displayed
  contentsDisplayed=false"
        .to_string()
}

fn render_watch(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu watch");
    }
    if let Some(error) = reject_args(args) {
        return error;
    }

    let stream_records = streams::list_streams(home_override.clone()).unwrap_or_default();
    let events = streams::list_events(home_override.clone()).unwrap_or_default();
    let room_records = rooms::list_rooms(home_override.clone()).unwrap_or_default();
    let room_events = rooms::list_room_events(home_override.clone()).unwrap_or_default();
    let relay_queue = relay_delivery::relay_queue_summary(home_override).ok();
    let open_streams = stream_records
        .iter()
        .filter(|stream| stream.state.as_str() == "open")
        .count();
    let total_packets: u64 = stream_records
        .iter()
        .map(|stream| stream.chunks_written)
        .sum();
    let total_bytes: usize = stream_records
        .iter()
        .map(|stream| stream.bytes_written)
        .sum();
    let latest = events.last();
    let flow = latest
        .map(|event| {
            format!(
                "{}  == encrypted stream ==>  {}",
                event.from_agent_id, event.to_agent_id
            )
        })
        .unwrap_or_else(|| "local-agent   -> conUD -> encrypted route -> remote-agent".to_string());
    let route = latest
        .map(|event| event.route.as_str())
        .unwrap_or("inactive");
    let stream_id = latest
        .map(|event| event.stream_id.as_str())
        .unwrap_or("none");
    let latest_event = latest
        .map(|event| event.event_type.as_str())
        .unwrap_or("idle");
    let latest_room = room_events.last();
    let room_flow = latest_room
        .map(|event| {
            format!(
                "{}  == private room event ==>  room {}",
                event.from_agent_id, event.room_id
            )
        })
        .unwrap_or_else(|| "agent       -> conUD room bus -> subscribed agents".to_string());
    let latest_room_topic = latest_room
        .map(|event| event.topic.as_str())
        .unwrap_or("idle");
    let latest_room_bytes = latest_room
        .map(|event| event.payload_bytes)
        .unwrap_or_default();
    let relay_queued = relay_queue.as_ref().map(|queue| queue.queued).unwrap_or(0);
    let relay_sent = relay_queue.as_ref().map(|queue| queue.sent).unwrap_or(0);
    let relay_rejected = relay_queue
        .as_ref()
        .map(|queue| queue.rejected)
        .unwrap_or(0);

    CliOutput::success(format!(
        r"conU watch

private transport view
  {flow}
  {room_flow}

  .-----------.      .--------.      .-------------.
  |  agent A  | ---> | conUD  | ---> | room / bus  |
  '-----------'      '--------'      '-------------'
        |                |
        |                v
        |          .------------.      .---------.
        '=======>  | blind relay | ===> | agent B |
                   '------------'      '---------'
                    peer-encrypted envelopes
                    daemon pump when configured

live counters
  route         {route}
  stream        {stream_id}
  event         {latest_event}
  open streams  {open_streams}
  rooms         {rooms_count}
  room events   {room_events_count}
  room topic    {latest_room_topic}
  room bytes    {latest_room_bytes}
  packets       {total_packets}
  bytes         {total_bytes}
  relay queued  {relay_queued}
  relay sent    {relay_sent}
  relay reject  {relay_rejected}
  contents      not displayed

animation
  [agent] >>> private packets >>> [conUD] >>> room/relay >>> [agent]

status: metadata animation only",
        rooms_count = room_records.len(),
        room_events_count = room_events.len(),
    ))
}

fn render_components(args: &[String]) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu components");
    }
    if let Some(error) = reject_args(args) {
        return error;
    }

    let mut output = String::from("conU components\n\n");
    for component in conu_core::COMPONENTS {
        output.push_str(component.name);
        output.push_str("\n  ");
        output.push_str(component.responsibility);
        output.push('\n');
    }
    CliOutput::success(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogRotateArgs {
    max_bytes: u64,
    keep_archives: usize,
    json: bool,
}

fn render_logs(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("rotate") => render_logs_rotate(&args[1..], home_override),
        Some("--help") | Some("-h") | None => CliOutput::success(render_logs_usage()),
        _ => CliOutput::failure(2, render_logs_usage()),
    }
}

fn render_logs_rotate(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let parsed = match parse_log_rotate_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let policy = match LogRotationPolicy::new(parsed.max_bytes, parsed.keep_archives) {
        Ok(policy) => policy,
        Err(error) => return CliOutput::failure(2, format!("conU logs rotate failed\n\n{error}")),
    };
    let report = match observability::rotate_logs(home_override, policy) {
        Ok(report) => report,
        Err(error) => return CliOutput::failure(1, format!("conU logs rotate failed\n\n{error}")),
    };

    if parsed.json {
        CliOutput::success(render_logs_rotate_json(&report))
    } else {
        CliOutput::success(render_logs_rotate_text(&report))
    }
}

fn parse_log_rotate_args(args: &[String]) -> Result<LogRotateArgs, CliOutput> {
    let mut max_bytes = observability::DEFAULT_LOG_ROTATE_MAX_BYTES;
    let mut keep_archives = observability::DEFAULT_LOG_ROTATE_KEEP_ARCHIVES;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--max-bytes" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_logs_usage()));
                };
                max_bytes = value
                    .parse::<u64>()
                    .map_err(|_| CliOutput::failure(2, render_logs_usage()))?;
            }
            "--keep" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_logs_usage()));
                };
                keep_archives = value
                    .parse::<usize>()
                    .map_err(|_| CliOutput::failure(2, render_logs_usage()))?;
            }
            "--help" | "-h" => return Err(CliOutput::success(render_logs_usage())),
            _ => return Err(CliOutput::failure(2, render_logs_usage())),
        }
        index += 1;
    }

    Ok(LogRotateArgs {
        max_bytes,
        keep_archives,
        json,
    })
}

fn render_logs_rotate_json(report: &LogRotationReport) -> String {
    let log_items = report
        .entries
        .iter()
        .map(|entry| {
            format!(
                r#"    {{
      "name": "{}",
      "sizeBytes": {},
      "rotated": {},
      "archivesRemoved": {}
    }}"#,
                json_escape(&entry.log_name),
                entry.size_bytes,
                entry.rotated,
                entry.archives_removed
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let logs = if log_items.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{log_items}\n  ]")
    };

    format!(
        r#"{{
  "status": "rotated",
  "maxBytes": {},
  "keepArchives": {},
  "filesScanned": {},
  "filesRotated": {},
  "archivesRemoved": {},
  "logs": {},
  "contentsDisplayed": false
}}"#,
        report.max_bytes,
        report.keep_archives,
        report.files_scanned,
        report.files_rotated,
        report.archives_removed,
        logs
    )
}

fn render_logs_rotate_text(report: &LogRotationReport) -> String {
    let logs = report
        .entries
        .iter()
        .map(|entry| {
            format!(
                "  {}  size {}  rotated {}  removed {}",
                entry.log_name,
                entry.size_bytes,
                yes_no(entry.rotated),
                entry.archives_removed
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let logs = if logs.is_empty() {
        "  none found".to_string()
    } else {
        logs
    };

    format!(
        r"conU logs rotate

status: rotated
max bytes: {}
keep archives: {}
files scanned: {}
files rotated: {}
archives removed: {}

logs
{logs}

privacy
  payload view  contents are not displayed by conU",
        report.max_bytes,
        report.keep_archives,
        report.files_scanned,
        report.files_rotated,
        report.archives_removed
    )
}

fn render_logs_usage() -> String {
    r"usage:
  conu logs rotate [--max-bytes <bytes>] [--keep <count>] [--json]"
        .to_string()
}

struct TelemetryView<'a> {
    snapshot: &'a StateSnapshot,
    runtime_status: &'a RuntimeStatus,
    local_agents: &'a [LocalAgentRecord],
    remote_agents: &'a [RemoteAgentRecord],
    sessions: &'a [RemoteSession],
    stream_records: &'a [StreamRecord],
    room_records: &'a [RoomRecord],
    room_events: &'a [RoomEvent],
    route_records: &'a [RouteRecord],
    peers: &'a [TrustedPeer],
    relay_queue: &'a relay_delivery::RelayQueueSummary,
    security: &'a SecurityAudit,
    log_scan: &'a DoctorLogScan,
}

fn render_telemetry(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("snapshot") => render_telemetry_snapshot(&args[1..], home_override),
        Some("--help") | Some("-h") | None => CliOutput::success(render_telemetry_usage()),
        _ => CliOutput::failure(2, render_telemetry_usage()),
    }
}

fn render_telemetry_snapshot(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let snapshot = match state::read_state(home_override.clone()) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let runtime_status = match runtime::read_runtime(home_override.clone()) {
        Ok(status) => status,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let local_agents = match agents::list_local_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let peers = match trust::list_peers(home_override.clone()) {
        Ok(peers) => peers,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let sessions = match sessions::list_remote_sessions(home_override.clone()) {
        Ok(sessions) => sessions,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let remote_agents = match sessions::list_remote_agents(home_override.clone()) {
        Ok(agents) => agents,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let stream_records = match streams::list_streams(home_override.clone()) {
        Ok(streams) => streams,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let room_records = match rooms::list_rooms(home_override.clone()) {
        Ok(rooms) => rooms,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let room_events = match rooms::list_room_events(home_override.clone()) {
        Ok(events) => events,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let route_records = match routes::list_routes(home_override.clone()) {
        Ok(routes) => routes,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let relay_queue = match relay_delivery::relay_queue_summary(home_override.clone()) {
        Ok(queue) => queue,
        Err(error) => {
            return CliOutput::failure(1, format!("conU telemetry snapshot failed\n\n{error}"));
        }
    };
    let security_audit =
        security::security_audit(home_override).unwrap_or_else(|_| empty_security_audit());
    let log_scan = scan_payload_safe_logs(&snapshot);
    let view = TelemetryView {
        snapshot: &snapshot,
        runtime_status: &runtime_status,
        local_agents: &local_agents,
        remote_agents: &remote_agents,
        sessions: &sessions,
        stream_records: &stream_records,
        room_records: &room_records,
        room_events: &room_events,
        route_records: &route_records,
        peers: &peers,
        relay_queue: &relay_queue,
        security: &security_audit,
        log_scan: &log_scan,
    };

    if json {
        CliOutput::success(render_telemetry_snapshot_json(&view))
    } else {
        CliOutput::success(render_telemetry_snapshot_text(&view))
    }
}

fn render_telemetry_snapshot_json(view: &TelemetryView<'_>) -> String {
    let snapshot = view.snapshot;
    let runtime_status = view.runtime_status;
    let security = view.security;
    let log_scan = view.log_scan;
    let relay_queue = view.relay_queue;

    format!(
        r#"{{
  "schema": "{}",
  "fieldAllowlist": {},
  "state": {{
    "initialized": {},
    "configReady": {},
    "trustStoreReady": {},
    "agentRegistryReady": {}
  }},
  "runtime": {{
    "state": "{}",
    "health": "{}",
    "heartbeatAgeSecs": {}
  }},
  "agents": {{
    "local": {},
    "remote": {},
    "trustedPeers": {},
    "sessions": {}
  }},
  "streams": {{
    "total": {},
    "open": {}
  }},
  "rooms": {{
    "total": {},
    "events": {}
  }},
  "routes": {{
    "selected": {},
    "selectedDirect": {},
    "selectedRelay": {},
    "relayFallbacks": {}
  }},
  "relay": {{
    "queued": {},
    "sent": {},
    "rejected": {}
  }},
  "logs": {{
    "payloadSafe": {},
    "scannedFiles": {},
    "issues": {}
  }},
  "security": {{
    "initialized": {},
    "localPayloadEncryption": {},
    "signedAgentCards": {},
    "peerKeyExchange": {},
    "replayCache": {},
    "keyRotationPlan": {},
    "secretsOsProtected": {}
  }},
  "privacy": {{
    "fieldAllowlistOnly": true,
    "contentsDisplayed": false
  }}
}}"#,
        json_escape(observability::TELEMETRY_SNAPSHOT_SCHEMA),
        json_string_array(observability::TELEMETRY_FIELD_ALLOWLIST),
        snapshot.is_initialized(),
        snapshot.config_exists,
        snapshot.trust_store_exists,
        snapshot.agent_registry_exists,
        runtime_status.state.as_str(),
        json_escape(runtime_health_label(runtime_status)),
        json_u64(runtime_status.heartbeat_age_secs()),
        view.local_agents.len(),
        view.remote_agents.len(),
        trusted_peer_count(view.peers),
        view.sessions.len(),
        view.stream_records.len(),
        open_stream_count(view.stream_records),
        view.room_records.len(),
        view.room_events.len(),
        selected_route_count(view.route_records),
        selected_direct_route_count(view.route_records),
        selected_relay_route_count(view.route_records),
        relay_fallback_route_count(view.route_records),
        relay_queue.queued,
        relay_queue.sent,
        relay_queue.rejected,
        log_scan.payload_safe,
        log_scan.scanned_files,
        log_scan.issues,
        security.initialized,
        security.local_payload_encryption,
        security.signed_agent_cards,
        security.peer_key_exchange,
        security.replay_cache,
        security.key_rotation_plan,
        security.secrets_os_protected
    )
}

fn render_telemetry_snapshot_text(view: &TelemetryView<'_>) -> String {
    let snapshot = view.snapshot;
    let runtime_status = view.runtime_status;
    let security = view.security;
    let log_scan = view.log_scan;
    let relay_queue = view.relay_queue;

    format!(
        r"conU telemetry snapshot

schema: {}
field allowlist: {} fields

state
  initialized       {}
  config            {}
  trust store       {}
  agent registry    {}

runtime
  conUD             {}
  health            {}
  heartbeat age     {}

agents
  local             {}
  remote            {}
  trusted peers     {}
  sessions          {}

streams
  total             {}
  open              {}

rooms
  total             {}
  events            {}

routes
  selected          {}
  direct            {}
  relay             {}
  relay fallback    {}

relay
  queued            {}
  sent              {}
  rejected          {}

logs
  payload safe      {}
  scanned files     {}
  issues            {}

security
  initialized       {}
  local payloads    {}
  signed agents     {}
  peer exchange     {}
  replay guard      {}
  key rotation      {}
  os secret store   {}

privacy
  field allowlist   enforced
  payload view      contents are not displayed by conU",
        observability::TELEMETRY_SNAPSHOT_SCHEMA,
        observability::TELEMETRY_FIELD_ALLOWLIST.len(),
        yes_no(snapshot.is_initialized()),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        ready_label(snapshot.agent_registry_exists),
        runtime_state_label(runtime_status),
        runtime_health_label(runtime_status),
        optional_u64_label(runtime_status.heartbeat_age_secs()),
        view.local_agents.len(),
        view.remote_agents.len(),
        trusted_peer_count(view.peers),
        view.sessions.len(),
        view.stream_records.len(),
        open_stream_count(view.stream_records),
        view.room_records.len(),
        view.room_events.len(),
        selected_route_count(view.route_records),
        selected_direct_route_count(view.route_records),
        selected_relay_route_count(view.route_records),
        relay_fallback_route_count(view.route_records),
        relay_queue.queued,
        relay_queue.sent,
        relay_queue.rejected,
        yes_no(log_scan.payload_safe),
        log_scan.scanned_files,
        log_scan.issues,
        ready_label(security.initialized),
        yes_no(security.local_payload_encryption),
        yes_no(security.signed_agent_cards),
        yes_no(security.peer_key_exchange),
        yes_no(security.replay_cache),
        yes_no(security.key_rotation_plan),
        yes_no(security.secrets_os_protected)
    )
}

fn render_telemetry_usage() -> String {
    r"usage:
  conu telemetry snapshot [--json]"
        .to_string()
}

const UPDATE_POLICY_SCHEMA: &str = "conu.releaseUpdatePolicy.v1";
const MAX_UPDATE_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_UPDATE_CHECKSUM_BYTES: u64 = 4096;
const MAX_UPDATE_SIGNATURE_BYTES: u64 = 1024 * 1024;
const MAX_UPDATE_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_UPDATE_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_UPDATE_REDIRECTS: usize = 3;
const UPDATE_DOWNLOAD_TIMEOUT_SECONDS: u64 = 20;
const MAX_UPDATE_ARCHIVE_ENTRIES: usize = 512;
const MAX_UPDATE_ARCHIVE_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_UPDATE_ARCHIVE_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_UPDATE_ARCHIVE_MANIFEST_BYTES: u64 = 64 * 1024;
const UPDATE_BINARY_NAMES: [&str; 4] = ["conu", "conud", "conu-relay", "conu-mcp"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateCheckArgs {
    policy_file: Option<PathBuf>,
    policy_url: Option<String>,
    sha256_file: Option<PathBuf>,
    sha256_url: Option<String>,
    signature_file: Option<PathBuf>,
    signature_url: Option<String>,
    gpg_verify: bool,
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateCheckSource {
    Local,
    Remote,
}

impl UpdateCheckSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateCheckReport {
    source: UpdateCheckSource,
    policy_location: String,
    sha256_location: String,
    signature_location: String,
    sha256: String,
    version: String,
    release_tag: String,
    channel: String,
    release_base_url: String,
    platform_archives: usize,
    package_manager_assets: usize,
    linux_package_assets: usize,
    repository_assets: usize,
    auto_apply: bool,
    manual_verification_required: bool,
    operator_consent_required: bool,
    gpg_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateCheckFiles {
    policy_file: PathBuf,
    sha256_file: PathBuf,
    signature_file: PathBuf,
    source: UpdateCheckSource,
    policy_location: String,
    sha256_location: String,
    signature_location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateDownloadArgs {
    check: UpdateCheckArgs,
    target: Option<String>,
    output_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateApplyArgs {
    check: UpdateCheckArgs,
    target: Option<String>,
    artifact_file: PathBuf,
    install_dir: PathBuf,
    dry_run: bool,
    confirm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedUpdatePolicy {
    report: UpdateCheckReport,
    policy: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateArtifactAsset {
    filename: String,
    target: String,
    url: String,
    sha256: String,
    sha256_url: String,
    signature_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateArtifactFiles {
    artifact_file: PathBuf,
    sha256_file: PathBuf,
    signature_file: PathBuf,
    bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateArtifactDownloadReport {
    policy: UpdateCheckReport,
    target: String,
    filename: String,
    url: String,
    artifact_file: PathBuf,
    sha256_file: PathBuf,
    signature_file: PathBuf,
    bytes: usize,
    sha256: String,
    gpg_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateApplyBinaryReport {
    name: String,
    source_file: PathBuf,
    target_file: PathBuf,
    backup_file: Option<PathBuf>,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateApplyReport {
    policy: UpdateCheckReport,
    target: String,
    filename: String,
    archive_file: PathBuf,
    install_dir: PathBuf,
    backup_dir: Option<PathBuf>,
    entries_scanned: usize,
    unpacked_bytes: u64,
    binaries: Vec<UpdateApplyBinaryReport>,
    sha256: String,
    gpg_verified: bool,
    dry_run: bool,
    update_applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedUpdateBinary {
    name: String,
    source_file: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug)]
struct StagedUpdateArchive {
    _staging_dir: UpdateDownloadDir,
    manifest_target: String,
    entries_scanned: usize,
    unpacked_bytes: u64,
    binaries: Vec<StagedUpdateBinary>,
}

fn render_update(args: &[String]) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("check") => render_update_check(&args[1..]),
        Some("download") => render_update_download(&args[1..]),
        Some("apply") => render_update_apply(&args[1..]),
        Some("--help") | Some("-h") | None => CliOutput::success(render_update_usage()),
        _ => CliOutput::failure(2, render_update_usage()),
    }
}

fn render_update_check(args: &[String]) -> CliOutput {
    let parsed = match parse_update_check_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match check_release_update_policy(&parsed) {
        Ok(report) => {
            if parsed.json {
                CliOutput::success(render_update_check_json(&report))
            } else {
                CliOutput::success(render_update_check_text(&report))
            }
        }
        Err(error) => update_command_failure("check", &error),
    }
}

fn render_update_download(args: &[String]) -> CliOutput {
    let parsed = match parse_update_download_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match download_release_update_artifact(&parsed) {
        Ok(report) => {
            if parsed.check.json {
                CliOutput::success(render_update_download_json(&report))
            } else {
                CliOutput::success(render_update_download_text(&report))
            }
        }
        Err(error) => update_command_failure("download", &error),
    }
}

fn render_update_apply(args: &[String]) -> CliOutput {
    let parsed = match parse_update_apply_args(args) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match apply_release_update_artifact(&parsed) {
        Ok(report) => {
            if parsed.check.json {
                CliOutput::success(render_update_apply_json(&report))
            } else {
                CliOutput::success(render_update_apply_text(&report))
            }
        }
        Err(error) => update_command_failure("apply", &error),
    }
}

fn update_command_failure(command: &str, error: &str) -> CliOutput {
    CliOutput::failure(
        1,
        format!(
            "conU update {command} failed\n\n{}\n\ncontentsDisplayed=false",
            redact_update_failure_paths(error)
        ),
    )
}

fn redact_update_failure_paths(error: &str) -> String {
    let mut output = String::with_capacity(error.len());
    let mut token = String::new();

    for ch in error.chars() {
        if ch.is_whitespace() {
            append_redacted_update_failure_token(&mut output, &token);
            token.clear();
            output.push(ch);
        } else {
            token.push(ch);
        }
    }
    append_redacted_update_failure_token(&mut output, &token);

    output
}

fn append_redacted_update_failure_token(output: &mut String, token: &str) {
    if token.is_empty() {
        return;
    }

    if is_update_local_path_token(token) {
        output.push_str("local; pathDisplayed=false");
    } else {
        output.push_str(token);
    }
}

fn is_update_local_path_token(token: &str) -> bool {
    let trimmed = token.trim_matches(|ch: char| {
        matches!(
            ch,
            '"' | '\'' | '`' | ',' | ';' | ':' | '!' | '?' | '(' | ')' | '[' | ']' | '{' | '}'
        )
    });
    let lower = trimmed.to_ascii_lowercase();

    if lower.contains("http://") || lower.contains("https://") {
        return false;
    }
    if trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
        return true;
    }

    let bytes = trimmed.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }

    trimmed.contains('\\') || trimmed.contains('/')
}

fn parse_update_check_args(args: &[String]) -> Result<UpdateCheckArgs, CliOutput> {
    let mut policy_file = None;
    let mut policy_url = None;
    let mut sha256_file = None;
    let mut sha256_url = None;
    let mut signature_file = None;
    let mut signature_url = None;
    let mut gpg_verify = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_check_usage()));
                };
                policy_file = Some(PathBuf::from(value));
            }
            "--policy-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_check_usage()));
                };
                policy_url = Some(value.to_string());
            }
            "--sha256-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_check_usage()));
                };
                sha256_file = Some(PathBuf::from(value));
            }
            "--sha256-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_check_usage()));
                };
                sha256_url = Some(value.to_string());
            }
            "--signature-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_check_usage()));
                };
                signature_file = Some(PathBuf::from(value));
            }
            "--signature-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_check_usage()));
                };
                signature_url = Some(value.to_string());
            }
            "--gpg-verify" => gpg_verify = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(CliOutput::success(render_update_check_usage())),
            _ => return Err(CliOutput::failure(2, render_update_check_usage())),
        }
        index += 1;
    }

    if policy_file.is_some() == policy_url.is_some() {
        return Err(CliOutput::failure(2, render_update_check_usage()));
    }
    if policy_url.is_some() && (sha256_file.is_some() || signature_file.is_some()) {
        return Err(CliOutput::failure(2, render_update_check_usage()));
    }
    if policy_file.is_some() && (sha256_url.is_some() || signature_url.is_some()) {
        return Err(CliOutput::failure(2, render_update_check_usage()));
    }

    Ok(UpdateCheckArgs {
        policy_file,
        policy_url,
        sha256_file,
        sha256_url,
        signature_file,
        signature_url,
        gpg_verify,
        json,
    })
}

fn parse_update_download_args(args: &[String]) -> Result<UpdateDownloadArgs, CliOutput> {
    let mut policy_file = None;
    let mut policy_url = None;
    let mut sha256_file = None;
    let mut sha256_url = None;
    let mut signature_file = None;
    let mut signature_url = None;
    let mut target = None;
    let mut output_dir = None;
    let mut gpg_verify = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                policy_file = Some(PathBuf::from(value));
            }
            "--policy-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                policy_url = Some(value.to_string());
            }
            "--sha256-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                sha256_file = Some(PathBuf::from(value));
            }
            "--sha256-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                sha256_url = Some(value.to_string());
            }
            "--signature-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                signature_file = Some(PathBuf::from(value));
            }
            "--signature-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                signature_url = Some(value.to_string());
            }
            "--target" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                target = Some(value.to_string());
            }
            "--output-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_download_usage()));
                };
                output_dir = Some(PathBuf::from(value));
            }
            "--gpg-verify" => gpg_verify = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(CliOutput::success(render_update_download_usage())),
            _ => return Err(CliOutput::failure(2, render_update_download_usage())),
        }
        index += 1;
    }

    if policy_file.is_some() == policy_url.is_some() {
        return Err(CliOutput::failure(2, render_update_download_usage()));
    }
    if policy_url.is_some() && (sha256_file.is_some() || signature_file.is_some()) {
        return Err(CliOutput::failure(2, render_update_download_usage()));
    }
    if policy_file.is_some() && (sha256_url.is_some() || signature_url.is_some()) {
        return Err(CliOutput::failure(2, render_update_download_usage()));
    }
    let Some(output_dir) = output_dir else {
        return Err(CliOutput::failure(2, render_update_download_usage()));
    };
    if let Some(target) = target.as_deref() {
        validate_public_asset_name(target, "download target")
            .map_err(|_| CliOutput::failure(2, render_update_download_usage()))?;
    }

    Ok(UpdateDownloadArgs {
        check: UpdateCheckArgs {
            policy_file,
            policy_url,
            sha256_file,
            sha256_url,
            signature_file,
            signature_url,
            gpg_verify,
            json,
        },
        target,
        output_dir,
    })
}

fn parse_update_apply_args(args: &[String]) -> Result<UpdateApplyArgs, CliOutput> {
    let mut policy_file = None;
    let mut policy_url = None;
    let mut sha256_file = None;
    let mut sha256_url = None;
    let mut signature_file = None;
    let mut signature_url = None;
    let mut target = None;
    let mut artifact_file = None;
    let mut install_dir = None;
    let mut dry_run = false;
    let mut confirm = false;
    let mut gpg_verify = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                policy_file = Some(PathBuf::from(value));
            }
            "--policy-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                policy_url = Some(value.to_string());
            }
            "--sha256-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                sha256_file = Some(PathBuf::from(value));
            }
            "--sha256-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                sha256_url = Some(value.to_string());
            }
            "--signature-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                signature_file = Some(PathBuf::from(value));
            }
            "--signature-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                signature_url = Some(value.to_string());
            }
            "--target" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                target = Some(value.to_string());
            }
            "--artifact-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                artifact_file = Some(PathBuf::from(value));
            }
            "--install-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(CliOutput::failure(2, render_update_apply_usage()));
                };
                install_dir = Some(PathBuf::from(value));
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--gpg-verify" => gpg_verify = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(CliOutput::success(render_update_apply_usage())),
            _ => return Err(CliOutput::failure(2, render_update_apply_usage())),
        }
        index += 1;
    }

    if policy_file.is_some() == policy_url.is_some() {
        return Err(CliOutput::failure(2, render_update_apply_usage()));
    }
    if policy_url.is_some() && (sha256_file.is_some() || signature_file.is_some()) {
        return Err(CliOutput::failure(2, render_update_apply_usage()));
    }
    if policy_file.is_some() && (sha256_url.is_some() || signature_url.is_some()) {
        return Err(CliOutput::failure(2, render_update_apply_usage()));
    }
    let Some(artifact_file) = artifact_file else {
        return Err(CliOutput::failure(2, render_update_apply_usage()));
    };
    let Some(install_dir) = install_dir else {
        return Err(CliOutput::failure(2, render_update_apply_usage()));
    };
    if dry_run == confirm {
        return Err(CliOutput::failure(2, render_update_apply_usage()));
    }
    if let Some(target) = target.as_deref() {
        validate_public_asset_name(target, "update apply target")
            .map_err(|_| CliOutput::failure(2, render_update_apply_usage()))?;
    }

    Ok(UpdateApplyArgs {
        check: UpdateCheckArgs {
            policy_file,
            policy_url,
            sha256_file,
            sha256_url,
            signature_file,
            signature_url,
            gpg_verify,
            json,
        },
        target,
        artifact_file,
        install_dir,
        dry_run,
        confirm,
    })
}

fn check_release_update_policy(args: &UpdateCheckArgs) -> Result<UpdateCheckReport, String> {
    validate_release_update_policy(args).map(|validated| validated.report)
}

fn validate_release_update_policy(args: &UpdateCheckArgs) -> Result<ValidatedUpdatePolicy, String> {
    if let Some(policy_file) = args.policy_file.clone() {
        let policy_location = policy_file.display().to_string();
        let sha256_file = args
            .sha256_file
            .clone()
            .unwrap_or_else(|| sidecar_path(&policy_file, ".sha256"));
        let signature_file = args
            .signature_file
            .clone()
            .unwrap_or_else(|| sidecar_path(&policy_file, ".asc"));
        let sha256_location = sha256_file.display().to_string();
        let signature_location = signature_file.display().to_string();
        return validate_release_update_policy_files(
            UpdateCheckFiles {
                policy_file,
                sha256_file,
                signature_file,
                source: UpdateCheckSource::Local,
                policy_location,
                sha256_location,
                signature_location,
            },
            args.gpg_verify,
        );
    }

    check_release_update_policy_remote(args)
}

fn check_release_update_policy_remote(
    args: &UpdateCheckArgs,
) -> Result<ValidatedUpdatePolicy, String> {
    let policy_url = args
        .policy_url
        .as_ref()
        .ok_or_else(|| "release update policy source was not provided".to_string())?;
    let policy_name = asset_name_from_update_url(policy_url, "policy-url")?;
    let sha256_url = args
        .sha256_url
        .clone()
        .unwrap_or_else(|| format!("{policy_url}.sha256"));
    let signature_url = args
        .signature_url
        .clone()
        .unwrap_or_else(|| format!("{policy_url}.asc"));
    validate_update_sidecar_url(&sha256_url, &format!("{policy_name}.sha256"), "sha256-url")?;
    validate_update_sidecar_url(
        &signature_url,
        &format!("{policy_name}.asc"),
        "signature-url",
    )?;

    let policy_bytes =
        fetch_update_url_bounded(policy_url, MAX_UPDATE_POLICY_BYTES, "release update policy")?;
    let sha256_bytes = fetch_update_url_bounded(
        &sha256_url,
        MAX_UPDATE_CHECKSUM_BYTES,
        "release update policy checksum",
    )?;
    let signature_bytes = fetch_update_url_bounded(
        &signature_url,
        MAX_UPDATE_SIGNATURE_BYTES,
        "release update policy signature",
    )?;

    let download_dir = UpdateDownloadDir::create()?;
    let policy_file =
        write_downloaded_update_file(download_dir.path(), &policy_name, &policy_bytes)?;
    let sha256_file = write_downloaded_update_file(
        download_dir.path(),
        &format!("{policy_name}.sha256"),
        &sha256_bytes,
    )?;
    let signature_file = write_downloaded_update_file(
        download_dir.path(),
        &format!("{policy_name}.asc"),
        &signature_bytes,
    )?;

    validate_release_update_policy_files(
        UpdateCheckFiles {
            policy_file,
            sha256_file,
            signature_file,
            source: UpdateCheckSource::Remote,
            policy_location: policy_url.to_string(),
            sha256_location: sha256_url,
            signature_location: signature_url,
        },
        args.gpg_verify,
    )
}

#[cfg(test)]
fn check_release_update_policy_files(
    files: UpdateCheckFiles,
    gpg_verify: bool,
) -> Result<UpdateCheckReport, String> {
    validate_release_update_policy_files(files, gpg_verify).map(|validated| validated.report)
}

fn validate_release_update_policy_files(
    files: UpdateCheckFiles,
    gpg_verify: bool,
) -> Result<ValidatedUpdatePolicy, String> {
    let UpdateCheckFiles {
        policy_file,
        sha256_file,
        signature_file,
        source,
        policy_location,
        sha256_location,
        signature_location,
    } = files;
    let policy_name = file_name_string(&policy_file, "release update policy")?;
    validate_public_asset_name(&policy_name, "policyAsset")?;
    let policy_bytes = read_limited_file(
        &policy_file,
        MAX_UPDATE_POLICY_BYTES,
        "release update policy",
    )?;
    if !policy_bytes.is_ascii() {
        return Err("release update policy must be ASCII JSON".to_string());
    }
    let sha256 = sha256_hex(&policy_bytes);
    verify_update_sha256_sidecar(&sha256_file, &policy_name, &sha256)?;
    verify_update_signature_sidecar(&signature_file)?;

    let policy = parse_release_update_policy_json(&policy_bytes)?;
    let policy_object = policy
        .as_object()
        .ok_or_else(|| "release update policy must be a JSON object".to_string())?;
    let schema = json_string_field(&policy, "schema")?;
    if schema != UPDATE_POLICY_SCHEMA {
        return Err(format!(
            "release update policy schema was {schema}, expected {UPDATE_POLICY_SCHEMA}"
        ));
    }
    let version = json_string_field(&policy, "version")?;
    if !semver_like(&version) {
        return Err(format!(
            "release update policy version is not semver-like: {version}"
        ));
    }
    let release_tag = json_string_field(&policy, "releaseTag")?;
    if release_tag != format!("v{version}") {
        return Err(format!(
            "release update policy tag {release_tag} does not match version {version}"
        ));
    }
    let channel = json_string_field(&policy, "channel")?;
    if channel != "stable" && channel != "prerelease" {
        return Err(format!(
            "release update policy channel is invalid: {channel}"
        ));
    }
    let release_base_url = json_string_field(&policy, "releaseBaseUrl")?;
    validate_public_https_url(&release_base_url, "releaseBaseUrl")?;
    validate_policy_asset(&policy, &policy_name, &release_base_url)?;

    let apply = policy
        .get("apply")
        .and_then(Value::as_object)
        .ok_or_else(|| "release update policy is missing apply object".to_string())?;
    let auto_apply = bool_member(apply, "autoApply", "apply")?;
    let manual_verification_required = bool_member(apply, "manualVerificationRequired", "apply")?;
    let operator_consent_required = bool_member(apply, "operatorConsentRequired", "apply")?;
    if auto_apply {
        return Err("release update policy must not enable autoApply".to_string());
    }
    if !manual_verification_required {
        return Err("release update policy must require manual verification".to_string());
    }
    if !operator_consent_required {
        return Err("release update policy must require operator consent".to_string());
    }
    if bool_member(apply, "downgradeAllowed", "apply")? {
        return Err("release update policy must not allow downgrades".to_string());
    }

    let verification = policy
        .get("verification")
        .and_then(Value::as_object)
        .ok_or_else(|| "release update policy is missing verification object".to_string())?;
    for field in [
        "strictSha256SidecarsRequired",
        "linuxDetachedSignaturesRequired",
        "policyDetachedSignatureRequired",
        "githubArtifactAttestationsExpectedForPlatformArchives",
    ] {
        if !bool_member(verification, field, "verification")? {
            return Err(format!(
                "release update policy verification.{field} must be true"
            ));
        }
    }

    for guard in [
        "payloadDisplayed",
        "tokenDisplayed",
        "keyMaterialDisplayed",
        "ciphertextDisplayed",
        "contentsDisplayed",
    ] {
        if policy_object.get(guard).and_then(Value::as_bool) != Some(false) {
            return Err(format!("release update policy expected {guard}=false"));
        }
    }

    let platform_archives = validate_asset_array(&policy, "platformArchives", &release_base_url)?;
    let package_manager_assets =
        validate_asset_array(&policy, "packageManagerAssets", &release_base_url)?;
    let linux_package_assets =
        validate_asset_array(&policy, "linuxPackageAssets", &release_base_url)?;
    let repository_assets = validate_asset_array(&policy, "repositoryAssets", &release_base_url)?;
    validate_npm_metadata(&policy, &version)?;

    let gpg_verified = if gpg_verify {
        verify_update_signature_with_gpg(&signature_file, &policy_file)?;
        true
    } else {
        false
    };

    Ok(ValidatedUpdatePolicy {
        report: UpdateCheckReport {
            source,
            policy_location,
            sha256_location,
            signature_location,
            sha256,
            version,
            release_tag,
            channel,
            release_base_url,
            platform_archives,
            package_manager_assets,
            linux_package_assets,
            repository_assets,
            auto_apply,
            manual_verification_required,
            operator_consent_required,
            gpg_verified,
        },
        policy,
    })
}

struct DuplicateKeyCheckedJson;

impl<'de> DeserializeSeed<'de> for DuplicateKeyCheckedJson {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyCheckedVisitor)
    }
}

struct DuplicateKeyCheckedVisitor;

impl<'de> Visitor<'de> for DuplicateKeyCheckedVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateKeyCheckedJson.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(DuplicateKeyCheckedJson)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut object = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            let value = access.next_value_seed(DuplicateKeyCheckedJson)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

fn parse_release_update_policy_json(policy_bytes: &[u8]) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(policy_bytes);
    let policy = DuplicateKeyCheckedJson
        .deserialize(&mut deserializer)
        .map_err(|error| format!("release update policy JSON is invalid: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("release update policy JSON is invalid: {error}"))?;
    Ok(policy)
}

fn validate_policy_asset(
    policy: &Value,
    policy_name: &str,
    release_base_url: &str,
) -> Result<(), String> {
    let asset = policy
        .get("policyAsset")
        .and_then(Value::as_object)
        .ok_or_else(|| "release update policy is missing policyAsset object".to_string())?;
    let filename = string_member(asset, "filename", "policyAsset")?;
    if filename != policy_name {
        return Err(format!(
            "release update policy policyAsset.filename was {filename}, expected {policy_name}"
        ));
    }
    validate_asset_url(
        string_member(asset, "url", "policyAsset")?,
        release_base_url,
        policy_name,
        "policyAsset.url",
    )?;
    validate_asset_url(
        string_member(asset, "sha256Url", "policyAsset")?,
        release_base_url,
        &format!("{policy_name}.sha256"),
        "policyAsset.sha256Url",
    )?;
    validate_asset_url(
        string_member(asset, "signatureUrl", "policyAsset")?,
        release_base_url,
        &format!("{policy_name}.asc"),
        "policyAsset.signatureUrl",
    )?;
    Ok(())
}

fn validate_asset_array(
    policy: &Value,
    field: &str,
    release_base_url: &str,
) -> Result<usize, String> {
    let assets = policy
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("release update policy is missing {field} array"))?;
    if assets.is_empty() {
        return Err(format!("release update policy {field} must not be empty"));
    }
    let mut names = HashSet::new();
    for asset in assets {
        let object = asset
            .as_object()
            .ok_or_else(|| format!("release update policy {field} entries must be objects"))?;
        let filename = string_member(object, "filename", field)?;
        validate_public_asset_name(filename, field)?;
        if !names.insert(filename.to_string()) {
            return Err(format!(
                "release update policy {field} duplicated {filename}"
            ));
        }
        let sha256 = string_member(object, "sha256", field)?;
        if !is_sha256_hex(sha256) {
            return Err(format!(
                "release update policy {field}.{filename} has invalid SHA-256"
            ));
        }
        validate_asset_url(
            string_member(object, "url", field)?,
            release_base_url,
            filename,
            field,
        )?;
        if let Some(sha256_url) = object.get("sha256Url").and_then(Value::as_str) {
            validate_asset_url(
                sha256_url,
                release_base_url,
                &format!("{filename}.sha256"),
                field,
            )?;
        }
        if let Some(signature_url) = object.get("signatureUrl").and_then(Value::as_str) {
            validate_asset_url(
                signature_url,
                release_base_url,
                &format!("{filename}.asc"),
                field,
            )?;
        }
    }
    Ok(assets.len())
}

fn validate_npm_metadata(policy: &Value, version: &str) -> Result<(), String> {
    let npm = policy
        .get("npm")
        .and_then(Value::as_object)
        .ok_or_else(|| "release update policy is missing npm object".to_string())?;
    let registry = string_member(npm, "registry", "npm")?;
    validate_public_https_url(registry, "npm.registry")?;
    let packages = npm
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "release update policy is missing npm.packages array".to_string())?;
    if packages.is_empty() {
        return Err("release update policy npm.packages must not be empty".to_string());
    }
    for package in packages {
        let object = package.as_object().ok_or_else(|| {
            "release update policy npm.packages entries must be objects".to_string()
        })?;
        let name = string_member(object, "name", "npm.packages")?;
        if name != "@imthegoodboy/conu" {
            return Err(format!(
                "release update policy npm package must be @imthegoodboy/conu: {name}"
            ));
        }
        let package_version = string_member(object, "version", "npm.packages")?;
        if package_version != version {
            return Err(format!(
                "release update policy npm package {name} has version {package_version}, expected {version}"
            ));
        }
    }
    Ok(())
}

fn download_release_update_artifact(
    args: &UpdateDownloadArgs,
) -> Result<UpdateArtifactDownloadReport, String> {
    let validated = validate_release_update_policy(&args.check)?;
    let target = match args.target.clone() {
        Some(target) => target,
        None => default_update_target()
            .ok_or_else(|| {
                "release update artifact target could not be detected; pass --target".to_string()
            })?
            .to_string(),
    };
    let asset = select_update_platform_archive(&validated.policy, &target)?;
    let artifact_bytes = fetch_update_url_bounded(
        &asset.url,
        MAX_UPDATE_ARTIFACT_BYTES,
        "release update artifact",
    )?;
    let sha256_bytes = fetch_update_url_bounded(
        &asset.sha256_url,
        MAX_UPDATE_CHECKSUM_BYTES,
        "release update artifact checksum",
    )?;
    let signature_bytes = fetch_update_url_bounded(
        &asset.signature_url,
        MAX_UPDATE_SIGNATURE_BYTES,
        "release update artifact signature",
    )?;
    let files = write_verified_update_artifact_files(
        &asset,
        &artifact_bytes,
        &sha256_bytes,
        &signature_bytes,
        &args.output_dir,
        args.check.gpg_verify,
    )?;

    Ok(UpdateArtifactDownloadReport {
        policy: validated.report,
        target: asset.target,
        filename: asset.filename,
        url: asset.url,
        artifact_file: files.artifact_file,
        sha256_file: files.sha256_file,
        signature_file: files.signature_file,
        bytes: files.bytes,
        sha256: asset.sha256,
        gpg_verified: args.check.gpg_verify,
    })
}

fn select_update_platform_archive(
    policy: &Value,
    target: &str,
) -> Result<UpdateArtifactAsset, String> {
    let assets = policy
        .get("platformArchives")
        .and_then(Value::as_array)
        .ok_or_else(|| "release update policy is missing platformArchives array".to_string())?;
    let mut selected = None;

    for asset in assets {
        let object = asset.as_object().ok_or_else(|| {
            "release update policy platformArchives entries must be objects".to_string()
        })?;
        if string_member(object, "target", "platformArchives")? != target {
            continue;
        }
        if selected.is_some() {
            return Err(format!(
                "release update policy has multiple platform archives for target {target}"
            ));
        }
        let filename = string_member(object, "filename", "platformArchives")?.to_string();
        validate_public_asset_name(&filename, "platformArchives")?;
        let sha256 = string_member(object, "sha256", "platformArchives")?.to_ascii_lowercase();
        if !is_sha256_hex(&sha256) {
            return Err(format!(
                "release update policy platformArchives.{filename} has invalid SHA-256"
            ));
        }
        let url = string_member(object, "url", "platformArchives")?.to_string();
        let sha256_url = string_member(object, "sha256Url", "platformArchives")?.to_string();
        let signature_url = string_member(object, "signatureUrl", "platformArchives")?.to_string();
        validate_update_sidecar_url(
            &sha256_url,
            &format!("{filename}.sha256"),
            "artifact sha256Url",
        )?;
        validate_update_sidecar_url(
            &signature_url,
            &format!("{filename}.asc"),
            "artifact signatureUrl",
        )?;
        selected = Some(UpdateArtifactAsset {
            filename,
            target: target.to_string(),
            url,
            sha256,
            sha256_url,
            signature_url,
        });
    }

    selected
        .ok_or_else(|| format!("release update policy has no platform archive for target {target}"))
}

fn write_verified_update_artifact_files(
    asset: &UpdateArtifactAsset,
    artifact_bytes: &[u8],
    sha256_bytes: &[u8],
    signature_bytes: &[u8],
    output_dir: &Path,
    gpg_verify: bool,
) -> Result<UpdateArtifactFiles, String> {
    let actual_sha256 = sha256_hex(artifact_bytes);
    if actual_sha256 != asset.sha256 {
        return Err("release update artifact SHA-256 did not match policy".to_string());
    }
    verify_update_sha256_sidecar_bytes(
        sha256_bytes,
        &asset.filename,
        &actual_sha256,
        "release update artifact",
    )?;
    verify_update_signature_sidecar_bytes(signature_bytes, "release update artifact signature")?;

    let verify_dir = UpdateDownloadDir::create()?;
    let verify_artifact =
        write_downloaded_update_file(verify_dir.path(), &asset.filename, artifact_bytes)?;
    let verify_sha256 = write_downloaded_update_file(
        verify_dir.path(),
        &format!("{}.sha256", asset.filename),
        sha256_bytes,
    )?;
    let verify_signature = write_downloaded_update_file(
        verify_dir.path(),
        &format!("{}.asc", asset.filename),
        signature_bytes,
    )?;
    verify_update_sha256_sidecar(&verify_sha256, &asset.filename, &actual_sha256)?;
    verify_update_signature_sidecar(&verify_signature)?;
    if gpg_verify {
        verify_detached_signature_with_gpg(
            &verify_signature,
            &verify_artifact,
            "release update artifact",
        )?;
    }

    let sha256_name = format!("{}.sha256", asset.filename);
    let signature_name = format!("{}.asc", asset.filename);
    ensure_update_output_files_available(
        output_dir,
        &[
            asset.filename.as_str(),
            sha256_name.as_str(),
            signature_name.as_str(),
        ],
    )?;

    let artifact_file =
        write_update_output_file(output_dir, &asset.filename, artifact_bytes, "artifact")?;
    let sha256_file = write_update_output_file(output_dir, &sha256_name, sha256_bytes, "checksum")?;
    let signature_file =
        write_update_output_file(output_dir, &signature_name, signature_bytes, "signature")?;

    Ok(UpdateArtifactFiles {
        artifact_file,
        sha256_file,
        signature_file,
        bytes: artifact_bytes.len(),
    })
}

fn apply_release_update_artifact(args: &UpdateApplyArgs) -> Result<UpdateApplyReport, String> {
    let validated = validate_release_update_policy(&args.check)?;
    let target = match args.target.clone() {
        Some(target) => target,
        None => default_update_target()
            .ok_or_else(|| {
                "release update apply target could not be detected; pass --target".to_string()
            })?
            .to_string(),
    };
    ensure_update_apply_target_matches_current_platform(&target)?;
    let asset = select_update_platform_archive(&validated.policy, &target)?;
    let artifact_name = file_name_string(&args.artifact_file, "release update artifact")?;
    validate_public_asset_name(&artifact_name, "release update artifact")?;
    if artifact_name != asset.filename {
        return Err(format!(
            "release update artifact file was {artifact_name}, expected {} for target {target}",
            asset.filename
        ));
    }

    let artifact_bytes = read_limited_file(
        &args.artifact_file,
        MAX_UPDATE_ARTIFACT_BYTES,
        "release update artifact",
    )?;
    let actual_sha256 = sha256_hex(&artifact_bytes);
    if actual_sha256 != asset.sha256 {
        return Err("release update artifact SHA-256 did not match policy".to_string());
    }
    verify_update_artifact_sidecars(
        &args.artifact_file,
        &asset.filename,
        &actual_sha256,
        args.check.gpg_verify,
    )?;

    let staged = stage_update_archive_binaries(&asset.filename, &artifact_bytes, &target)?;
    if staged.manifest_target != target {
        return Err(format!(
            "release update archive manifest target was {}, expected {target}",
            staged.manifest_target
        ));
    }

    let (binaries, backup_dir, update_applied) = if args.confirm {
        plan_staged_update_binaries(&staged.binaries, &args.install_dir, None, true)?;
        let backup_dir =
            create_update_apply_backup_dir(&args.install_dir, &validated.report.version)?;
        let reports =
            install_staged_update_binaries(&staged.binaries, &args.install_dir, Some(&backup_dir))?;
        (reports, Some(backup_dir), true)
    } else {
        let reports =
            plan_staged_update_binaries(&staged.binaries, &args.install_dir, None, false)?;
        (reports, None, false)
    };

    Ok(UpdateApplyReport {
        policy: validated.report,
        target,
        filename: asset.filename,
        archive_file: args.artifact_file.clone(),
        install_dir: args.install_dir.clone(),
        backup_dir,
        entries_scanned: staged.entries_scanned,
        unpacked_bytes: staged.unpacked_bytes,
        binaries,
        sha256: actual_sha256,
        gpg_verified: args.check.gpg_verify,
        dry_run: args.dry_run,
        update_applied,
    })
}

fn ensure_update_apply_target_matches_current_platform(target: &str) -> Result<(), String> {
    let current = default_update_target().ok_or_else(|| {
        "release update apply cannot detect the current platform target".to_string()
    })?;
    if target != current {
        return Err(format!(
            "release update apply target {target} does not match current platform {current}"
        ));
    }
    Ok(())
}

fn verify_update_artifact_sidecars(
    artifact_file: &Path,
    artifact_name: &str,
    actual_sha256: &str,
    gpg_verify: bool,
) -> Result<(), String> {
    let sha256_file = sidecar_path(artifact_file, ".sha256");
    let signature_file = sidecar_path(artifact_file, ".asc");
    let sha256_bytes = read_limited_file(
        &sha256_file,
        MAX_UPDATE_CHECKSUM_BYTES,
        "release update artifact checksum",
    )?;
    verify_update_sha256_sidecar_bytes(
        &sha256_bytes,
        artifact_name,
        actual_sha256,
        "release update artifact",
    )?;
    let signature_bytes = read_limited_file(
        &signature_file,
        MAX_UPDATE_SIGNATURE_BYTES,
        "release update artifact signature",
    )?;
    verify_update_signature_sidecar_bytes(&signature_bytes, "release update artifact signature")?;
    if gpg_verify {
        verify_detached_signature_with_gpg(
            &signature_file,
            artifact_file,
            "release update artifact",
        )?;
    }
    Ok(())
}

fn stage_update_archive_binaries(
    archive_name: &str,
    archive_bytes: &[u8],
    target: &str,
) -> Result<StagedUpdateArchive, String> {
    if archive_name.ends_with(".tar.gz") {
        return stage_update_tar_gz_archive(archive_name, archive_bytes, target);
    }
    if archive_name.ends_with(".zip") {
        return stage_update_zip_archive(archive_name, archive_bytes, target);
    }
    Err(format!(
        "release update artifact {archive_name} must be a .tar.gz or .zip archive"
    ))
}

fn stage_update_zip_archive(
    archive_name: &str,
    archive_bytes: &[u8],
    target: &str,
) -> Result<StagedUpdateArchive, String> {
    let reader = std::io::Cursor::new(archive_bytes);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|error| format!("release update ZIP archive is invalid: {error}"))?;
    let staging_dir = UpdateDownloadDir::create()?;
    let mut scan = UpdateArchiveScan::new(target, archive_name)?;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("release update ZIP member {index} is invalid: {error}"))?;
        let raw_name = file.name().to_string();
        let mode = file.unix_mode();
        if mode.is_some_and(|value| (value & 0o170000) == 0o120000) {
            return Err(release_update_archive_member_failure(
                "contains unsupported link member",
            ));
        }
        let is_dir = file.is_dir();
        let size = file.size();
        let normalized = scan.record_member(archive_name, &raw_name, size, is_dir)?;
        if normalized.is_empty() || is_dir {
            continue;
        }
        if normalized == "manifest.toml" {
            let manifest = read_update_archive_member_limited(
                &mut file,
                MAX_UPDATE_ARCHIVE_MANIFEST_BYTES,
                "release update archive manifest.toml",
            )?;
            scan.record_manifest(&manifest)?;
            continue;
        }
        if let Some(binary_name) = scan.expected_binary_name(&normalized) {
            let path = staging_dir
                .path()
                .join(update_binary_filename(&binary_name));
            let sha256 =
                write_update_staged_binary(&path, &mut file, size, archive_name, &binary_name)?;
            scan.record_binary(&binary_name, path, size, sha256)?;
        }
    }

    scan.finish(staging_dir)
}

fn stage_update_tar_gz_archive(
    archive_name: &str,
    archive_bytes: &[u8],
    target: &str,
) -> Result<StagedUpdateArchive, String> {
    let reader = std::io::Cursor::new(archive_bytes);
    let decoder = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let staging_dir = UpdateDownloadDir::create()?;
    let mut scan = UpdateArchiveScan::new(target, archive_name)?;
    let entries = archive
        .entries()
        .map_err(|error| format!("release update tar archive is invalid: {error}"))?;

    for entry in entries {
        let mut entry =
            entry.map_err(|error| format!("release update tar member is invalid: {error}"))?;
        let raw_name = entry
            .path()
            .map_err(|_| release_update_archive_member_failure("member path is invalid"))?
            .to_str()
            .ok_or_else(|| release_update_archive_member_failure("member path is invalid"))?
            .to_string();
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(release_update_archive_member_failure(
                "contains unsupported link member",
            ));
        }
        let is_dir = entry_type.is_dir();
        if !is_dir && !entry_type.is_file() {
            return Err(release_update_archive_member_failure(
                "contains unsupported non-file member",
            ));
        }
        let size = entry
            .header()
            .size()
            .map_err(|error| format!("release update tar member size is invalid: {error}"))?;
        let normalized = scan.record_member(archive_name, &raw_name, size, is_dir)?;
        if normalized.is_empty() || is_dir {
            continue;
        }
        if normalized == "manifest.toml" {
            let manifest = read_update_archive_member_limited(
                &mut entry,
                MAX_UPDATE_ARCHIVE_MANIFEST_BYTES,
                "release update archive manifest.toml",
            )?;
            scan.record_manifest(&manifest)?;
            continue;
        }
        if let Some(binary_name) = scan.expected_binary_name(&normalized) {
            let path = staging_dir
                .path()
                .join(update_binary_filename(&binary_name));
            let sha256 =
                write_update_staged_binary(&path, &mut entry, size, archive_name, &binary_name)?;
            scan.record_binary(&binary_name, path, size, sha256)?;
        }
    }

    scan.finish(staging_dir)
}

struct UpdateArchiveScan {
    target: String,
    expected_root: String,
    root_style: Option<UpdateArchiveRootStyle>,
    expected_binaries: Vec<(String, String)>,
    paths: HashSet<String>,
    binaries: Vec<StagedUpdateBinary>,
    manifest_target: Option<String>,
    manifest_payload_safe: bool,
    entries_scanned: usize,
    unpacked_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateArchiveRootStyle {
    Rooted,
    Rootless,
}

impl UpdateArchiveScan {
    fn new(target: &str, archive_name: &str) -> Result<Self, String> {
        let suffix = update_binary_suffix_for_target(target)?;
        let expected_root = expected_update_archive_root(archive_name)?;
        let expected_binaries = UPDATE_BINARY_NAMES
            .iter()
            .map(|name| ((*name).to_string(), format!("bin/{}{}", name, suffix)))
            .collect();
        Ok(Self {
            target: target.to_string(),
            expected_root,
            root_style: None,
            expected_binaries,
            paths: HashSet::new(),
            binaries: Vec::new(),
            manifest_target: None,
            manifest_payload_safe: false,
            entries_scanned: 0,
            unpacked_bytes: 0,
        })
    }

    fn record_member(
        &mut self,
        archive_name: &str,
        raw_name: &str,
        size: u64,
        is_dir: bool,
    ) -> Result<String, String> {
        self.entries_scanned += 1;
        if self.entries_scanned > MAX_UPDATE_ARCHIVE_ENTRIES {
            return Err(release_update_archive_named_member_failure(
                archive_name,
                &format!("contains more than {MAX_UPDATE_ARCHIVE_ENTRIES} entries"),
            ));
        }
        if size > MAX_UPDATE_ARCHIVE_MEMBER_BYTES {
            return Err(release_update_archive_member_failure("member is too large"));
        }
        let (normalized, root_style) =
            normalize_update_archive_member(raw_name, &self.expected_root)?;
        if let Some(root_style) = root_style {
            self.record_root_style(archive_name, root_style)?;
        }
        if normalized.is_empty() {
            return Ok(normalized);
        }
        if !is_dir && !self.paths.insert(normalized.clone()) {
            return Err(release_update_archive_member_failure("duplicated path"));
        }
        if !is_dir {
            self.unpacked_bytes = self
                .unpacked_bytes
                .checked_add(size)
                .ok_or_else(|| "release update archive unpacked size overflowed".to_string())?;
            if self.unpacked_bytes > MAX_UPDATE_ARCHIVE_UNPACKED_BYTES {
                return Err(release_update_archive_member_failure(&format!(
                    "uncompressed contents exceed {MAX_UPDATE_ARCHIVE_UNPACKED_BYTES} bytes"
                )));
            }
            self.reject_unexpected_binary_path(&normalized)?;
        }
        Ok(normalized)
    }

    fn record_root_style(
        &mut self,
        archive_name: &str,
        root_style: UpdateArchiveRootStyle,
    ) -> Result<(), String> {
        if let Some(existing) = self.root_style {
            if existing != root_style {
                return Err(release_update_archive_named_member_failure(
                    archive_name,
                    "mixes rooted and rootless members",
                ));
            }
        } else {
            self.root_style = Some(root_style);
        }
        Ok(())
    }

    fn reject_unexpected_binary_path(&self, normalized: &str) -> Result<(), String> {
        let filename = normalized.rsplit('/').next().unwrap_or(normalized);
        let expected_filenames = self
            .expected_binaries
            .iter()
            .map(|(_, path)| path.rsplit('/').next().unwrap_or(path.as_str()))
            .collect::<HashSet<_>>();
        let is_expected_binary_name = expected_filenames.contains(filename);
        let is_expected_path = self
            .expected_binaries
            .iter()
            .any(|(_, path)| path == normalized);
        if is_expected_binary_name && !is_expected_path {
            return Err(release_update_archive_member_failure(
                "contains unexpected binary path",
            ));
        }
        Ok(())
    }

    fn expected_binary_name(&self, normalized: &str) -> Option<String> {
        self.expected_binaries
            .iter()
            .find_map(|(name, path)| (path == normalized).then_some(name.clone()))
    }

    fn record_manifest(&mut self, bytes: &[u8]) -> Result<(), String> {
        if !bytes.is_ascii() {
            return Err("release update archive manifest.toml must be ASCII".to_string());
        }
        let text = String::from_utf8(bytes.to_vec()).map_err(|error| {
            format!("release update archive manifest.toml is invalid UTF-8: {error}")
        })?;
        let manifest = parse_update_archive_manifest(&text)?;
        self.manifest_target = manifest.target;
        self.manifest_payload_safe = manifest.payload_contents_included == Some(false);
        Ok(())
    }

    fn record_binary(
        &mut self,
        name: &str,
        source_file: PathBuf,
        bytes: u64,
        sha256: String,
    ) -> Result<(), String> {
        if self.binaries.iter().any(|binary| binary.name == name) {
            return Err(format!("release update archive duplicated binary: {name}"));
        }
        self.binaries.push(StagedUpdateBinary {
            name: name.to_string(),
            source_file,
            bytes,
            sha256,
        });
        Ok(())
    }

    fn finish(self, staging_dir: UpdateDownloadDir) -> Result<StagedUpdateArchive, String> {
        let manifest_target = self
            .manifest_target
            .ok_or_else(|| "release update archive manifest.toml is missing target".to_string())?;
        if !self.manifest_payload_safe {
            return Err(
                "release update archive manifest.toml does not declare payload_contents_included = false"
                    .to_string(),
            );
        }
        if manifest_target != self.target {
            return Err(format!(
                "release update archive manifest target was {manifest_target}, expected {}",
                self.target
            ));
        }
        let present = self
            .binaries
            .iter()
            .map(|binary| binary.name.as_str())
            .collect::<HashSet<_>>();
        let missing = UPDATE_BINARY_NAMES
            .iter()
            .filter(|name| !present.contains(**name))
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "release update archive missing binaries: {}",
                missing.join(", ")
            ));
        }
        Ok(StagedUpdateArchive {
            _staging_dir: staging_dir,
            manifest_target,
            entries_scanned: self.entries_scanned,
            unpacked_bytes: self.unpacked_bytes,
            binaries: self.binaries,
        })
    }
}

fn expected_update_archive_root(archive_name: &str) -> Result<String, String> {
    let root = archive_name
        .strip_suffix(".tar.gz")
        .or_else(|| archive_name.strip_suffix(".zip"))
        .ok_or_else(|| {
            format!("release update artifact {archive_name} must be a .tar.gz or .zip archive")
        })?;
    validate_public_asset_name(root, "release update archive root")?;
    Ok(root.to_string())
}

fn release_update_archive_member_failure(reason: &str) -> String {
    format!("release update archive {reason}; pathDisplayed=false contentsDisplayed=false")
}

fn release_update_archive_named_member_failure(archive_name: &str, reason: &str) -> String {
    format!(
        "release update archive {archive_name} {reason}; pathDisplayed=false contentsDisplayed=false"
    )
}

fn normalize_update_archive_member(
    name: &str,
    expected_root: &str,
) -> Result<(String, Option<UpdateArchiveRootStyle>), String> {
    let normalized = name.replace('\\', "/");
    if normalized.contains(':') || normalized.contains('\0') {
        return Err(release_update_archive_member_failure(
            "contains unsafe path",
        ));
    }
    let path = std::path::Path::new(&normalized);
    if path.is_absolute() {
        return Err(release_update_archive_member_failure(
            "contains unsafe path",
        ));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(value) => {
                let part = value
                    .to_str()
                    .ok_or_else(|| release_update_archive_member_failure("path is not UTF-8"))?;
                if part.is_empty() {
                    continue;
                }
                parts.push(part.to_string());
            }
            std::path::Component::CurDir => {}
            _ => {
                return Err(release_update_archive_member_failure(
                    "contains unsafe path",
                ));
            }
        }
    }
    let root_style = if let Some(first) = parts.first() {
        if first == expected_root {
            Some(UpdateArchiveRootStyle::Rooted)
        } else if first.starts_with("conu-") {
            return Err(release_update_archive_member_failure(&format!(
                "contains unexpected root; expected {expected_root}"
            )));
        } else {
            Some(UpdateArchiveRootStyle::Rootless)
        }
    } else {
        None
    };
    if root_style == Some(UpdateArchiveRootStyle::Rooted) {
        parts.remove(0);
    }
    Ok((parts.join("/"), root_style))
}

fn read_update_archive_member_limited<R: Read>(
    reader: &mut R,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut limited = reader.take(limit + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{label} could not be read: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{label} is too large"));
    }
    Ok(bytes)
}

fn write_update_staged_binary<R: Read>(
    path: &Path,
    reader: &mut R,
    expected_bytes: u64,
    archive_name: &str,
    binary_name: &str,
) -> Result<String, String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "could not stage {binary_name} from release update archive {archive_name}: {error}"
            )
        })?;
    let (copied, sha256) = match copy_update_binary_with_sha256(reader, &mut file) {
        Ok(result) => result,
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(format!(
                "could not read {binary_name} from release update archive {archive_name}: {error}"
            ));
        }
    };
    drop(file);
    if copied != expected_bytes {
        let _ = fs::remove_file(path);
        return Err(format!(
            "release update archive {binary_name} size changed while staging"
        ));
    }
    Ok(sha256)
}

fn copy_update_binary_with_sha256<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; 8192];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        writer.write_all(&buffer[..read])?;
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("release update binary size overflowed"))?;
    }

    let digest = hasher.finalize();
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((copied, sha256))
}

#[derive(Default)]
struct UpdateArchiveManifest {
    target: Option<String>,
    payload_contents_included: Option<bool>,
}

fn parse_update_archive_manifest(text: &str) -> Result<UpdateArchiveManifest, String> {
    let mut seen = HashSet::new();
    let mut manifest = UpdateArchiveManifest::default();

    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(format!(
                "release update archive manifest.toml line {line_number} must include a key"
            ));
        }
        if !seen.insert(key.to_string()) {
            return Err(format!(
                "release update archive manifest.toml line {line_number} contains duplicate key {key}"
            ));
        }
        let value = value.trim();
        match key {
            "target" => {
                manifest.target = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .filter(|value| !value.trim().is_empty())
                    .map(ToString::to_string);
            }
            "payload_contents_included" => {
                manifest.payload_contents_included = match value {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                };
            }
            _ => {}
        }
    }

    Ok(manifest)
}

fn update_binary_suffix_for_target(target: &str) -> Result<&'static str, String> {
    if target.starts_with("windows-") {
        return Ok(".exe");
    }
    if target.starts_with("linux-") || target.starts_with("macos-") {
        return Ok("");
    }
    Err(format!(
        "release update apply target is unsupported: {target}"
    ))
}

fn update_binary_filename(name: &str) -> String {
    format!("{}{}", name, env::consts::EXE_SUFFIX)
}

fn create_update_apply_backup_dir(install_dir: &Path, version: &str) -> Result<PathBuf, String> {
    validate_public_asset_name(version, "release update version")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    create_update_apply_backup_dir_with_nonce(install_dir, version, nonce)
}

fn create_update_apply_backup_dir_with_nonce(
    install_dir: &Path,
    version: &str,
    nonce: u128,
) -> Result<PathBuf, String> {
    validate_public_asset_name(version, "release update version")?;
    ensure_update_install_directory(install_dir)?;
    let backup_root = install_dir.join(".conu-update-backups");
    ensure_update_backup_root_directory(&backup_root)?;

    for attempt in 0..1024 {
        let backup_dir = backup_root.join(format!("{version}-{nonce}-{attempt}"));
        match fs::create_dir(&backup_dir) {
            Ok(()) => return Ok(backup_dir),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "could not create release update backup directory {}: {error}",
                    backup_dir.display()
                ));
            }
        }
    }

    Err("could not create unique release update backup directory".to_string())
}

fn ensure_update_install_directory(install_dir: &Path) -> Result<(), String> {
    if update_install_directory_exists(install_dir)? {
        return Ok(());
    }
    fs::create_dir_all(install_dir).map_err(|error| {
        format!(
            "could not create release update install directory {}: {error}",
            install_dir.display()
        )
    })?;
    if update_install_directory_exists(install_dir)? {
        return Ok(());
    }
    Err(format!(
        "could not create release update install directory {}: directory was not created",
        install_dir.display()
    ))
}

fn update_install_directory_exists(install_dir: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(install_dir) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "release update install-dir is not a directory: {}",
                    install_dir.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "could not inspect release update install directory {}: {error}",
            install_dir.display()
        )),
    }
}

fn ensure_update_install_file_parent(target_file: &Path) -> Result<(), String> {
    let install_dir = target_file.parent().ok_or_else(|| {
        format!(
            "release update install target has no parent directory: {}",
            target_file.display()
        )
    })?;
    if update_install_directory_exists(install_dir)? {
        return Ok(());
    }
    Err(format!(
        "release update install target parent does not exist: {}",
        install_dir.display()
    ))
}

fn ensure_update_install_file_parent_if_present(target_file: &Path) -> Result<(), String> {
    let Some(install_dir) = target_file.parent() else {
        return Ok(());
    };
    match fs::symlink_metadata(install_dir) {
        Ok(_) => ensure_update_install_file_parent(target_file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect release update install directory {}: {error}",
            install_dir.display()
        )),
    }
}

fn ensure_update_backup_root_directory(backup_root: &Path) -> Result<(), String> {
    if update_backup_root_directory_exists(backup_root)? {
        return Ok(());
    }
    fs::create_dir_all(backup_root).map_err(|error| {
        format!(
            "could not create release update backup root {}: {error}",
            backup_root.display()
        )
    })?;
    if update_backup_root_directory_exists(backup_root)? {
        return Ok(());
    }
    Err(format!(
        "could not create release update backup root {}: directory was not created",
        backup_root.display()
    ))
}

fn update_backup_root_directory_exists(backup_root: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(backup_root) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "release update backup root is not a directory: {}",
                    backup_root.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "could not inspect release update backup root {}: {error}",
            backup_root.display()
        )),
    }
}

fn ensure_prepared_update_backup_directory(
    install_dir: &Path,
    backup_dir: &Path,
) -> Result<(), String> {
    let backup_root = install_dir.join(".conu-update-backups");
    match backup_dir.parent() {
        Some(parent) if parent == backup_root.as_path() => {}
        _ => {
            return Err(format!(
                "release update backup directory is outside backup root: {}",
                backup_dir.display()
            ));
        }
    }
    ensure_existing_update_backup_directory(&backup_root, backup_dir)
}

fn ensure_existing_update_backup_directory(
    backup_root: &Path,
    backup_dir: &Path,
) -> Result<(), String> {
    if !update_backup_root_directory_exists(backup_root)? {
        return Err(format!(
            "release update backup root does not exist: {}",
            backup_root.display()
        ));
    }
    match fs::symlink_metadata(backup_dir) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "release update backup directory is not a directory: {}",
                    backup_dir.display()
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(format!(
            "release update backup directory does not exist: {}",
            backup_dir.display()
        )),
        Err(error) => Err(format!(
            "could not inspect release update backup directory {}: {error}",
            backup_dir.display()
        )),
    }
}

fn ensure_update_backup_file_parent(backup_file: &Path) -> Result<(), String> {
    let backup_dir = backup_file.parent().ok_or_else(|| {
        format!(
            "release update backup file has no parent directory: {}",
            backup_file.display()
        )
    })?;
    let backup_root = backup_dir.parent().ok_or_else(|| {
        format!(
            "release update backup file has no backup root: {}",
            backup_file.display()
        )
    })?;
    ensure_existing_update_backup_directory(backup_root, backup_dir)
}

fn ensure_update_backup_file_parent_if_present(backup_file: &Path) -> Result<(), String> {
    let Some(backup_dir) = backup_file.parent() else {
        return Ok(());
    };
    match fs::symlink_metadata(backup_dir) {
        Ok(_) => ensure_update_backup_file_parent(backup_file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect release update backup directory {}: {error}",
            backup_dir.display()
        )),
    }
}

fn plan_staged_update_binaries(
    binaries: &[StagedUpdateBinary],
    install_dir: &Path,
    backup_dir: Option<&Path>,
    _confirmed: bool,
) -> Result<Vec<UpdateApplyBinaryReport>, String> {
    update_install_directory_exists(install_dir)?;

    let mut reports = Vec::new();
    let mut targets = HashSet::new();
    for binary in binaries {
        validate_public_asset_name(&binary.name, "release update binary")?;
        let filename = update_binary_filename(&binary.name);
        let target_file = install_dir.join(&filename);
        if !targets.insert(target_file.clone()) {
            return Err(format!(
                "release update install target overlaps: {}",
                target_file.display()
            ));
        }
        let target_exists = inspect_update_install_target(&target_file)?;
        let backup_file = backup_dir.and_then(|dir| {
            if target_exists {
                Some(dir.join(&filename))
            } else {
                None
            }
        });
        reports.push(UpdateApplyBinaryReport {
            name: binary.name.clone(),
            source_file: binary.source_file.clone(),
            target_file,
            backup_file,
            bytes: binary.bytes,
            sha256: binary.sha256.clone(),
        });
    }
    Ok(reports)
}

fn install_staged_update_binaries(
    binaries: &[StagedUpdateBinary],
    install_dir: &Path,
    backup_dir: Option<&Path>,
) -> Result<Vec<UpdateApplyBinaryReport>, String> {
    let reports = plan_staged_update_binaries(binaries, install_dir, backup_dir, true)?;
    ensure_update_install_directory(install_dir)?;
    if let Some(backup_dir) = backup_dir {
        ensure_prepared_update_backup_directory(install_dir, backup_dir)?;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut temp_targets = Vec::new();
    for report in &reports {
        let filename = report
            .target_file
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "release update install target has invalid filename".to_string())?;
        let temp_target =
            match create_update_temp_install_target(report, install_dir, filename, nonce) {
                Ok(temp_target) => temp_target,
                Err(error) => {
                    cleanup_update_temp_targets(&temp_targets);
                    return Err(error);
                }
            };
        temp_targets.push((report.target_file.clone(), temp_target));
    }

    if let Err(error) = back_up_existing_update_binaries(&reports) {
        cleanup_update_temp_targets(&temp_targets);
        return Err(error);
    }

    let mut installed = Vec::new();
    for (target_file, temp_target) in &temp_targets {
        let Some(report) = reports
            .iter()
            .find(|report| report.target_file == *target_file)
        else {
            let recovery_errors = rollback_update_install(&installed).err();
            cleanup_update_temp_targets(&temp_targets);
            return Err(with_update_recovery_error(
                format!(
                    "release update install plan is missing target {}",
                    target_file.display()
                ),
                recovery_errors,
            ));
        };
        let backup_file = report.backup_file.clone();
        if let Err(error) = remove_existing_update_install_target(target_file) {
            let recovery_errors = rollback_update_install(&installed).err();
            cleanup_update_temp_targets(&temp_targets);
            return Err(with_update_recovery_error(error, recovery_errors));
        }
        if let Err(error) = ensure_update_install_file_parent(target_file)
            .and_then(|_| ensure_update_install_file_parent(temp_target))
            .and_then(|_| verify_update_temp_install_target(report, temp_target))
        {
            let mut recovery_errors = Vec::new();
            if let Some(backup_file) = backup_file.as_ref()
                && let Err(error) = restore_update_backup(target_file, backup_file)
            {
                recovery_errors.push(error);
            }
            if let Err(error) = rollback_update_install(&installed) {
                recovery_errors.push(error);
            }
            cleanup_update_temp_targets(&temp_targets);
            return Err(with_update_recovery_error(
                error,
                (!recovery_errors.is_empty()).then(|| recovery_errors.join("; ")),
            ));
        }
        if let Err(error) = fs::rename(temp_target, target_file) {
            let mut recovery_errors = Vec::new();
            if let Some(backup_file) = backup_file.as_ref()
                && let Err(error) = restore_update_backup(target_file, backup_file)
            {
                recovery_errors.push(error);
            }
            if let Err(error) = rollback_update_install(&installed) {
                recovery_errors.push(error);
            }
            cleanup_update_temp_targets(&temp_targets);
            return Err(with_update_recovery_error(
                format!(
                    "could not install release update binary {}: {error}",
                    target_file.display()
                ),
                (!recovery_errors.is_empty()).then(|| recovery_errors.join("; ")),
            ));
        }
        installed.push((target_file.clone(), backup_file));
    }

    Ok(reports)
}

fn inspect_update_install_target(target_file: &Path) -> Result<bool, String> {
    ensure_update_install_file_parent_if_present(target_file)?;
    match fs::symlink_metadata(target_file) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "release update install target is not a regular file: {}",
                    target_file.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "could not inspect release update install target {}: {error}",
            target_file.display()
        )),
    }
}

fn remove_existing_update_install_target(target_file: &Path) -> Result<(), String> {
    if !inspect_update_install_target(target_file)? {
        return Ok(());
    }
    ensure_update_install_file_parent(target_file)?;
    fs::remove_file(target_file).map_err(|error| {
        format!(
            "could not replace release update binary {}: {error}",
            target_file.display()
        )
    })
}

fn with_update_recovery_error(error: String, recovery_error: Option<String>) -> String {
    match recovery_error {
        Some(recovery_error) => format!("{error}; rollback also reported: {recovery_error}"),
        None => error,
    }
}

fn back_up_existing_update_binaries(reports: &[UpdateApplyBinaryReport]) -> Result<(), String> {
    for report in reports {
        ensure_update_install_file_parent_if_present(&report.target_file)?;
        let metadata = match fs::symlink_metadata(&report.target_file) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "could not inspect release update install target {}: {error}",
                    report.target_file.display()
                ));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "release update install target is not a regular file: {}",
                report.target_file.display()
            ));
        }
        let Some(backup_file) = report.backup_file.as_ref() else {
            return Err(format!(
                "release update backup path was not prepared for {}",
                report.target_file.display()
            ));
        };
        ensure_update_backup_file_parent(backup_file)?;
        if backup_file.exists() {
            return Err(format!(
                "release update backup target already exists: {}",
                backup_file.display()
            ));
        }
        ensure_update_install_file_parent(&report.target_file)?;
        let mut source_file = fs::File::open(&report.target_file).map_err(|error| {
            format!(
                "could not back up release update binary {}: {error}",
                report.target_file.display()
            )
        })?;
        ensure_update_install_target_unchanged_while_backing_up(
            &report.target_file,
            &metadata,
            &source_file,
        )?;
        let mut backup = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(backup_file)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(format!(
                    "release update backup target already exists: {}",
                    backup_file.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "could not reserve release update backup target {}: {error}",
                    backup_file.display()
                ));
            }
        };
        let copied = match io::copy(&mut source_file, &mut backup) {
            Ok(copied) => copied,
            Err(error) => {
                drop(backup);
                remove_update_backup_file_if_safe(backup_file);
                return Err(format!(
                    "could not back up release update binary {}: {error}",
                    report.target_file.display()
                ));
            }
        };
        drop(backup);
        if let Err(error) = ensure_update_install_target_unchanged_while_backing_up(
            &report.target_file,
            &metadata,
            &source_file,
        ) {
            remove_update_backup_file_if_safe(backup_file);
            return Err(error);
        }
        if copied != metadata.len() {
            remove_update_backup_file_if_safe(backup_file);
            return Err(format!(
                "release update install target changed while backing up {}",
                report.target_file.display()
            ));
        }
    }
    Ok(())
}

fn ensure_update_install_target_unchanged_while_backing_up(
    target_file: &Path,
    expected: &fs::Metadata,
    source_file: &fs::File,
) -> Result<(), String> {
    ensure_update_install_file_parent(target_file)?;
    let path_metadata = match fs::symlink_metadata(target_file) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(format!(
                "could not inspect release update install target {}: {error}",
                target_file.display()
            ));
        }
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(format!(
            "release update install target is not a regular file: {}",
            target_file.display()
        ));
    }
    if !update_input_file_metadata_matches(expected, &path_metadata) {
        return Err(format!(
            "release update install target changed while backing up {}",
            target_file.display()
        ));
    }
    let opened_metadata = source_file.metadata().map_err(|error| {
        format!(
            "could not inspect opened release update install target {}: {error}",
            target_file.display()
        )
    })?;
    if !opened_metadata.is_file() || !update_input_file_metadata_matches(expected, &opened_metadata)
    {
        return Err(format!(
            "release update install target changed while backing up {}",
            target_file.display()
        ));
    }
    Ok(())
}

fn create_update_temp_install_target(
    report: &UpdateApplyBinaryReport,
    install_dir: &Path,
    filename: &str,
    nonce: u128,
) -> Result<PathBuf, String> {
    match report.target_file.parent() {
        Some(parent) if parent == install_dir => {}
        _ => {
            return Err(format!(
                "release update install target is outside install-dir: {}",
                report.target_file.display()
            ));
        }
    }
    ensure_update_install_file_parent(&report.target_file)?;
    ensure_update_install_directory(install_dir)?;
    let source_label = "release update staged binary";
    let source_metadata = update_input_file_metadata(&report.source_file, source_label)?;
    if source_metadata.len() != report.bytes {
        return Err(format!(
            "release update staged binary changed while preparing {}",
            report.target_file.display()
        ));
    }

    for attempt in 0..1024 {
        let temp_target =
            install_dir.join(format!(".{filename}.conu-update-new-{nonce}-{attempt}"));
        let mut temp_file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_target)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "could not reserve release update temporary install target {}: {error}",
                    temp_target.display()
                ));
            }
        };

        let path_metadata = match update_input_file_metadata(&report.source_file, source_label) {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(temp_file);
                remove_update_install_file_if_safe(&temp_target);
                return Err(error);
            }
        };
        if !update_input_file_metadata_matches(&source_metadata, &path_metadata) {
            drop(temp_file);
            remove_update_install_file_if_safe(&temp_target);
            return Err(format!(
                "release update staged binary changed while preparing {}",
                report.target_file.display()
            ));
        }
        let mut source_file = match fs::File::open(&report.source_file) {
            Ok(file) => file,
            Err(error) => {
                drop(temp_file);
                remove_update_install_file_if_safe(&temp_target);
                return Err(format!(
                    "could not stage release update binary {}: {error}",
                    report.target_file.display()
                ));
            }
        };
        let opened_path_metadata =
            match update_input_file_metadata(&report.source_file, source_label) {
                Ok(metadata) => metadata,
                Err(error) => {
                    drop(temp_file);
                    remove_update_install_file_if_safe(&temp_target);
                    return Err(error);
                }
            };
        if !update_input_file_metadata_matches(&source_metadata, &opened_path_metadata) {
            drop(temp_file);
            remove_update_install_file_if_safe(&temp_target);
            return Err(format!(
                "release update staged binary changed while preparing {}",
                report.target_file.display()
            ));
        }
        let opened_metadata = match source_file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(temp_file);
                remove_update_install_file_if_safe(&temp_target);
                return Err(format!(
                    "release update staged binary metadata could not be read: {error}"
                ));
            }
        };
        if !opened_metadata.is_file()
            || !update_input_file_metadata_matches(&source_metadata, &opened_metadata)
        {
            drop(temp_file);
            remove_update_install_file_if_safe(&temp_target);
            return Err(format!(
                "release update staged binary changed while preparing {}",
                report.target_file.display()
            ));
        }
        let (copied, copied_sha256) =
            match copy_update_binary_with_sha256(&mut source_file, &mut temp_file) {
                Ok(result) => result,
                Err(error) => {
                    drop(temp_file);
                    remove_update_install_file_if_safe(&temp_target);
                    return Err(format!(
                        "could not stage release update binary {}: {error}",
                        report.target_file.display()
                    ));
                }
            };
        if copied != report.bytes || copied_sha256 != report.sha256 {
            drop(temp_file);
            remove_update_install_file_if_safe(&temp_target);
            return Err(format!(
                "release update staged binary changed while preparing {}",
                report.target_file.display()
            ));
        }
        let final_source_metadata =
            match update_input_file_metadata(&report.source_file, source_label) {
                Ok(metadata) => metadata,
                Err(error) => {
                    drop(temp_file);
                    remove_update_install_file_if_safe(&temp_target);
                    return Err(error);
                }
            };
        if !update_input_file_metadata_matches(&source_metadata, &final_source_metadata) {
            drop(temp_file);
            remove_update_install_file_if_safe(&temp_target);
            return Err(format!(
                "release update staged binary changed while preparing {}",
                report.target_file.display()
            ));
        }
        let final_opened_metadata = match source_file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(temp_file);
                remove_update_install_file_if_safe(&temp_target);
                return Err(format!(
                    "release update staged binary metadata could not be read: {error}"
                ));
            }
        };
        if !update_input_file_metadata_matches(&source_metadata, &final_opened_metadata) {
            drop(temp_file);
            remove_update_install_file_if_safe(&temp_target);
            return Err(format!(
                "release update staged binary changed while preparing {}",
                report.target_file.display()
            ));
        }
        if let Err(error) = set_update_binary_file_permissions(&temp_file, &temp_target) {
            drop(temp_file);
            remove_update_install_file_if_safe(&temp_target);
            return Err(error);
        }
        drop(temp_file);
        return Ok(temp_target);
    }

    Err(format!(
        "could not reserve unique release update temporary install target for {filename}"
    ))
}

fn verify_update_temp_install_target(
    report: &UpdateApplyBinaryReport,
    temp_target: &Path,
) -> Result<(), String> {
    ensure_update_install_file_parent(temp_target)?;
    let label = "release update temporary install target";
    let metadata = update_input_file_metadata(temp_target, label)?;
    if metadata.len() != report.bytes {
        return Err(format!(
            "release update temporary install target changed before installing {}",
            report.target_file.display()
        ));
    }
    let mut temp_file = fs::File::open(temp_target).map_err(|error| {
        format!(
            "could not open release update temporary install target {}: {error}",
            temp_target.display()
        )
    })?;
    let opened_path_metadata = update_input_file_metadata(temp_target, label)?;
    if !update_input_file_metadata_matches(&metadata, &opened_path_metadata) {
        return Err(format!(
            "release update temporary install target changed before installing {}",
            report.target_file.display()
        ));
    }
    let opened_metadata = temp_file.metadata().map_err(|error| {
        format!(
            "could not inspect opened release update temporary install target {}: {error}",
            temp_target.display()
        )
    })?;
    if !opened_metadata.is_file()
        || !update_input_file_metadata_matches(&metadata, &opened_metadata)
    {
        return Err(format!(
            "release update temporary install target changed before installing {}",
            report.target_file.display()
        ));
    }
    let mut sink = io::sink();
    let (read, sha256) =
        copy_update_binary_with_sha256(&mut temp_file, &mut sink).map_err(|error| {
            format!(
                "could not verify release update temporary install target {}: {error}",
                temp_target.display()
            )
        })?;
    if read != report.bytes || sha256 != report.sha256 {
        return Err(format!(
            "release update temporary install target changed before installing {}",
            report.target_file.display()
        ));
    }
    let final_path_metadata = update_input_file_metadata(temp_target, label)?;
    if !update_input_file_metadata_matches(&metadata, &final_path_metadata) {
        return Err(format!(
            "release update temporary install target changed before installing {}",
            report.target_file.display()
        ));
    }
    let final_opened_metadata = temp_file.metadata().map_err(|error| {
        format!(
            "could not inspect opened release update temporary install target {}: {error}",
            temp_target.display()
        )
    })?;
    if !final_opened_metadata.is_file()
        || !update_input_file_metadata_matches(&metadata, &final_opened_metadata)
    {
        return Err(format!(
            "release update temporary install target changed before installing {}",
            report.target_file.display()
        ));
    }
    Ok(())
}

fn rollback_update_install(installed: &[(PathBuf, Option<PathBuf>)]) -> Result<(), String> {
    let mut errors = Vec::new();
    for (target_file, backup_file) in installed.iter().rev() {
        match ensure_update_install_file_parent_if_present(target_file) {
            Ok(()) => match fs::remove_file(target_file) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => errors.push(format!(
                    "could not remove partially installed release update binary {}: {error}",
                    target_file.display()
                )),
            },
            Err(error) => errors.push(error),
        }
        if let Some(backup_file) = backup_file
            && let Err(error) = restore_update_backup(target_file, backup_file)
        {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn restore_update_backup(target_file: &Path, backup_file: &Path) -> Result<(), String> {
    ensure_update_backup_file_parent_if_present(backup_file)?;
    ensure_update_install_file_parent(target_file)?;
    let metadata = update_backup_file_metadata(backup_file)?;
    let mut backup = fs::File::open(backup_file).map_err(|error| {
        format!(
            "could not open release update backup file {}: {error}",
            backup_file.display()
        )
    })?;
    let opened_path_metadata = update_backup_file_metadata(backup_file)?;
    if !update_input_file_metadata_matches(&metadata, &opened_path_metadata) {
        return Err(format!(
            "release update backup changed while opening {}",
            backup_file.display()
        ));
    }
    let opened_metadata = backup.metadata().map_err(|error| {
        format!(
            "could not inspect opened release update backup file {}: {error}",
            backup_file.display()
        )
    })?;
    if !opened_metadata.is_file()
        || !update_input_file_metadata_matches(&metadata, &opened_metadata)
    {
        return Err(format!(
            "release update backup changed while opening {}",
            backup_file.display()
        ));
    }
    let mut target = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target_file)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "release update restore target already exists: {}",
                target_file.display()
            ));
        }
        Err(error) => {
            return Err(format!(
                "could not reserve release update restore target {}: {error}",
                target_file.display()
            ));
        }
    };
    let copied = match io::copy(&mut backup, &mut target) {
        Ok(copied) => copied,
        Err(error) => {
            drop(target);
            remove_update_install_file_if_safe(target_file);
            return Err(format!(
                "could not restore release update backup {} to {}: {error}",
                backup_file.display(),
                target_file.display()
            ));
        }
    };
    let final_path_metadata = match update_backup_file_metadata(backup_file) {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(target);
            remove_update_install_file_if_safe(target_file);
            return Err(error);
        }
    };
    if !update_input_file_metadata_matches(&metadata, &final_path_metadata) {
        drop(target);
        remove_update_install_file_if_safe(target_file);
        return Err(format!(
            "release update backup changed while restoring {}",
            backup_file.display()
        ));
    }
    let final_opened_metadata = match backup.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(target);
            remove_update_install_file_if_safe(target_file);
            return Err(format!(
                "could not inspect opened release update backup file {}: {error}",
                backup_file.display()
            ));
        }
    };
    if !update_input_file_metadata_matches(&metadata, &final_opened_metadata) {
        drop(target);
        remove_update_install_file_if_safe(target_file);
        return Err(format!(
            "release update backup changed while restoring {}",
            backup_file.display()
        ));
    }
    if copied != metadata.len() {
        drop(target);
        remove_update_install_file_if_safe(target_file);
        return Err(format!(
            "release update backup changed while restoring {}",
            backup_file.display()
        ));
    }
    if let Err(error) = set_update_binary_file_permissions(&target, target_file) {
        drop(target);
        remove_update_install_file_if_safe(target_file);
        return Err(error);
    }
    drop(target);
    Ok(())
}

fn update_backup_file_metadata(backup_file: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(backup_file).map_err(|error| {
        format!(
            "could not inspect release update backup file {}: {error}",
            backup_file.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "release update backup file is not a regular file: {}",
            backup_file.display()
        ));
    }
    Ok(metadata)
}

fn cleanup_update_temp_targets(temp_targets: &[(PathBuf, PathBuf)]) {
    for (_, temp_target) in temp_targets {
        remove_update_install_file_if_safe(temp_target);
    }
}

fn remove_update_install_file_if_safe(path: &Path) {
    if ensure_update_install_file_parent_if_present(path).is_ok() {
        let _ = fs::remove_file(path);
    }
}

fn remove_update_backup_file_if_safe(path: &Path) {
    if ensure_update_backup_file_parent_if_present(path).is_ok() {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
fn set_update_binary_file_permissions(file: &fs::File, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = file.metadata().map_err(|error| {
        format!(
            "could not read release update binary permissions {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "release update binary is not a regular file: {}",
            path.display()
        ));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    file.set_permissions(permissions).map_err(|error| {
        format!(
            "could not set release update binary permissions {}: {error}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_update_binary_file_permissions(_file: &fs::File, _path: &Path) -> Result<(), String> {
    Ok(())
}

fn ensure_update_output_files_available(dir: &Path, names: &[&str]) -> Result<(), String> {
    ensure_update_output_directory(dir)?;
    let mut seen = HashSet::new();
    for name in names {
        validate_public_asset_name(name, "downloaded update asset")?;
        if !seen.insert(*name) {
            return Err(format!(
                "release update artifact output names overlap: {name}"
            ));
        }
        let path = dir.join(name);
        ensure_update_output_path_available(&path, None)?;
    }
    Ok(())
}

fn ensure_update_output_directory(dir: &Path) -> Result<(), String> {
    if update_output_directory_exists(dir)? {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|error| {
        format!(
            "could not create release update artifact output directory {}: {error}",
            dir.display()
        )
    })?;
    if update_output_directory_exists(dir)? {
        return Ok(());
    }
    Err(format!(
        "could not create release update artifact output directory {}: directory was not created",
        dir.display()
    ))
}

fn update_output_directory_exists(dir: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "release update artifact output directory is not a directory: {}",
                    dir.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "could not inspect release update artifact output directory {}: {error}",
            dir.display()
        )),
    }
}

fn ensure_update_output_path_available(path: &Path, label: Option<&str>) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(update_output_exists_message(path, label)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect release update artifact output {}: {error}",
            path.display()
        )),
    }
}

fn update_output_exists_message(path: &Path, label: Option<&str>) -> String {
    match label {
        Some(label) => format!(
            "release update artifact {label} output already exists: {}",
            path.display()
        ),
        None => format!(
            "release update artifact output already exists: {}",
            path.display()
        ),
    }
}

fn write_update_output_file(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    label: &str,
) -> Result<PathBuf, String> {
    validate_public_asset_name(name, "downloaded update asset")?;
    ensure_update_output_directory(dir)?;
    let path = dir.join(name);
    ensure_update_output_path_available(&path, Some(label))?;
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "release update artifact {label} output already exists: {}",
                path.display()
            ));
        }
        Err(error) => {
            return Err(format!(
                "could not reserve release update artifact {label} {}: {error}",
                path.display()
            ));
        }
    };
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(format!(
            "could not write release update artifact {label} {}: {error}",
            path.display()
        ));
    }
    Ok(path)
}

fn default_update_target() -> Option<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-x64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("macos", "x86_64") => Some("macos-x64"),
        ("macos", "aarch64") => Some("macos-arm64"),
        ("windows", "x86_64") => Some("windows-x64"),
        _ => None,
    }
}

fn render_update_check_json(report: &UpdateCheckReport) -> String {
    let location_fields = match report.source {
        UpdateCheckSource::Local => r#"
  "policyFile": "local",
  "sha256File": "local",
  "signatureFile": "local",
  "pathDisplayed": false,"#
            .to_string(),
        UpdateCheckSource::Remote => format!(
            r#"
  "policyUrl": "{}",
  "sha256Url": "{}",
  "signatureUrl": "{}","#,
            json_escape(&report.policy_location),
            json_escape(&report.sha256_location),
            json_escape(&report.signature_location)
        ),
    };
    format!(
        r#"{{
  "status": "update_policy_valid",
  "source": "{}",
  "schema": "{}",
  "version": "{}",
  "releaseTag": "{}",
  "channel": "{}",
  "releaseBaseUrl": "{}",{}
  "sha256": "{}",
  "sha256SidecarMatched": true,
  "signatureSidecarPresent": true,
  "gpgVerified": {},
  "apply": {{
    "autoApply": {},
    "manualVerificationRequired": {},
    "operatorConsentRequired": {}
  }},
  "assetCounts": {{
    "platformArchives": {},
    "packageManagerAssets": {},
    "linuxPackageAssets": {},
    "repositoryAssets": {}
  }},
  "privacy": {{
    "payloadDisplayed": false,
    "tokenDisplayed": false,
    "keyMaterialDisplayed": false,
    "ciphertextDisplayed": false,
    "contentsDisplayed": false
  }}
}}"#,
        report.source.as_str(),
        UPDATE_POLICY_SCHEMA,
        json_escape(&report.version),
        json_escape(&report.release_tag),
        json_escape(&report.channel),
        json_escape(&report.release_base_url),
        location_fields,
        report.sha256,
        report.gpg_verified,
        report.auto_apply,
        report.manual_verification_required,
        report.operator_consent_required,
        report.platform_archives,
        report.package_manager_assets,
        report.linux_package_assets,
        report.repository_assets
    )
}

fn render_update_check_text(report: &UpdateCheckReport) -> String {
    let (location_label, location_value) = match report.source {
        UpdateCheckSource::Local => ("file", "local; pathDisplayed=false".to_string()),
        UpdateCheckSource::Remote => ("url", report.policy_location.clone()),
    };
    format!(
        r"conU update check

status: update policy valid
source: {}
schema: {}
version: {}
tag: {}
channel: {}
release base: {}

policy
  {}              {}
  sha256           {}
  sidecar          matched
  signature        present
  gpg verified     {}

apply
  auto apply       {}
  manual verify    {}
  operator consent {}

assets
  platform archives {}
  package managers  {}
  linux packages    {}
  repository assets {}

privacy
  payload view      contents are not displayed by conU",
        report.source.as_str(),
        UPDATE_POLICY_SCHEMA,
        report.version,
        report.release_tag,
        report.channel,
        report.release_base_url,
        location_label,
        location_value,
        report.sha256,
        yes_no(report.gpg_verified),
        yes_no(report.auto_apply),
        yes_no(report.manual_verification_required),
        yes_no(report.operator_consent_required),
        report.platform_archives,
        report.package_manager_assets,
        report.linux_package_assets,
        report.repository_assets
    )
}

fn render_update_download_json(report: &UpdateArtifactDownloadReport) -> String {
    format!(
        r#"{{
  "status": "update_artifact_downloaded",
  "source": "{}",
  "version": "{}",
  "releaseTag": "{}",
  "target": "{}",
  "filename": "{}",
  "url": "{}",
  "artifactFile": "local",
  "sha256File": "local",
  "signatureFile": "local",
  "pathDisplayed": false,
  "bytes": {},
  "sha256": "{}",
  "sha256SidecarMatched": true,
  "signatureSidecarPresent": true,
  "gpgVerified": {},
  "updateApplied": false,
  "privacy": {{
    "payloadDisplayed": false,
    "tokenDisplayed": false,
    "keyMaterialDisplayed": false,
    "ciphertextDisplayed": false,
    "contentsDisplayed": false
  }}
}}"#,
        report.policy.source.as_str(),
        json_escape(&report.policy.version),
        json_escape(&report.policy.release_tag),
        json_escape(&report.target),
        json_escape(&report.filename),
        json_escape(&report.url),
        report.bytes,
        report.sha256,
        report.gpg_verified
    )
}

fn render_update_download_text(report: &UpdateArtifactDownloadReport) -> String {
    format!(
        r"conU update download

status: artifact downloaded
source: {}
version: {}
tag: {}
target: {}

artifact
  filename         {}
  file             local; pathDisplayed=false
  bytes            {}
  sha256           {}
  sidecar          matched
  signature        present
  gpg verified     {}

apply
  update applied   no

privacy
  payload view      contents are not displayed by conU",
        report.policy.source.as_str(),
        report.policy.version,
        report.policy.release_tag,
        report.target,
        report.filename,
        report.bytes,
        report.sha256,
        yes_no(report.gpg_verified)
    )
}

fn render_update_apply_json(report: &UpdateApplyReport) -> String {
    let backup_dir = report
        .backup_dir
        .as_ref()
        .map(|_| r#""local""#.to_string())
        .unwrap_or_else(|| "null".to_string());
    let binaries = report
        .binaries
        .iter()
        .map(|binary| {
            let backup_file = binary
                .backup_file
                .as_ref()
                .map(|_| r#""local""#.to_string())
                .unwrap_or_else(|| "null".to_string());
            format!(
                r#"    {{
      "name": "{}",
      "targetFile": "local",
      "backupFile": {},
      "pathDisplayed": false,
      "bytes": {}
    }}"#,
                json_escape(&binary.name),
                backup_file,
                binary.bytes
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        r#"{{
  "status": "{}",
  "source": "{}",
  "version": "{}",
  "releaseTag": "{}",
  "target": "{}",
  "filename": "{}",
  "archiveFile": "local",
  "installDir": "local",
  "backupDir": {},
  "pathDisplayed": false,
  "entriesScanned": {},
  "unpackedBytes": {},
  "binaries": [
{}
  ],
  "sha256": "{}",
  "sha256SidecarMatched": true,
  "signatureSidecarPresent": true,
  "gpgVerified": {},
  "dryRun": {},
  "updateApplied": {},
  "privacy": {{
    "payloadDisplayed": false,
    "tokenDisplayed": false,
    "keyMaterialDisplayed": false,
    "ciphertextDisplayed": false,
    "contentsDisplayed": false
  }}
}}"#,
        if report.update_applied {
            "update_applied"
        } else {
            "update_apply_ready"
        },
        report.policy.source.as_str(),
        json_escape(&report.policy.version),
        json_escape(&report.policy.release_tag),
        json_escape(&report.target),
        json_escape(&report.filename),
        backup_dir,
        report.entries_scanned,
        report.unpacked_bytes,
        binaries,
        report.sha256,
        report.gpg_verified,
        report.dry_run,
        report.update_applied
    )
}

fn render_update_apply_text(report: &UpdateApplyReport) -> String {
    let backup_dir = report
        .backup_dir
        .as_ref()
        .map(|_| "local; pathDisplayed=false".to_string())
        .unwrap_or_else(|| "none".to_string());
    let binaries = report
        .binaries
        .iter()
        .map(|binary| format!("  {:<15} local; pathDisplayed=false", binary.name))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r"conU update apply

status: {}
source: {}
version: {}
tag: {}
target: {}

artifact
  filename         {}
  file             local; pathDisplayed=false
  bytes unpacked   {}
  entries scanned  {}
  sha256           {}
  sidecar          matched
  signature        present
  gpg verified     {}

install
  install dir      local; pathDisplayed=false
  backup dir       {}
  dry run          {}
  update applied   {}

binaries
{}

privacy
  payload view      contents are not displayed by conU",
        if report.update_applied {
            "update applied"
        } else {
            "ready to apply"
        },
        report.policy.source.as_str(),
        report.policy.version,
        report.policy.release_tag,
        report.target,
        report.filename,
        report.unpacked_bytes,
        report.entries_scanned,
        report.sha256,
        yes_no(report.gpg_verified),
        backup_dir,
        yes_no(report.dry_run),
        yes_no(report.update_applied),
        binaries
    )
}

fn render_update_usage() -> String {
    r"usage:
  conu update check --policy-file <path> [--sha256-file <path>] [--signature-file <path>] [--gpg-verify] [--json]
  conu update check --policy-url <https-url> [--sha256-url <https-url>] [--signature-url <https-url>] [--gpg-verify] [--json]
  conu update download --policy-file <path> --output-dir <dir> [--target <target>] [--gpg-verify] [--json]
  conu update download --policy-url <https-url> --output-dir <dir> [--target <target>] [--sha256-url <https-url>] [--signature-url <https-url>] [--gpg-verify] [--json]
  conu update apply --policy-file <path> --artifact-file <archive> --install-dir <dir> [--target <target>] [--gpg-verify] (--dry-run|--confirm) [--json]
  conu update apply --policy-url <https-url> --artifact-file <archive> --install-dir <dir> [--target <target>] [--sha256-url <https-url>] [--signature-url <https-url>] [--gpg-verify] (--dry-run|--confirm) [--json]"
        .to_string()
}

fn render_update_check_usage() -> String {
    render_update_usage()
}

fn render_update_download_usage() -> String {
    render_update_usage()
}

fn render_update_apply_usage() -> String {
    render_update_usage()
}

#[derive(Debug)]
struct UpdateDownloadDir {
    path: PathBuf,
}

impl UpdateDownloadDir {
    fn create() -> Result<Self, String> {
        let temp_root = env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();

        for attempt in 0..1024 {
            let path = temp_root.join(format!(
                "conu-update-check-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "could not create temporary update check directory {}: {error}",
                        path.display()
                    ));
                }
            }
        }

        Err("could not create unique temporary update check directory".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UpdateDownloadDir {
    fn drop(&mut self) {
        if self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("conu-update-check-"))
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedUpdateUrl {
    host: String,
    port: u16,
    path_and_query: String,
}

impl ParsedUpdateUrl {
    fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UpdateHttpFetch {
    Body(Vec<u8>),
    Redirect(String),
}

fn fetch_update_url_bounded(url: &str, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut current = url.to_string();
    for redirect_count in 0..=MAX_UPDATE_REDIRECTS {
        match fetch_update_url_once(&current, max_bytes, label, redirect_count > 0)? {
            UpdateHttpFetch::Body(bytes) => return Ok(bytes),
            UpdateHttpFetch::Redirect(next) => current = next,
        }
    }

    Err(format!("{label} download followed too many redirects"))
}

fn fetch_update_url_once(
    url: &str,
    max_bytes: u64,
    label: &str,
    allow_query: bool,
) -> Result<UpdateHttpFetch, String> {
    let parsed = parse_https_update_url(url, label, allow_query)?;
    let timeout = Duration::from_secs(UPDATE_DOWNLOAD_TIMEOUT_SECONDS);
    let stream = connect_update_public_tcp(&parsed.host, parsed.port, timeout, label)?;
    let connector = TlsConnector::new()
        .map_err(|error| format!("{label} download could not configure TLS: {error}"))?;
    let mut stream = match connector.connect(&parsed.host, stream) {
        Ok(stream) => stream,
        Err(HandshakeError::Failure(error)) => {
            return Err(format!("{label} download TLS handshake failed: {error}"));
        }
        Err(HandshakeError::WouldBlock(_)) => {
            return Err(format!("{label} download TLS handshake would block"));
        }
    };

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: conu-update-check/0.1\r\nAccept: application/octet-stream, application/json;q=0.9, text/plain;q=0.8\r\nConnection: close\r\n\r\n",
        parsed.path_and_query,
        parsed.authority()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("{label} download request failed: {error}"))?;
    let headers = read_update_http_headers(&mut stream, label)?;
    let status = parse_update_http_status(&headers, label)?;
    if (300..400).contains(&status) {
        let location = update_http_header_value(&headers, "location")
            .ok_or_else(|| format!("{label} download redirect was missing Location header"))?;
        return Ok(UpdateHttpFetch::Redirect(resolve_update_redirect(
            &location, &parsed, label,
        )?));
    }
    if status != 200 {
        return Err(format!("{label} download returned HTTP {status}"));
    }

    if let Some(length) = update_http_header_value(&headers, "content-length") {
        let length = length
            .parse::<u64>()
            .map_err(|_| format!("{label} download Content-Length was invalid"))?;
        if length > max_bytes {
            return Err(format!("{label} download is too large"));
        }
    }

    if update_http_header_value(&headers, "transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        read_update_chunked_body(&mut stream, max_bytes, label)
    } else {
        read_update_body_to_end(&mut stream, max_bytes, label)
    }
    .map(UpdateHttpFetch::Body)
}

fn read_update_http_headers(stream: &mut impl Read, label: &str) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1];
    while bytes.len() < MAX_UPDATE_HTTP_HEADER_BYTES {
        stream
            .read_exact(&mut buffer)
            .map_err(|error| format!("{label} download response header read failed: {error}"))?;
        bytes.push(buffer[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| format!("{label} download response headers were not UTF-8"));
        }
    }
    Err(format!("{label} download response headers were too large"))
}

fn parse_update_http_status(headers: &str, label: &str) -> Result<u16, String> {
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| format!("{label} download response was empty"))?;
    let mut parts = status_line.split_whitespace();
    let protocol = parts
        .next()
        .ok_or_else(|| format!("{label} download response was malformed"))?;
    if !protocol.starts_with("HTTP/") {
        return Err(format!("{label} download response was not HTTP"));
    }
    parts
        .next()
        .ok_or_else(|| format!("{label} download response did not include a status code"))?
        .parse::<u16>()
        .map_err(|_| format!("{label} download response status code was invalid"))
}

fn update_http_header_value(headers: &str, header: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(header) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn read_update_body_to_end(
    stream: &mut impl Read,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("{label} download body read failed: {error}"))?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len() as u64 + read as u64 > max_bytes {
            return Err(format!("{label} download is too large"));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn read_update_chunked_body(
    stream: &mut impl Read,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line = read_update_crlf_line(stream, 128, label)?;
        let chunk_size_text = line
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let chunk_size = u64::from_str_radix(&chunk_size_text, 16)
            .map_err(|_| format!("{label} download chunk size was invalid"))?;
        if chunk_size == 0 {
            loop {
                if read_update_crlf_line(stream, MAX_UPDATE_HTTP_HEADER_BYTES, label)?.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        if body.len() as u64 + chunk_size > max_bytes {
            return Err(format!("{label} download is too large"));
        }
        let chunk_len = usize::try_from(chunk_size)
            .map_err(|_| format!("{label} download chunk was too large"))?;
        let mut chunk = vec![0_u8; chunk_len];
        stream
            .read_exact(&mut chunk)
            .map_err(|error| format!("{label} download chunk read failed: {error}"))?;
        let mut crlf = [0_u8; 2];
        stream
            .read_exact(&mut crlf)
            .map_err(|error| format!("{label} download chunk terminator read failed: {error}"))?;
        if crlf != *b"\r\n" {
            return Err(format!("{label} download chunk terminator was invalid"));
        }
        body.extend_from_slice(&chunk);
    }
}

fn read_update_crlf_line(
    stream: &mut impl Read,
    max_bytes: usize,
    label: &str,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1];
    while bytes.len() < max_bytes {
        stream
            .read_exact(&mut buffer)
            .map_err(|error| format!("{label} download line read failed: {error}"))?;
        bytes.push(buffer[0]);
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len().saturating_sub(2));
            return String::from_utf8(bytes)
                .map_err(|_| format!("{label} download line was not UTF-8"));
        }
    }
    Err(format!("{label} download line was too large"))
}

fn resolve_update_redirect(
    location: &str,
    previous: &ParsedUpdateUrl,
    label: &str,
) -> Result<String, String> {
    if location.starts_with("https://") {
        parse_https_update_url(location, label, true)?;
        return Ok(location.to_string());
    }
    if location.starts_with('/') && !location.starts_with("//") {
        let next = format!("https://{}{}", previous.authority(), location);
        parse_https_update_url(&next, label, true)?;
        return Ok(next);
    }
    Err(format!(
        "{label} download redirect must stay on an absolute HTTPS URL"
    ))
}

fn connect_update_public_tcp(
    host: &str,
    port: u16,
    timeout: Duration,
    label: &str,
) -> Result<TcpStream, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{label} download could not resolve host: {error}"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(format!("{label} download host did not resolve"));
    }

    let mut last_error = None;
    let mut saw_public_address = false;
    for address in addresses {
        if !is_public_ip(address.ip()) {
            continue;
        }
        saw_public_address = true;
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout)).map_err(|error| {
                    format!("{label} download could not set read timeout: {error}")
                })?;
                stream.set_write_timeout(Some(timeout)).map_err(|error| {
                    format!("{label} download could not set write timeout: {error}")
                })?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }

    if !saw_public_address {
        return Err(format!(
            "{label} download host resolved only to non-public addresses"
        ));
    }

    Err(format!(
        "{label} download could not connect: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no reachable public address".to_string())
    ))
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = ip.octets();
    !(first == 0
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first == 100 && (64..=127).contains(&second))
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 88 && third == 99)
        || (first == 198 && (second == 18 || second == 19))
        || first >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_ipv6_unique_local(ip)
        || is_ipv6_link_local(ip)
        || is_ipv6_site_local(ip)
        || is_ipv6_documentation(ip)
        || is_ipv6_3fff_documentation(ip)
        || is_ipv6_discard_only(ip)
        || is_ipv6_dummy_prefix(ip)
        || is_ipv6_protocol_assignment(ip)
        || is_ipv6_nat64_local_use(ip)
        || is_ipv6_segment_routing_sid(ip)
        || is_ipv6_6to4(ip)
    {
        return false;
    }

    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    if let Some(compatible) = ipv4_compatible_address(ip) {
        return is_public_ipv4(compatible);
    }
    if let Some(well_known_nat64) = ipv6_well_known_nat64_address(ip) {
        return is_public_ipv4(well_known_nat64);
    }

    true
}

fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_site_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfec0
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_ipv6_3fff_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x3fff && (segments[1] & 0xf000) == 0
}

fn is_ipv6_discard_only(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
}

fn is_ipv6_dummy_prefix(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 1
}

fn is_ipv6_protocol_assignment(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] <= 0x01ff
}

fn is_ipv6_nat64_local_use(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1
}

fn is_ipv6_segment_routing_sid(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x5f00
}

fn is_ipv6_6to4(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2002
}

fn ipv6_well_known_nat64_address(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[..6] != [0x0064, 0xff9b, 0, 0, 0, 0] {
        return None;
    }
    Some(Ipv4Addr::new(
        (segments[6] >> 8) as u8,
        segments[6] as u8,
        (segments[7] >> 8) as u8,
        segments[7] as u8,
    ))
}

fn ipv4_compatible_address(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[..6].iter().any(|segment| *segment != 0) {
        return None;
    }
    Some(Ipv4Addr::new(
        (segments[6] >> 8) as u8,
        segments[6] as u8,
        (segments[7] >> 8) as u8,
        segments[7] as u8,
    ))
}

fn asset_name_from_update_url(url: &str, label: &str) -> Result<String, String> {
    let parsed = parse_https_update_url(url, label, false)?;
    let path = parsed.path_and_query.split('?').next().unwrap_or_default();
    let name = path
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("release update policy {label} must end with an asset filename"))?;
    validate_public_asset_name(name, label)?;
    Ok(name.to_string())
}

fn validate_update_sidecar_url(
    url: &str,
    expected_filename: &str,
    label: &str,
) -> Result<(), String> {
    let name = asset_name_from_update_url(url, label)?;
    if name != expected_filename {
        return Err(format!(
            "release update policy {label} ended with {name}, expected {expected_filename}"
        ));
    }
    Ok(())
}

fn write_downloaded_update_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    validate_public_asset_name(name, "downloaded update asset")?;
    fs::create_dir_all(dir).map_err(|error| {
        format!(
            "could not create downloaded release update policy directory {}: {error}",
            dir.display()
        )
    })?;
    let path = dir.join(name);
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "downloaded release update policy file already exists: {}",
                path.display()
            ));
        }
        Err(error) => {
            return Err(format!(
                "could not reserve downloaded release update policy file {}: {error}",
                path.display()
            ));
        }
    };
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(format!(
            "could not write downloaded release update policy file {}: {error}",
            path.display()
        ));
    }
    Ok(path)
}

fn update_input_file_metadata(path: &Path, label: &str) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "{label} file is not readable at {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} path is not a regular file: {}",
            path.display()
        ));
    }
    Ok(metadata)
}

fn read_limited_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = update_input_file_metadata(path, label)?;
    if metadata.len() > max_bytes {
        return Err(format!("{label} file is too large: {}", path.display()));
    }

    let mut file =
        fs::File::open(path).map_err(|error| format!("{label} file could not be read: {error}"))?;
    let path_metadata = update_input_file_metadata(path, label)?;
    if !update_input_file_metadata_matches(&metadata, &path_metadata) {
        return Err(format!(
            "{label} file changed while opening: {}",
            path.display()
        ));
    }
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("{label} file metadata could not be read: {error}"))?;
    if !opened_metadata.is_file() {
        return Err(format!(
            "{label} path is not a regular file: {}",
            path.display()
        ));
    }
    if opened_metadata.len() > max_bytes {
        return Err(format!("{label} file is too large: {}", path.display()));
    }
    if !update_input_file_metadata_matches(&metadata, &opened_metadata) {
        return Err(format!(
            "{label} file changed while opening: {}",
            path.display()
        ));
    }

    let mut bytes = Vec::new();
    let limit = max_bytes.saturating_add(1);
    let read = std::io::Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{label} file could not be read: {error}"))?;
    if read as u64 > max_bytes || bytes.len() as u64 > max_bytes {
        return Err(format!("{label} file is too large: {}", path.display()));
    }
    let final_path_metadata = update_input_file_metadata(path, label)?;
    if !update_input_file_metadata_matches(&metadata, &final_path_metadata) {
        return Err(format!(
            "{label} file changed while reading: {}",
            path.display()
        ));
    }
    let final_opened_metadata = file
        .metadata()
        .map_err(|error| format!("{label} file metadata could not be read: {error}"))?;
    if !update_input_file_metadata_matches(&metadata, &final_opened_metadata)
        || bytes.len() as u64 != final_opened_metadata.len()
    {
        return Err(format!(
            "{label} file changed while reading: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn update_input_file_metadata_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.len() == current.len() && update_input_file_identity_matches(expected, current)
}

#[cfg(unix)]
fn update_input_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == current.dev() && expected.ino() == current.ino()
}

#[cfg(windows)]
fn update_input_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    expected.file_attributes() == current.file_attributes()
        && expected.creation_time() == current.creation_time()
        && expected.last_write_time() == current.last_write_time()
        && expected.file_size() == current.file_size()
}

#[cfg(not(any(unix, windows)))]
fn update_input_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.modified().ok() == current.modified().ok()
}

fn verify_update_sha256_sidecar(
    path: &Path,
    policy_name: &str,
    actual_sha256: &str,
) -> Result<(), String> {
    let bytes = read_limited_file(
        path,
        MAX_UPDATE_CHECKSUM_BYTES,
        "release update policy checksum",
    )?;
    if !bytes.is_ascii() {
        return Err("release update policy checksum sidecar must be ASCII".to_string());
    }
    verify_update_sha256_sidecar_bytes(&bytes, policy_name, actual_sha256, "release update policy")
}

fn verify_update_sha256_sidecar_bytes(
    bytes: &[u8],
    asset_name: &str,
    actual_sha256: &str,
    label: &str,
) -> Result<(), String> {
    if !bytes.is_ascii() {
        return Err(format!("{label} checksum sidecar must be ASCII"));
    }
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("{label} checksum sidecar is invalid UTF-8: {error}"))?;
    let line = text.trim_end_matches(['\r', '\n']);
    if line.contains('\n') || line.contains('\r') {
        return Err(format!("{label} checksum sidecar must contain one line"));
    }
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(format!("{label} checksum sidecar has invalid format"));
    }
    let expected_sha256 = parts[0].to_ascii_lowercase();
    if !is_sha256_hex(&expected_sha256) {
        return Err(format!("{label} checksum sidecar hash is invalid"));
    }
    if parts[1] != asset_name {
        return Err(format!(
            "{label} checksum sidecar names {}, expected {asset_name}",
            parts[1]
        ));
    }
    if expected_sha256 != actual_sha256 {
        return Err(format!("{label} checksum did not match file"));
    }
    Ok(())
}

fn verify_update_signature_sidecar(path: &Path) -> Result<(), String> {
    let bytes = read_limited_file(
        path,
        MAX_UPDATE_SIGNATURE_BYTES,
        "release update policy signature",
    )?;
    verify_update_signature_sidecar_bytes(&bytes, "release update policy signature")
}

fn verify_update_signature_sidecar_bytes(bytes: &[u8], label: &str) -> Result<(), String> {
    if !bytes.is_ascii() {
        return Err(format!("{label} must be ASCII armored"));
    }
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("{label} is invalid UTF-8: {error}"))?;
    if !text.contains("BEGIN PGP SIGNATURE") {
        return Err(format!("{label} is not ASCII-armored PGP"));
    }
    Ok(())
}

fn verify_update_signature_with_gpg(signature: &Path, policy: &Path) -> Result<(), String> {
    verify_detached_signature_with_gpg(signature, policy, "release update policy")
}

fn verify_detached_signature_with_gpg(
    signature: &Path,
    subject: &Path,
    label: &str,
) -> Result<(), String> {
    let gpg = env::var("GPG_EXE").unwrap_or_else(|_| "gpg".to_string());
    let status = Command::new(&gpg)
        .arg("--verify")
        .arg(signature)
        .arg(subject)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            format!("could not run {gpg} for {label} signature verification: {error}")
        })?;
    if !status.success() {
        return Err(format!("{label} signature did not verify with gpg"));
    }
    Ok(())
}

fn json_string_field(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("release update policy is missing string field {field}"))
}

fn string_member<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| {
            format!("release update policy {context}.{field} must be a non-empty string")
        })
}

fn bool_member(
    object: &serde_json::Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<bool, String> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("release update policy {context}.{field} must be boolean"))
}

fn validate_public_https_url(value: &str, label: &str) -> Result<(), String> {
    parse_https_update_url(value, label, false).map(|_| ())
}

fn parse_https_update_url(
    value: &str,
    label: &str,
    allow_query: bool,
) -> Result<ParsedUpdateUrl, String> {
    if !value.starts_with("https://") {
        return Err(format!(
            "release update policy {label} must be an https URL"
        ));
    }
    if value.contains('#') || (!allow_query && value.contains('?')) {
        return Err(format!(
            "release update policy {label} must not include query or fragment"
        ));
    }
    let rest = &value["https://".len()..];
    let (authority, path_and_query) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(format!(
            "release update policy {label} must not include credentials"
        ));
    }
    if authority
        .as_bytes()
        .iter()
        .any(|byte| is_update_url_authority_control(*byte))
    {
        return Err(format!(
            "release update policy {label} authority is invalid"
        ));
    }
    if authority.chars().any(char::is_whitespace)
        || path_and_query.chars().any(char::is_whitespace)
        || path_and_query.contains('\\')
    {
        return Err(format!("release update policy {label} URL is invalid"));
    }
    validate_update_url_path(&path_and_query, label)?;

    let (host, port) = parse_update_authority(authority, label)?;
    validate_update_public_host(&host, label)?;

    Ok(ParsedUpdateUrl {
        host,
        port,
        path_and_query,
    })
}

fn parse_update_authority(authority: &str, label: &str) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port_text) = rest
            .split_once(']')
            .ok_or_else(|| format!("release update policy {label} IPv6 host is invalid"))?;
        let port = if let Some(port_text) = port_text.strip_prefix(':') {
            port_text
                .parse::<u16>()
                .map_err(|_| format!("release update policy {label} port is invalid"))?
        } else if port_text.is_empty() {
            443
        } else {
            return Err(format!(
                "release update policy {label} authority is invalid"
            ));
        };
        return Ok((host.to_ascii_lowercase(), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port_text))
            if !host.is_empty()
                && !port_text.is_empty()
                && port_text.chars().all(|c| c.is_ascii_digit()) =>
        {
            let port = port_text
                .parse::<u16>()
                .map_err(|_| format!("release update policy {label} port is invalid"))?;
            (host, port)
        }
        Some((_host, _port_text)) => {
            return Err(format!(
                "release update policy {label} authority is invalid"
            ));
        }
        None => (authority, 443),
    };
    Ok((host.trim().to_ascii_lowercase(), port))
}

fn validate_update_url_path(path_and_query: &str, label: &str) -> Result<(), String> {
    let path = path_and_query.split('?').next().unwrap_or_default();
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        if segment == "." || segment == ".." {
            return Err(format!(
                "release update policy {label} path must not contain dot segments"
            ));
        }
        let decoded = percent_decode_update_path_segment(segment, label)?;
        if decoded == b"." || decoded == b".." {
            return Err(format!(
                "release update policy {label} path must not contain dot segments"
            ));
        }
        if decoded.contains(&b'/') || decoded.contains(&b'\\') {
            return Err(format!(
                "release update policy {label} path must not contain encoded separators"
            ));
        }
        if decoded.iter().any(|byte| is_update_url_path_control(*byte)) {
            return Err(format!(
                "release update policy {label} path must not contain whitespace or control characters"
            ));
        }
    }
    Ok(())
}

fn is_update_url_authority_control(value: u8) -> bool {
    value <= b' ' || value == 0x7f || value == b'\\' || value == b'%'
}

fn is_update_url_path_control(value: u8) -> bool {
    value <= b' ' || value == 0x7f
}

fn percent_decode_update_path_segment(segment: &str, label: &str) -> Result<Vec<u8>, String> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(format!("release update policy {label} URL is invalid"));
            }
            let high = hex_value(bytes[index + 1])
                .ok_or_else(|| format!("release update policy {label} URL is invalid"))?;
            let low = hex_value(bytes[index + 2])
                .ok_or_else(|| format!("release update policy {label} URL is invalid"))?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_update_public_host(host: &str, label: &str) -> Result<(), String> {
    if host.is_empty()
        || host.contains('/')
        || host.contains('\\')
        || host.chars().any(char::is_whitespace)
    {
        return Err(format!("release update policy {label} host is invalid"));
    }
    let trimmed = host.trim_matches('.');
    if trimmed.eq_ignore_ascii_case("localhost")
        || trimmed.ends_with(".localhost")
        || trimmed.ends_with(".local")
    {
        return Err(format!("release update policy {label} host must be public"));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>()
        && !is_public_ip(ip)
    {
        return Err(format!("release update policy {label} host must be public"));
    }
    Ok(())
}

fn validate_asset_url(
    url: &str,
    release_base_url: &str,
    filename: &str,
    label: &str,
) -> Result<(), String> {
    validate_public_https_url(url, label)?;
    let expected = format!(
        "{}/{}",
        release_base_url.trim_end_matches('/'),
        percent_encode_asset_filename(filename)
    );
    if url != expected {
        return Err(format!(
            "release update policy {label} URL was {url}, expected {expected}"
        ));
    }
    Ok(())
}

fn validate_public_asset_name(filename: &str, label: &str) -> Result<(), String> {
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
        || filename.chars().any(char::is_whitespace)
    {
        return Err(format!(
            "release update policy {label} has unsafe asset name: {filename}"
        ));
    }
    Ok(())
}

fn percent_encode_asset_filename(filename: &str) -> String {
    filename
        .as_bytes()
        .iter()
        .map(|byte| match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (*byte as char).to_string()
            }
            value => format!("%{value:02X}"),
        })
        .collect::<String>()
}

fn semver_like(version: &str) -> bool {
    let mut parts = version.splitn(3, '.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch_and_suffix) = parts.next() else {
        return false;
    };
    if !numeric_identifier(major) || !numeric_identifier(minor) {
        return false;
    }
    let patch_digits = patch_and_suffix
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if patch_digits.is_empty() || !numeric_identifier(&patch_digits) {
        return false;
    }
    let suffix = &patch_and_suffix[patch_digits.len()..];
    suffix.is_empty()
        || suffix.len() > 1
            && (suffix.starts_with('-') || suffix.starts_with('+'))
            && suffix[1..]
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || ".-+".contains(character))
}

fn numeric_identifier(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|character| character.is_ascii_digit())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}{suffix}"))
        .unwrap_or_else(|| suffix.trim_start_matches('.').to_string());
    path.with_file_name(name)
}

fn file_name_string(path: &Path, label: &str) -> Result<String, String> {
    path.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("{label} path must include a valid file name"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorBinary {
    name: &'static str,
    path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorLogScan {
    payload_safe: bool,
    scanned_files: usize,
    issues: usize,
}

fn render_doctor(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu doctor [--json]");
    }
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let snapshot = match state::read_state(home_override.clone()) {
        Ok(snapshot) => snapshot,
        Err(error) => return CliOutput::failure(1, format!("conU doctor failed\n\n{error}")),
    };
    let runtime_status = match runtime::read_runtime(home_override.clone()) {
        Ok(status) => status,
        Err(error) => return CliOutput::failure(1, format!("conU doctor failed\n\n{error}")),
    };
    let security_audit =
        security::security_audit(home_override).unwrap_or_else(|_| empty_security_audit());
    let binaries = release_binaries();
    let log_scan = scan_payload_safe_logs(&snapshot);
    let status = doctor_status(&snapshot, &security_audit, &binaries, &log_scan);

    if json {
        CliOutput::success(render_doctor_json(
            status,
            &snapshot,
            &runtime_status,
            &security_audit,
            &binaries,
            &log_scan,
        ))
    } else {
        CliOutput::success(render_doctor_text(
            status,
            &snapshot,
            &runtime_status,
            &security_audit,
            &binaries,
            &log_scan,
        ))
    }
}

fn render_doctor_json(
    status: &str,
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> String {
    format!(
        r#"{{
  "status": "{}",
  "statePath": "{}",
  "initialized": {},
  "runtime": {{
    "state": "{}",
    "health": "{}",
    "pid": {}
  }},
  "binaries": {{
    "conu": {},
    "conud": {},
    "conuRelay": {},
    "conuMcp": {}
  }},
  "security": {{
    "initialized": {},
    "localPayloadEncryption": {},
    "signedAgentCards": {},
    "peerKeyExchange": {},
    "replayCache": {},
    "keyRotationPlan": {}
  }},
  "logs": {{
    "payloadSafe": {},
    "scannedFiles": {},
    "issues": {}
  }},
  "releaseGates": {{
    "localInstallReady": {},
    "controlledRelayReady": {},
    "managedPublicNetworkReady": false,
    "publicInternetReady": false,
    "knownLimitsDocumented": true
  }},
  "privacy": {{
    "contentsDisplayed": false
  }}
}}"#,
        json_escape(status),
        json_escape(&snapshot.paths.home.display().to_string()),
        snapshot.is_initialized(),
        runtime_status.state.as_str(),
        json_escape(runtime_health_label(runtime_status)),
        json_u32(runtime_status.pid),
        doctor_binary_json(binaries, "conu"),
        doctor_binary_json(binaries, "conud"),
        doctor_binary_json(binaries, "conu-relay"),
        doctor_binary_json(binaries, "conu-mcp"),
        security.initialized,
        security.local_payload_encryption,
        security.signed_agent_cards,
        security.peer_key_exchange,
        security.replay_cache,
        security.key_rotation_plan,
        log_scan.payload_safe,
        log_scan.scanned_files,
        log_scan.issues,
        local_install_ready(snapshot, security, binaries, log_scan),
        controlled_relay_ready(snapshot, security, binaries, log_scan)
    )
}

fn render_doctor_text(
    status: &str,
    snapshot: &StateSnapshot,
    runtime_status: &RuntimeStatus,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> String {
    format!(
        r"conU doctor

status: {status}
state path: {}

runtime
  conUD       {}
  health      {}
  pid         {}

binaries
{}

security
  initialized        {}
  local payloads     {}
  signed agents      {}
  peer exchange      {}
  replay guard       {}
  key rotation plan  {}

logs
  payload safe       {}
  scanned files      {}
  issues             {}

release gates
  local install      {}
  controlled relay   {}
  managed network    not ready; no managed multi-region relay service
  known limits       documented

privacy
  payload view       contents are not displayed by conU",
        snapshot.paths.home.display(),
        runtime_state_label(runtime_status),
        runtime_health_label(runtime_status),
        runtime_pid_label(runtime_status),
        doctor_binaries_text(binaries),
        ready_label(security.initialized),
        if security.local_payload_encryption {
            "encrypted at rest"
        } else {
            "not ready"
        },
        ready_label(security.signed_agent_cards),
        ready_label(security.peer_key_exchange),
        ready_label(security.replay_cache),
        ready_label(security.key_rotation_plan),
        yes_no(log_scan.payload_safe),
        log_scan.scanned_files,
        log_scan.issues,
        yes_no(local_install_ready(snapshot, security, binaries, log_scan)),
        yes_no(controlled_relay_ready(
            snapshot, security, binaries, log_scan
        ))
    )
}

const LOCAL_SMOKE_FROM_AGENT: &str = "agent.alpha";
const LOCAL_SMOKE_TO_AGENT: &str = "agent.beta";
const LOCAL_SMOKE_PAYLOAD: &[u8] = &[b'Z'; 32];
const LOCAL_SETUP_FROM_AGENT: &str = "agent.alpha";
const LOCAL_SETUP_TO_AGENT: &str = "agent.beta";
const LOCAL_SETUP_FROM_DISPLAY: &str = "Alpha Agent";
const LOCAL_SETUP_TO_DISPLAY: &str = "Beta Agent";
const LOCAL_SETUP_AGENT_KIND: &str = "local-agent";
const LOCAL_SETUP_ROOM: &str = "room.dev";
const LOCAL_SETUP_ROOM_DISPLAY: &str = "Dev Room";
const LOCAL_SETUP_PAYLOAD: &[u8] = &[0xA5; 32];

impl Default for LocalSetupOptions {
    fn default() -> Self {
        Self {
            from_agent_id: LOCAL_SETUP_FROM_AGENT.to_string(),
            to_agent_id: LOCAL_SETUP_TO_AGENT.to_string(),
            from_display_name: LOCAL_SETUP_FROM_DISPLAY.to_string(),
            to_display_name: LOCAL_SETUP_TO_DISPLAY.to_string(),
            from_agent_kind: LOCAL_SETUP_AGENT_KIND.to_string(),
            to_agent_kind: LOCAL_SETUP_AGENT_KIND.to_string(),
            from_display_name_explicit: false,
            to_display_name_explicit: false,
            from_agent_kind_explicit: false,
            to_agent_kind_explicit: false,
            room_id: LOCAL_SETUP_ROOM.to_string(),
            room_display_name: LOCAL_SETUP_ROOM_DISPLAY.to_string(),
            room_display_name_explicit: false,
            start_runtime: false,
            json: false,
        }
    }
}

impl SmokeHome {
    fn create(home_override: Option<PathBuf>) -> Result<Self, String> {
        let base = home_override
            .unwrap_or_else(env::temp_dir)
            .join("conu-smoke");
        fs::create_dir_all(&base)
            .map_err(|error| format!("could not prepare local smoke workspace: {error}"))?;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = base.join(format!("local-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)
            .map_err(|error| format!("could not create local smoke workspace: {error}"))?;

        Ok(Self { path })
    }
}

impl Drop for SmokeHome {
    fn drop(&mut self) {
        if self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("local-"))
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn render_smoke(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("local") => render_smoke_local(&args[1..], home_override),
        Some("--json") | None => render_smoke_local(args, home_override),
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_smoke_usage()),
        Some(_) => CliOutput::failure(2, render_smoke_usage()),
    }
}

fn render_smoke_local(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if args
        .iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "help")
    {
        return CliOutput::success(render_smoke_usage());
    }

    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    match run_local_smoke(home_override) {
        Ok(report) if json => CliOutput::success(render_local_smoke_json(&report)),
        Ok(report) => CliOutput::success(render_local_smoke_text(&report)),
        Err(error) => CliOutput::failure(1, format!("conU smoke failed\n\n{error}")),
    }
}

fn run_local_smoke(home_override: Option<PathBuf>) -> Result<LocalSmokeReport, String> {
    let smoke_home = SmokeHome::create(home_override)?;
    let home = smoke_home.path.clone();
    let init = state::init_state(Some(home.clone()))
        .map_err(|error| format!("initialize temp state: {error}"))?;
    security::ensure_security_state_from_paths(&init.paths)
        .map_err(|error| format!("initialize temp security: {error}"))?;

    submit_smoke_agent(&home, LOCAL_SMOKE_FROM_AGENT, "Alpha")?;
    submit_smoke_agent(&home, LOCAL_SMOKE_TO_AGENT, "Beta")?;
    let gateway = agents::process_gateway_requests(Some(home.clone()))
        .map_err(|error| format!("process temp agent gateway: {error}"))?;
    if gateway.registered_agents.len() != 2 {
        return Err("local smoke did not register both temp agents".to_string());
    }

    let message = LocalMessage::new(
        LOCAL_SMOKE_FROM_AGENT,
        LOCAL_SMOKE_TO_AGENT,
        OpaquePayload::from_bytes(LOCAL_SMOKE_PAYLOAD.to_vec()),
    )
    .map_err(|error| format!("build temp local message: {error}"))?;
    let submission = messages::submit_local_message(Some(home.clone()), message)
        .map_err(|error| format!("submit temp local message: {error}"))?;
    let processed = messages::process_message_requests(Some(home.clone()))
        .map_err(|error| format!("process temp local message: {error}"))?;
    let inbox = messages::list_agent_inbox(Some(home.clone()), LOCAL_SMOKE_TO_AGENT)
        .map_err(|error| format!("read temp inbox metadata: {error}"))?;
    let receipts = messages::list_receipts(Some(home))
        .map_err(|error| format!("read temp receipt metadata: {error}"))?;

    let delivered = inbox.iter().find(|entry| {
        entry.from_agent_id == LOCAL_SMOKE_FROM_AGENT
            && entry.to_agent_id == LOCAL_SMOKE_TO_AGENT
            && entry.payload_bytes == LOCAL_SMOKE_PAYLOAD.len()
    });
    let Some(delivered) = delivered else {
        return Err("local smoke did not find delivered inbox metadata".to_string());
    };
    if processed.delivered != 1 || receipts.len() != 1 {
        return Err("local smoke delivery metadata was incomplete".to_string());
    }

    Ok(LocalSmokeReport {
        registered_agents: gateway.registered_agents.len(),
        delivered_messages: processed.delivered,
        inbox_entries: inbox.len(),
        receipts: receipts.len(),
        payload_bytes: submission.payload_bytes,
        request_id: submission.request_id,
        envelope_id: delivered.envelope_id.clone(),
    })
}

fn submit_smoke_agent(home: &Path, agent_id: &str, display_name: &str) -> Result<(), String> {
    let registration = AgentRegistration::new(agent_id, display_name, "smoke-agent")
        .map_err(|error| format!("build temp agent metadata: {error}"))?;
    agents::submit_registration(Some(home.to_path_buf()), registration)
        .map(|_| ())
        .map_err(|error| format!("submit temp agent metadata: {error}"))
}

fn render_local_smoke_json(report: &LocalSmokeReport) -> String {
    format!(
        r#"{{
  "status": "passed",
  "mode": "local",
  "registeredAgents": {},
  "deliveredMessages": {},
  "inboxEntries": {},
  "receipts": {},
  "payloadBytes": {},
  "requestId": "{}",
  "envelopeId": "{}",
  "tempStatePersisted": false,
  "contentsDisplayed": false
}}"#,
        report.registered_agents,
        report.delivered_messages,
        report.inbox_entries,
        report.receipts,
        report.payload_bytes,
        json_escape(&report.request_id),
        json_escape(&report.envelope_id)
    )
}

fn render_local_smoke_text(report: &LocalSmokeReport) -> String {
    format!(
        r"conU smoke local

status: passed
mode: temp local state
agents registered: {}
messages delivered: {}
inbox entries: {}
receipts: {}
request: {}
envelope: {}
bytes: {}

next
  conu agents register <agent-id> <display-name> --messages true
  echo <payload> | conu send <from-agent> <to-agent> --stdin
  conu send <from-agent> <to-agent> --file ./message.bin --json
  conu wait <to-agent> --process-ipc --timeout-ms 30000 --json

privacy
  temp state    removed after smoke
  payload view  contents are not displayed by conU
  contentsDisplayed=false",
        report.registered_agents,
        report.delivered_messages,
        report.inbox_entries,
        report.receipts,
        report.request_id,
        report.envelope_id,
        report.payload_bytes
    )
}

fn render_smoke_usage() -> String {
    "usage: conu smoke [local] [--json]".to_string()
}

fn render_setup(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    match args.first().map(String::as_str) {
        Some("local") => render_setup_local(&args[1..], home_override),
        Some("--help") | Some("-h") | Some("help") => CliOutput::success(render_setup_usage()),
        Some(value) if value.starts_with("--") => render_setup_local(args, home_override),
        None => render_setup_local(args, home_override),
        Some(_) => CliOutput::failure(2, render_setup_usage()),
    }
}

fn render_setup_local(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if args
        .iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "help")
    {
        return CliOutput::success(render_setup_usage());
    }

    let options = match parse_setup_local_args(args) {
        Ok(options) => options,
        Err(error) => return error,
    };

    match run_local_setup(home_override.clone(), &options) {
        Ok(mut report) => {
            if options.start_runtime {
                match start_conud_runtime(home_override) {
                    Ok(runtime) => report.runtime = Some(runtime),
                    Err(error) => {
                        return CliOutput::failure(1, format!("conU setup failed\n\n{error}"));
                    }
                }
            }
            if options.json {
                CliOutput::success(render_local_setup_json(&report))
            } else {
                CliOutput::success(render_local_setup_text(&report))
            }
        }
        Err(error) => CliOutput::failure(1, format!("conU setup failed\n\n{error}")),
    }
}

fn parse_setup_local_args(args: &[String]) -> Result<LocalSetupOptions, CliOutput> {
    let mut options = LocalSetupOptions::default();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                options.json = true;
                index += 1;
            }
            "--start" => {
                options.start_runtime = true;
                index += 1;
            }
            "--from" => {
                options.from_agent_id = parse_setup_option_value(args, index, "--from")?;
                index += 2;
            }
            "--to" => {
                options.to_agent_id = parse_setup_option_value(args, index, "--to")?;
                index += 2;
            }
            "--from-name" => {
                options.from_display_name = parse_setup_option_value(args, index, "--from-name")?;
                options.from_display_name_explicit = true;
                index += 2;
            }
            "--to-name" => {
                options.to_display_name = parse_setup_option_value(args, index, "--to-name")?;
                options.to_display_name_explicit = true;
                index += 2;
            }
            "--from-kind" => {
                options.from_agent_kind = parse_setup_option_value(args, index, "--from-kind")?;
                options.from_agent_kind_explicit = true;
                index += 2;
            }
            "--to-kind" => {
                options.to_agent_kind = parse_setup_option_value(args, index, "--to-kind")?;
                options.to_agent_kind_explicit = true;
                index += 2;
            }
            "--room" => {
                options.room_id = parse_setup_option_value(args, index, "--room")?;
                index += 2;
            }
            "--room-name" => {
                options.room_display_name = parse_setup_option_value(args, index, "--room-name")?;
                options.room_display_name_explicit = true;
                index += 2;
            }
            value if value.starts_with("--") => {
                return Err(unknown_option_error());
            }
            _ => {
                return Err(CliOutput::failure(2, render_setup_usage()));
            }
        }
    }

    if options.from_agent_id == options.to_agent_id {
        return Err(CliOutput::failure(
            2,
            format!(
                "--from and --to must be different\n\n{}",
                render_setup_usage()
            ),
        ));
    }
    if options.from_agent_id != LOCAL_SETUP_FROM_AGENT && !options.from_display_name_explicit {
        options.from_display_name = options.from_agent_id.clone();
    }
    if options.to_agent_id != LOCAL_SETUP_TO_AGENT && !options.to_display_name_explicit {
        options.to_display_name = options.to_agent_id.clone();
    }
    if options.room_id != LOCAL_SETUP_ROOM && !options.room_display_name_explicit {
        options.room_display_name = options.room_id.clone();
    }

    Ok(options)
}

fn parse_setup_option_value(
    args: &[String],
    index: usize,
    option: &'static str,
) -> Result<String, CliOutput> {
    let Some(value) = args.get(index + 1) else {
        return Err(CliOutput::failure(2, render_setup_usage()));
    };
    if value.starts_with("--") || value.trim().is_empty() {
        return Err(CliOutput::failure(
            2,
            format!("{option} expects a value\n\n{}", render_setup_usage()),
        ));
    }
    Ok(value.clone())
}

fn run_local_setup(
    home_override: Option<PathBuf>,
    options: &LocalSetupOptions,
) -> Result<LocalSetupReport, String> {
    let init = state::init_state(home_override.clone())
        .map_err(|error| format!("initialize local state: {error}"))?;
    security::ensure_security_state_from_paths(&init.paths)
        .map_err(|error| format!("initialize local security: {error}"))?;
    let home = init.paths.home.clone();

    let existing_agents = agents::list_local_agents(Some(home.clone()))
        .map_err(|error| format!("read existing local agents: {error}"))?;
    let from_display_name = setup_agent_display_name(
        &existing_agents,
        &options.from_agent_id,
        &options.from_display_name,
        options.from_display_name_explicit,
    );
    let to_display_name = setup_agent_display_name(
        &existing_agents,
        &options.to_agent_id,
        &options.to_display_name,
        options.to_display_name_explicit,
    );
    let from_agent_kind = setup_agent_kind(
        &existing_agents,
        &options.from_agent_id,
        &options.from_agent_kind,
        options.from_agent_kind_explicit,
    );
    let to_agent_kind = setup_agent_kind(
        &existing_agents,
        &options.to_agent_id,
        &options.to_agent_kind,
        options.to_agent_kind_explicit,
    );

    submit_setup_agent(
        &home,
        &options.from_agent_id,
        &from_display_name,
        &from_agent_kind,
    )?;
    submit_setup_agent(
        &home,
        &options.to_agent_id,
        &to_display_name,
        &to_agent_kind,
    )?;
    let gateway = agents::process_gateway_requests(Some(home.clone()))
        .map_err(|error| format!("process local agent gateway: {error}"))?;

    let local_agents = agents::list_local_agents(Some(home.clone()))
        .map_err(|error| format!("read local agents: {error}"))?;
    for agent_id in [&options.from_agent_id, &options.to_agent_id] {
        if !local_agents.iter().any(|agent| {
            agent.agent_id.as_str() == agent_id.as_str()
                && agent.capabilities.messages
                && agent.capabilities.streams
                && agent.capabilities.rooms
        }) {
            return Err(format!(
                "{agent_id} is not ready for messages, streams, and rooms"
            ));
        }
    }

    let (stream, stream_created) = setup_local_stream(&home, options)?;
    let (room, room_created, to_agent_joined_room) = setup_local_room(&home, options)?;

    let message = LocalMessage::new(
        &options.from_agent_id,
        &options.to_agent_id,
        OpaquePayload::from_bytes(LOCAL_SETUP_PAYLOAD.to_vec()),
    )
    .map_err(|error| format!("build local setup message: {error}"))?;
    let submission = messages::submit_local_message(Some(home.clone()), message)
        .map_err(|error| format!("submit local setup message: {error}"))?;
    let processed = messages::process_message_requests(Some(home.clone()))
        .map_err(|error| format!("process local setup message: {error}"))?;
    if processed.delivered == 0 {
        return Err("local setup message was not delivered".to_string());
    }

    let inbox = messages::list_agent_inbox(Some(home.clone()), &options.to_agent_id)
        .map_err(|error| format!("read setup inbox metadata: {error}"))?;
    let delivered = processed.envelope_ids.iter().rev().find_map(|envelope_id| {
        inbox.iter().find(|entry| {
            entry.envelope_id.as_str() == envelope_id.as_str()
                && entry.from_agent_id.as_str() == options.from_agent_id.as_str()
                && entry.to_agent_id.as_str() == options.to_agent_id.as_str()
                && entry.payload_bytes == LOCAL_SETUP_PAYLOAD.len()
        })
    });
    let Some(delivered) = delivered else {
        return Err("local setup did not find delivered inbox metadata".to_string());
    };

    let receipts = messages::list_receipts(Some(home.clone()))
        .map_err(|error| format!("read local receipt metadata: {error}"))?;
    let receipt_count = receipts
        .iter()
        .filter(|receipt| receipt.envelope_id == delivered.envelope_id)
        .count();
    if receipt_count == 0 {
        return Err("local setup did not write a delivery receipt".to_string());
    }

    Ok(LocalSetupReport {
        state_path: home,
        node_id: init.node.node_id,
        node_created: init.node_created,
        from_agent_id: options.from_agent_id.clone(),
        to_agent_id: options.to_agent_id.clone(),
        from_agent_kind,
        to_agent_kind,
        registered_agents: gateway.registered_agents.len(),
        local_agents: local_agents.len(),
        stream_id: stream.stream_id,
        stream_created,
        room_id: room.room_id,
        room_created,
        room_participants: room.participants.len(),
        to_agent_joined_room,
        inbox_entries: inbox.len(),
        receipts: receipt_count,
        payload_bytes: submission.payload_bytes,
        request_id: submission.request_id,
        envelope_id: delivered.envelope_id.clone(),
        runtime: None,
    })
}

fn run_agent_prepare(
    home_override: Option<PathBuf>,
    options: &AgentPrepareArgs,
) -> Result<AgentPrepareReport, String> {
    let init = state::init_state(home_override)
        .map_err(|error| format!("initialize local state: {error}"))?;
    security::ensure_security_state_from_paths(&init.paths)
        .map_err(|error| format!("initialize local security: {error}"))?;
    let home = init.paths.home.clone();

    let mut registration =
        AgentRegistration::new(&options.agent_id, &options.display_name, &options.kind)
            .map_err(|error| format!("build agent metadata: {error}"))?;
    registration.capabilities = options.capabilities.clone();
    let registration_submission = agents::submit_registration(Some(home.clone()), registration)
        .map_err(|error| format!("submit agent metadata: {error}"))?;
    let registration_gateway = agents::process_gateway_requests(Some(home.clone()))
        .map_err(|error| format!("process agent metadata: {error}"))?;

    let mut processed_agents = registration_gateway.processed;
    let mut rejected_agents = registration_gateway.rejected;
    let registered_agents = registration_gateway.registered_agents.len();

    let registered = agents::list_local_agents(Some(home.clone()))
        .map_err(|error| format!("read local agents: {error}"))?
        .into_iter()
        .find(|agent| agent.agent_id == options.agent_id)
        .ok_or_else(|| format!("{} was not registered locally", options.agent_id))?;
    if registered.capabilities != options.capabilities {
        return Err(format!(
            "{} capabilities were not applied by the local gateway",
            options.agent_id
        ));
    }

    let mut presence_request_id = None;
    let mut heartbeat_updated = false;
    if options.capabilities.presence {
        let heartbeat = PresenceHeartbeat::new(&options.agent_id, options.presence)
            .map_err(|error| format!("build agent presence: {error}"))?;
        let presence_submission = agents::submit_presence_heartbeat(Some(home.clone()), heartbeat)
            .map_err(|error| format!("submit agent presence: {error}"))?;
        presence_request_id = Some(presence_submission.request_id);
        let presence_gateway = agents::process_gateway_requests(Some(home.clone()))
            .map_err(|error| format!("process agent presence: {error}"))?;
        heartbeat_updated = presence_gateway
            .heartbeat_agents
            .iter()
            .any(|agent_id| agent_id == &options.agent_id);
        processed_agents += presence_gateway.processed;
        rejected_agents += presence_gateway.rejected;
    }

    let prepared_agent = agents::list_local_agents(Some(home.clone()))
        .map_err(|error| format!("read prepared agent: {error}"))?
        .into_iter()
        .find(|agent| agent.agent_id == options.agent_id)
        .ok_or_else(|| format!("{} was not available after preparation", options.agent_id))?;
    if options.capabilities.presence && prepared_agent.presence != options.presence {
        return Err(format!(
            "{} presence was not updated to {}",
            options.agent_id,
            options.presence.as_str()
        ));
    }
    if options.capabilities.presence && prepared_agent.presence == options.presence {
        heartbeat_updated = true;
    }

    let (stream, stream_created) = if let Some(to_agent_id) = options.connect_to_agent_id.as_deref()
    {
        let (stream, created) =
            prepare_agent_stream(&home, &options.agent_id, to_agent_id, &options.stream_kind)?;
        (Some(stream), created)
    } else {
        (None, false)
    };

    let (room, room_created, agent_joined_room) = if let Some(room_id) = options.room_id.as_deref()
    {
        let display_name = options.room_display_name.as_deref().unwrap_or(room_id);
        let (room, created, joined) =
            prepare_agent_room(&home, &options.agent_id, room_id, display_name)?;
        (Some(room), created, joined)
    } else {
        (None, false, false)
    };

    Ok(AgentPrepareReport {
        state_path: home,
        node_id: init.node.node_id,
        node_created: init.node_created,
        agent_id: options.agent_id.clone(),
        display_name: prepared_agent.display_name,
        kind: prepared_agent.kind,
        capabilities: prepared_agent.capabilities,
        presence: options
            .capabilities
            .presence
            .then_some(prepared_agent.presence),
        registration_request_id: registration_submission.request_id,
        presence_request_id,
        processed_agents,
        rejected_agents,
        registered_agents,
        heartbeat_updated,
        stream,
        stream_created,
        room,
        room_created,
        agent_joined_room,
    })
}

fn submit_setup_agent(
    home: &Path,
    agent_id: &str,
    display_name: &str,
    kind: &str,
) -> Result<(), String> {
    let mut registration = AgentRegistration::new(agent_id, display_name, kind)
        .map_err(|error| format!("build setup agent metadata: {error}"))?;
    registration.capabilities = setup_agent_capabilities();
    agents::submit_registration(Some(home.to_path_buf()), registration)
        .map(|_| ())
        .map_err(|error| format!("submit setup agent metadata: {error}"))
}

fn setup_agent_display_name(
    existing_agents: &[LocalAgentRecord],
    agent_id: &str,
    default_display_name: &str,
    explicit: bool,
) -> String {
    if explicit {
        return default_display_name.to_string();
    }

    existing_agents
        .iter()
        .find(|agent| agent.agent_id == agent_id)
        .map(|agent| agent.display_name.clone())
        .unwrap_or_else(|| default_display_name.to_string())
}

fn setup_agent_kind(
    existing_agents: &[LocalAgentRecord],
    agent_id: &str,
    default_kind: &str,
    explicit: bool,
) -> String {
    if explicit {
        return default_kind.to_string();
    }

    existing_agents
        .iter()
        .find(|agent| agent.agent_id == agent_id)
        .map(|agent| agent.kind.clone())
        .unwrap_or_else(|| default_kind.to_string())
}

fn setup_agent_capabilities() -> AgentCapabilities {
    let mut capabilities = AgentCapabilities::basic();
    capabilities.messages = true;
    capabilities.streams = true;
    capabilities.rooms = true;
    capabilities.files = false;
    capabilities.presence = true;
    capabilities
}

fn setup_local_stream(
    home: &Path,
    options: &LocalSetupOptions,
) -> Result<(StreamRecord, bool), String> {
    let existing = streams::list_streams(Some(home.to_path_buf()))
        .map_err(|error| format!("read local stream metadata: {error}"))?
        .into_iter()
        .find(|stream| {
            stream.from_agent_id.as_str() == options.from_agent_id.as_str()
                && stream.to_agent_id.as_str() == options.to_agent_id.as_str()
                && stream.kind == "message"
                && stream.state.as_str() == "open"
        });
    if let Some(stream) = existing {
        return Ok((stream, false));
    }

    streams::open_stream(
        Some(home.to_path_buf()),
        &options.from_agent_id,
        &options.to_agent_id,
        "message",
    )
    .map(|report| (report.stream, true))
    .map_err(|error| format!("open local setup stream: {error}"))
}

fn setup_local_room(
    home: &Path,
    options: &LocalSetupOptions,
) -> Result<(RoomRecord, bool, bool), String> {
    let existing = rooms::list_rooms(Some(home.to_path_buf()))
        .map_err(|error| format!("read local room metadata: {error}"))?
        .into_iter()
        .find(|room| room.room_id.as_str() == options.room_id.as_str());

    let (room, created) = if let Some(room) = existing {
        (room, false)
    } else {
        let report = rooms::create_room(
            Some(home.to_path_buf()),
            &options.room_id,
            &options.room_display_name,
            &options.from_agent_id,
        )
        .map_err(|error| format!("create local setup room: {error}"))?;
        (report.room, true)
    };

    let from_agent_present = room
        .participants
        .iter()
        .any(|participant| participant.agent_id.as_str() == options.from_agent_id.as_str());
    if !from_agent_present {
        rooms::join_room(
            Some(home.to_path_buf()),
            &options.room_id,
            &options.from_agent_id,
        )
        .map_err(|error| format!("join from agent to local setup room: {error}"))?;
    }

    let joined = rooms::join_room(
        Some(home.to_path_buf()),
        &options.room_id,
        &options.to_agent_id,
    )
    .map_err(|error| format!("join to agent to local setup room: {error}"))?;
    Ok((joined.room, created, joined.joined))
}

fn prepare_agent_stream(
    home: &Path,
    from_agent_id: &str,
    to_agent_id: &str,
    kind: &str,
) -> Result<(StreamRecord, bool), String> {
    let existing = streams::list_streams(Some(home.to_path_buf()))
        .map_err(|error| format!("read local stream metadata: {error}"))?
        .into_iter()
        .find(|stream| {
            stream.from_agent_id == from_agent_id
                && stream.to_agent_id == to_agent_id
                && stream.kind == kind
                && stream.state.as_str() == "open"
        });
    if let Some(stream) = existing {
        return Ok((stream, false));
    }

    streams::open_stream(Some(home.to_path_buf()), from_agent_id, to_agent_id, kind)
        .map(|report| (report.stream, true))
        .map_err(|error| format!("open prepared agent stream: {error}"))
}

fn prepare_agent_room(
    home: &Path,
    agent_id: &str,
    room_id: &str,
    display_name: &str,
) -> Result<(RoomRecord, bool, bool), String> {
    let existing = rooms::list_rooms(Some(home.to_path_buf()))
        .map_err(|error| format!("read local room metadata: {error}"))?
        .into_iter()
        .find(|room| room.room_id == room_id);

    let (room, created) = if let Some(room) = existing {
        (room, false)
    } else {
        let report = rooms::create_room(Some(home.to_path_buf()), room_id, display_name, agent_id)
            .map_err(|error| format!("create prepared agent room: {error}"))?;
        (report.room, true)
    };

    if room
        .participants
        .iter()
        .any(|participant| participant.agent_id == agent_id)
    {
        return Ok((room, created, false));
    }

    let joined = rooms::join_room(Some(home.to_path_buf()), room_id, agent_id)
        .map_err(|error| format!("join prepared agent room: {error}"))?;
    Ok((joined.room, created, joined.joined))
}

fn render_agent_prepare_json(report: &AgentPrepareReport) -> String {
    format!(
        r#"{{
  "status": "ready",
  "statePath": "{}",
  "nodeId": "{}",
  "nodeCreated": {},
  "agent": {{
    "agentId": "{}",
    "displayName": "{}",
    "kind": "{}",
    "presence": {},
    "capabilities": {{
      "messages": {},
      "streams": {},
      "rooms": {},
      "files": {},
      "presence": {}
    }}
  }},
  "gateway": {{
    "registrationRequestId": "{}",
    "presenceRequestId": {},
    "processed": {},
    "rejected": {},
    "registeredAgents": {},
    "heartbeatUpdated": {}
  }},
  "stream": {},
  "room": {},
  "contentsDisplayed": false
}}"#,
        json_escape(&report.state_path.display().to_string()),
        json_escape(&report.node_id),
        report.node_created,
        json_escape(&report.agent_id),
        json_escape(&report.display_name),
        json_escape(&report.kind),
        agent_prepare_presence_json(report.presence),
        report.capabilities.messages,
        report.capabilities.streams,
        report.capabilities.rooms,
        report.capabilities.files,
        report.capabilities.presence,
        json_escape(&report.registration_request_id),
        optional_json_string(report.presence_request_id.as_deref()),
        report.processed_agents,
        report.rejected_agents,
        report.registered_agents,
        report.heartbeat_updated,
        agent_prepare_stream_json(report.stream.as_ref(), report.stream_created),
        agent_prepare_room_json(
            report.room.as_ref(),
            report.room_created,
            report.agent_joined_room
        )
    )
}

fn agent_prepare_presence_json(presence: Option<AgentPresence>) -> String {
    presence
        .map(|presence| json_string(presence.as_str()))
        .unwrap_or_else(|| "null".to_string())
}

fn agent_prepare_stream_json(stream: Option<&StreamRecord>, created: bool) -> String {
    match stream {
        Some(stream) => format!(
            r#"{{
    "streamId": "{}",
    "fromAgentId": "{}",
    "toAgentId": "{}",
    "kind": "{}",
    "state": "{}",
    "route": "{}",
    "created": {},
    "contentsDisplayed": false
  }}"#,
            json_escape(&stream.stream_id),
            json_escape(&stream.from_agent_id),
            json_escape(&stream.to_agent_id),
            json_escape(&stream.kind),
            stream.state.as_str(),
            json_escape(&stream.route),
            created
        ),
        None => "null".to_string(),
    }
}

fn agent_prepare_room_json(room: Option<&RoomRecord>, created: bool, agent_joined: bool) -> String {
    match room {
        Some(room) => format!(
            r#"{{
    "roomId": "{}",
    "displayName": "{}",
    "state": "{}",
    "createdByAgentId": "{}",
    "participants": {},
    "created": {},
    "agentJoined": {},
    "contentsDisplayed": false
  }}"#,
            json_escape(&room.room_id),
            json_escape(&room.display_name),
            room.state.as_str(),
            json_escape(&room.created_by_agent_id),
            room.participants.len(),
            created,
            agent_joined
        ),
        None => "null".to_string(),
    }
}

fn render_agent_prepare_text(report: &AgentPrepareReport) -> String {
    let presence = report
        .presence
        .map(|presence| presence.as_str())
        .unwrap_or("disabled");
    let presence_request = report
        .presence_request_id
        .as_deref()
        .unwrap_or("not submitted");
    let stream = match report.stream.as_ref() {
        Some(stream) => format!(
            "{} ({}; {} -> {}; kind {}; route {})",
            stream.stream_id,
            created_or_reused(report.stream_created),
            stream.from_agent_id,
            stream.to_agent_id,
            stream.kind,
            stream.route
        ),
        None => "not requested".to_string(),
    };
    let room = match report.room.as_ref() {
        Some(room) => format!(
            "{} ({} participants; {})",
            room.room_id,
            room.participants.len(),
            room_prepare_state(report.room_created, report.agent_joined_room)
        ),
        None => "not requested".to_string(),
    };
    let next_steps = agent_prepare_next_steps(report);

    format!(
        r"conU agents prepare

status: ready
state: {}
node: {}
agent: {}
name: {}
kind: {}
capabilities: {}
presence: {}
registration request: {}
presence request: {}
gateway processed: {}
gateway rejected: {}
registered this run: {}
presence updated: {}
stream: {}
room: {}

next
{}

privacy
  payload view  contents are not displayed by conU
  contentsDisplayed=false",
        report.state_path.display(),
        report.node_id,
        report.agent_id,
        report.display_name,
        report.kind,
        capabilities_summary(&report.capabilities),
        presence,
        report.registration_request_id,
        presence_request,
        report.processed_agents,
        report.rejected_agents,
        report.registered_agents,
        report.heartbeat_updated,
        stream,
        room,
        next_steps
    )
}

fn created_or_reused(created: bool) -> &'static str {
    if created { "created" } else { "reused" }
}

fn room_prepare_state(created: bool, agent_joined: bool) -> &'static str {
    if created {
        "created"
    } else if agent_joined {
        "agent joined"
    } else {
        "reused"
    }
}

fn agent_prepare_next_steps(report: &AgentPrepareReport) -> String {
    let mut steps = Vec::new();
    steps.push(format!("conu agents export {} --json", report.agent_id));
    if let Some(stream) = report.stream.as_ref() {
        steps.push(format!("conu streams write {} --stdin", stream.stream_id));
    }
    if let Some(room) = report.room.as_ref() {
        steps.push(format!(
            "conu rooms publish {} {} <topic> --stdin",
            room.room_id, report.agent_id
        ));
    }
    steps.push("conu watch".to_string());

    steps
        .into_iter()
        .map(|step| format!("  {step}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_local_setup_json(report: &LocalSetupReport) -> String {
    format!(
        r#"{{
  "status": "ready",
  "mode": "local",
  "statePath": "{}",
  "nodeId": "{}",
  "nodeCreated": {},
  "agents": {{
    "from": "{}",
    "to": "{}",
    "fromKind": "{}",
    "toKind": "{}",
    "registeredThisRun": {},
    "localTotal": {}
  }},
  "stream": {{
    "streamId": "{}",
    "created": {}
  }},
  "room": {{
    "roomId": "{}",
    "created": {},
    "toAgentJoined": {},
    "participants": {}
  }},
  "delivery": {{
    "requestId": "{}",
    "envelopeId": "{}",
    "payloadBytes": {},
    "inboxEntries": {},
    "receipts": {}
  }},
  "runtime": {},
  "persistentState": true,
  "contentsDisplayed": false
}}"#,
        json_escape(&report.state_path.display().to_string()),
        json_escape(&report.node_id),
        report.node_created,
        json_escape(&report.from_agent_id),
        json_escape(&report.to_agent_id),
        json_escape(&report.from_agent_kind),
        json_escape(&report.to_agent_kind),
        report.registered_agents,
        report.local_agents,
        json_escape(&report.stream_id),
        report.stream_created,
        json_escape(&report.room_id),
        report.room_created,
        report.to_agent_joined_room,
        report.room_participants,
        json_escape(&report.request_id),
        json_escape(&report.envelope_id),
        report.payload_bytes,
        report.inbox_entries,
        report.receipts,
        render_local_setup_runtime_json(report.runtime.as_ref())
    )
}

fn render_local_setup_runtime_json(runtime: Option<&StartRuntimeReport>) -> String {
    let Some(runtime) = runtime else {
        return "null".to_string();
    };

    format!(
        r#"{{
    "requested": true,
    "status": "{}",
    "launched": {},
    "pid": {},
    "health": "{}"
  }}"#,
        runtime.status.state.as_str(),
        runtime.launched,
        json_u32(runtime.status.pid),
        json_escape(runtime_health_label(&runtime.status))
    )
}

fn render_local_setup_text(report: &LocalSetupReport) -> String {
    format!(
        r"conU setup local

status: ready
mode: reusable local state
state: {}
node: {}
agents: {} -> {}
registered this run: {}
local agents total: {}
agent kinds: {} -> {}
stream: {} ({})
room: {} ({} participants, {})
message: delivered
request: {}
envelope: {}
bytes: {}
receipts: {}
runtime: {}

next
  conu connect local {} {}
  conu chat
  conu send {} {} --file ./message.bin --json
  conu wait {} --process-ipc --timeout-ms 30000 --json
  conu inbox {}
  conu history {}
  conu rooms publish {} {} build --stdin
  conu watch

privacy
  state         persisted for local testing
  payload view  contents are not displayed by conU
  contentsDisplayed=false",
        report.state_path.display(),
        report.node_id,
        report.from_agent_id,
        report.to_agent_id,
        report.registered_agents,
        report.local_agents,
        report.from_agent_kind,
        report.to_agent_kind,
        report.stream_id,
        if report.stream_created {
            "created"
        } else {
            "reused"
        },
        report.room_id,
        report.room_participants,
        if report.room_created {
            "created"
        } else if report.to_agent_joined_room {
            "to agent joined"
        } else {
            "reused"
        },
        report.request_id,
        report.envelope_id,
        report.payload_bytes,
        report.receipts,
        local_setup_runtime_label(report.runtime.as_ref()),
        report.from_agent_id,
        report.to_agent_id,
        report.from_agent_id,
        report.to_agent_id,
        report.to_agent_id,
        report.to_agent_id,
        report.to_agent_id,
        report.room_id,
        report.from_agent_id
    )
}

fn local_setup_runtime_label(runtime: Option<&StartRuntimeReport>) -> String {
    runtime
        .map(|runtime| {
            format!(
                "{} ({}, pid {})",
                runtime_state_label(&runtime.status),
                if runtime.launched {
                    "launched"
                } else {
                    "already running"
                },
                runtime_pid_label(&runtime.status)
            )
        })
        .unwrap_or_else(|| "not started; run conu setup --start or conu start".to_string())
}

fn render_setup_usage() -> String {
    r"usage:
  conu setup [local] [--start] [--from <agent-id>] [--to <agent-id>] [--from-name <display-name>] [--to-name <display-name>] [--from-kind <kind>] [--to-kind <kind>] [--room <room-id>] [--room-name <display-name>] [--json]

defaults:
  from agent  agent.alpha (local-agent)
  to agent    agent.beta (local-agent)
  room        room.dev

privacy:
  setup verifies delivery with opaque bytes only
  payload contents are never displayed
  contentsDisplayed=false"
        .to_string()
}

fn doctor_status(
    snapshot: &StateSnapshot,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> &'static str {
    if !snapshot.is_initialized() {
        "needs_init"
    } else if !log_scan.payload_safe {
        "privacy_attention"
    } else if !security_controls_ready(security) {
        "needs_security_audit"
    } else if !all_required_binaries_present(binaries) {
        "missing_binaries"
    } else {
        "ready_for_local_use"
    }
}

fn local_install_ready(
    snapshot: &StateSnapshot,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> bool {
    snapshot.is_initialized()
        && security_controls_ready(security)
        && all_required_binaries_present(binaries)
        && log_scan.payload_safe
}

fn controlled_relay_ready(
    snapshot: &StateSnapshot,
    security: &SecurityAudit,
    binaries: &[DoctorBinary],
    log_scan: &DoctorLogScan,
) -> bool {
    snapshot.is_initialized()
        && security_controls_ready(security)
        && doctor_binary_present(binaries, "conu")
        && doctor_binary_present(binaries, "conud")
        && doctor_binary_present(binaries, "conu-relay")
        && log_scan.payload_safe
}

fn security_controls_ready(security: &SecurityAudit) -> bool {
    security.initialized
        && security.local_payload_encryption
        && security.signed_agent_cards
        && security.peer_key_exchange
        && security.replay_cache
        && security.key_rotation_plan
}

fn all_required_binaries_present(binaries: &[DoctorBinary]) -> bool {
    ["conu", "conud", "conu-relay", "conu-mcp"]
        .iter()
        .all(|name| doctor_binary_present(binaries, name))
}

fn release_binaries() -> Vec<DoctorBinary> {
    vec![
        DoctorBinary {
            name: "conu",
            path: env::current_exe().ok(),
        },
        DoctorBinary {
            name: "conud",
            path: resolve_companion_executable("conud", "CONUD_EXE"),
        },
        DoctorBinary {
            name: "conu-relay",
            path: resolve_companion_executable("conu-relay", "CONU_RELAY_EXE"),
        },
        DoctorBinary {
            name: "conu-mcp",
            path: resolve_companion_executable("conu-mcp", "CONU_MCP_EXE"),
        },
    ]
}

fn doctor_binary_present(binaries: &[DoctorBinary], name: &str) -> bool {
    binaries
        .iter()
        .any(|binary| binary.name == name && binary.path.is_some())
}

fn doctor_binary_json(binaries: &[DoctorBinary], name: &str) -> String {
    binaries
        .iter()
        .find(|binary| binary.name == name)
        .and_then(|binary| binary.path.as_ref())
        .map(|path| json_string(&path.display().to_string()))
        .unwrap_or_else(|| "null".to_string())
}

fn doctor_binaries_text(binaries: &[DoctorBinary]) -> String {
    binaries
        .iter()
        .map(|binary| {
            let path = binary
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "not found".to_string());
            format!("  {:<11} {}", binary.name, path)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn resolve_companion_executable(binary_name: &str, env_var: &str) -> Option<PathBuf> {
    if let Ok(value) = env::var(env_var) {
        let path = PathBuf::from(value);
        if path.exists() {
            return Some(path);
        }
    }

    let executable_name = format!("{binary_name}{}", env::consts::EXE_SUFFIX);
    if let Ok(mut path) = env::current_exe() {
        path.set_file_name(&executable_name);
        if path.exists() {
            return Some(path);
        }
    }

    let path_value = env::var_os("PATH")?;
    for directory in env::split_paths(&path_value) {
        let candidate = directory.join(&executable_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn scan_payload_safe_logs(snapshot: &StateSnapshot) -> DoctorLogScan {
    let log_dir = &snapshot.paths.logs_dir;
    if !log_dir.exists() {
        return DoctorLogScan {
            payload_safe: true,
            scanned_files: 0,
            issues: 0,
        };
    }

    let mut scanned_files = 0;
    let mut issues = 0;
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_log_or_archive(&path) {
                continue;
            }
            scanned_files += 1;
            let Ok(contents) = read_doctor_log_contents(&path) else {
                issues += 1;
                continue;
            };
            if FORBIDDEN_LOG_TERMS
                .iter()
                .any(|term| contents.contains(term))
            {
                issues += 1;
            }
        }
    }

    DoctorLogScan {
        payload_safe: issues == 0,
        scanned_files,
        issues,
    }
}

fn is_log_or_archive(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    name.ends_with(".log")
        || name.split_once(".log.").is_some_and(|(_, suffix)| {
            !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
        })
}

fn read_doctor_log_contents(path: &Path) -> Result<String, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    let file_type = metadata.file_type();
    let invalid_metadata = file_type.is_symlink()
        || !file_type.is_file()
        || metadata.len() > MAX_DOCTOR_LOG_SCAN_BYTES;
    if invalid_metadata {
        return Err(());
    }

    let mut file = fs::File::open(path).map_err(|_| ())?;
    let path_metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    let path_file_type = path_metadata.file_type();
    if path_file_type.is_symlink()
        || !path_file_type.is_file()
        || !update_input_file_metadata_matches(&metadata, &path_metadata)
    {
        return Err(());
    }

    let opened_metadata = file.metadata().map_err(|_| ())?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_DOCTOR_LOG_SCAN_BYTES
        || !update_input_file_metadata_matches(&metadata, &opened_metadata)
    {
        return Err(());
    }

    let mut contents = String::new();
    let limit = MAX_DOCTOR_LOG_SCAN_BYTES.saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_string(&mut contents)
        .map_err(|_| ())?;
    if contents.len() as u64 > MAX_DOCTOR_LOG_SCAN_BYTES {
        return Err(());
    }
    Ok(contents)
}

const FORBIDDEN_LOG_TERMS: &[&str] = &[
    "private message contents",
    "Review this code",
    "payload_text",
    "payload_hex",
    "secret_key_hex",
];
const MAX_DOCTOR_LOG_SCAN_BYTES: u64 = 1024 * 1024;
const RUNTIME_START_POLL_ATTEMPTS: usize = 30;
const RUNTIME_START_READ_RETRY_ATTEMPTS: usize = 5;
const RUNTIME_START_READ_RETRY_DELAY: Duration = Duration::from_millis(25);

fn render_start(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu start [--json]");
    }
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    match start_conud_runtime(home_override) {
        Ok(report) => CliOutput::success(render_start_report(&report, json)),
        Err(error) => CliOutput::failure(1, format!("conU start failed\n\n{error}")),
    }
}

fn start_conud_runtime(home_override: Option<PathBuf>) -> Result<StartRuntimeReport, String> {
    let current = read_runtime_for_start(home_override.clone())?;
    if current.is_live() {
        return Ok(StartRuntimeReport {
            status: current,
            launched: false,
        });
    }

    let daemon = resolve_conud_executable();
    let child = match spawn_conud_daemon(&daemon, home_override.as_ref()) {
        Ok(child) => child,
        Err(error) => {
            return Err(format!(
                "could not launch conUD at {}: {error}\nset CONUD_EXE to the conud binary path if it is not beside conu",
                daemon.display()
            ));
        }
    };

    for _ in 0..RUNTIME_START_POLL_ATTEMPTS {
        thread::sleep(Duration::from_millis(100));
        match read_runtime_for_start(home_override.clone()) {
            Ok(status) if status.is_live() => {
                return Ok(StartRuntimeReport {
                    status,
                    launched: true,
                });
            }
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }

    Err(format!(
        "launched pid {} but no fresh conUD heartbeat was detected",
        child.id()
    ))
}

fn read_runtime_for_start(home_override: Option<PathBuf>) -> Result<RuntimeStatus, String> {
    let mut last_error = None;
    for attempt in 0..RUNTIME_START_READ_RETRY_ATTEMPTS {
        match runtime::read_runtime(home_override.clone()) {
            Ok(status) => return Ok(status),
            Err(error) => {
                let message = error.to_string();
                if runtime_start_read_error_is_retryable(&message)
                    && attempt + 1 < RUNTIME_START_READ_RETRY_ATTEMPTS
                {
                    last_error = Some(message);
                    thread::sleep(RUNTIME_START_READ_RETRY_DELAY);
                    continue;
                }
                return Err(message);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "runtime status could not be read".to_string()))
}

fn runtime_start_read_error_is_retryable(message: &str) -> bool {
    message.contains("runtime control path changed while reading")
        || message.contains("runtime control path changed while opening")
}

fn render_stop(args: &[String], home_override: Option<PathBuf>) -> CliOutput {
    if is_help_request(args) {
        return CliOutput::success("usage: conu stop [--json]");
    }
    let json = match json_flag(args) {
        Ok(json) => json,
        Err(error) => return error,
    };

    let report = match runtime::request_runtime_stop(home_override.clone()) {
        Ok(report) => report,
        Err(error) => return CliOutput::failure(1, format!("conU stop failed\n\n{error}")),
    };

    if report.requested {
        for _ in 0..30 {
            thread::sleep(Duration::from_millis(100));
            match runtime::read_runtime(home_override.clone()) {
                Ok(status) if !status.is_live() => {
                    return CliOutput::success(render_stop_report(
                        &StopReport {
                            requested: true,
                            status,
                        },
                        json,
                    ));
                }
                Ok(_) => {}
                Err(error) => return CliOutput::failure(1, format!("conU stop failed\n\n{error}")),
            }
        }
    }

    CliOutput::success(render_stop_report(&report, json))
}

fn render_init_report(report: &InitReport, security: &SecurityReport) -> String {
    let repaired =
        report.config_created || report.trust_store_created || report.agent_registry_created;
    let status = if report.node_created {
        "created"
    } else if repaired {
        "repaired"
    } else {
        "already initialized"
    };

    format!(
        r"conU init

status: {status}
node: {}
name: {}
state path: {}

files
  node identity  {}
  config         {}
  trust store    {}
  agent registry {}
  security keys  {}

next
  conu status
  conu security audit
  conu start",
        report.node.node_id,
        report.node.display_name,
        report.paths.home.display(),
        created_label(report.node_created),
        created_label(report.config_created),
        created_label(report.trust_store_created),
        created_label(report.agent_registry_created),
        created_label(
            security.identity_signing_key_created
                || security.identity_exchange_key_created
                || security.storage_key_created
        )
    )
}

struct StatusView<'a> {
    snapshot: &'a StateSnapshot,
    runtime_status: &'a RuntimeStatus,
    local_agents: &'a [LocalAgentRecord],
    remote_agents: &'a [RemoteAgentRecord],
    sessions: &'a [RemoteSession],
    stream_records: &'a [StreamRecord],
    room_records: &'a [RoomRecord],
    route_records: &'a [RouteRecord],
    peers: &'a [TrustedPeer],
    security: &'a SecurityAudit,
}

fn render_status_text(view: &StatusView<'_>) -> String {
    let snapshot = view.snapshot;
    let runtime_status = view.runtime_status;
    let security = view.security;
    let node = snapshot
        .node
        .as_ref()
        .map(|node| node.node_id.as_str())
        .unwrap_or("not initialized");
    let display_name = snapshot
        .node
        .as_ref()
        .map(|node| node.display_name.as_str())
        .unwrap_or("not initialized");

    format!(
        r"conU status

runtime
  conUD         {}
  pid           {}
  health        {}
  local IPC     file gateway active
  relay         daemon pump when configured; service via conu-relay
  routes        direct {} relay {} fallback {}

identity
  state         {}
  node          {}
  name          {}
  state path    {}
  config        {}
  trust store   {}
  security      {}

agents
  local         {} registered
  remote        {} visible
  registry      {}
  trusted peers {}
  sessions      {}
  streams       {}
  rooms         {}
  routes        {} selected

privacy
  local storage encrypted at rest: {}
  agent cards   signed: {}
  replay guard  active: {}
  secret store  {} os_protected={}
  payload view  contents are not displayed by conU",
        runtime_state_label(runtime_status),
        runtime_pid_label(runtime_status),
        runtime_health_label(runtime_status),
        selected_direct_route_count(view.route_records),
        selected_relay_route_count(view.route_records),
        relay_fallback_route_count(view.route_records),
        initialization_label(snapshot),
        node,
        display_name,
        snapshot.paths.home.display(),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        ready_label(security.initialized),
        view.local_agents.len(),
        view.remote_agents.len(),
        ready_label(snapshot.agent_registry_exists),
        trusted_peer_count(view.peers),
        view.sessions.len(),
        view.stream_records.len(),
        view.room_records.len(),
        selected_route_count(view.route_records),
        yes_no(security.local_payload_encryption),
        yes_no(security.signed_agent_cards),
        yes_no(security.replay_cache),
        security.secret_storage_backend,
        yes_no(security.secrets_os_protected)
    )
}

fn render_status_json(view: &StatusView<'_>) -> String {
    let snapshot = view.snapshot;
    let runtime_status = view.runtime_status;
    let security = view.security;
    let node = snapshot
        .node
        .as_ref()
        .map(|node| node.node_id.as_str())
        .unwrap_or("not_initialized");
    let display_name = snapshot
        .node
        .as_ref()
        .map(|node| node.display_name.as_str())
        .unwrap_or("not_initialized");

    format!(
        r#"{{
  "runtime": {{
    "conud": "{}",
    "pid": {},
    "heartbeatAgeSecs": {},
    "localHealth": "{}",
    "localIpc": "file_gateway",
    "relay": "daemon_pump_when_configured",
    "selectedDirectRoutes": {},
    "selectedRelayRoutes": {},
    "relayFallbacks": {}
  }},
  "identity": {{
    "state": "{}",
    "node": "{}",
    "displayName": "{}",
    "statePath": "{}",
    "config": "{}",
    "trustStore": "{}"
  }},
  "agents": {{
    "local": {},
    "remote": {},
    "registry": "{}",
    "trustedPeers": {},
    "sessions": {},
    "streams": {},
    "rooms": {},
    "routes": {}
  }},
  "security": {{
    "initialized": {},
    "localPayloadEncryption": {},
    "signedAgentCards": {},
    "peerKeyExchange": {},
    "replayCache": {},
    "keyRotationPlan": {},
    "secretStorageBackend": "{}",
    "secretsOsProtected": {}
  }},
  "privacy": {{
    "contentsDisplayed": false
  }}
}}"#,
        runtime_status.state.as_str(),
        json_u32(runtime_status.pid),
        json_u64(runtime_status.heartbeat_age_secs()),
        json_escape(runtime_health_label(runtime_status)),
        selected_direct_route_count(view.route_records),
        selected_relay_route_count(view.route_records),
        relay_fallback_route_count(view.route_records),
        initialization_label(snapshot),
        json_escape(node),
        json_escape(display_name),
        json_escape(&snapshot.paths.home.display().to_string()),
        ready_label(snapshot.config_exists),
        ready_label(snapshot.trust_store_exists),
        view.local_agents.len(),
        view.remote_agents.len(),
        ready_label(snapshot.agent_registry_exists),
        trusted_peer_count(view.peers),
        view.sessions.len(),
        view.stream_records.len(),
        view.room_records.len(),
        selected_route_count(view.route_records),
        security.initialized,
        security.local_payload_encryption,
        security.signed_agent_cards,
        security.peer_key_exchange,
        security.replay_cache,
        security.key_rotation_plan,
        json_escape(&security.secret_storage_backend),
        security.secrets_os_protected
    )
}

fn render_help() -> String {
    r"conu - private agent-to-agent communication

Usage:
  conu [command]

Start:
  conu                  open the Up/Down menu in a terminal
  conu setup --start    create two local agents and start conUD
  conu ready <id> <name> register one agent and mark it ready
  conu connect          choose an agent action
  conu chat             send one private local message

Messages:
  conu inbox [agent-id]
  conu next <agent-id> --json
  conu history <agent-id>
  conu wait <agent-id> --process-ipc --timeout-ms 30000 --json
  conu receive <agent-id> <envelope-id> --output <file>
  conu receive <agent-id> --latest --output <file> --process-ipc
  conu pull <agent-id> --dir ./agent-inbox --process-ipc

Runtime:
  conu dashboard
  conu status
  conu agents
  conu watch
  conu doctor

Reference:
  conu help commands    full command list
  conu <command> --help command-specific help
  conu --version

privacy:
  payload bytes are private and not displayed
  contentsDisplayed=false"
        .to_string()
}

fn render_help_command(args: &[String]) -> CliOutput {
    if args.is_empty() || matches!(args, [arg] if matches!(arg.as_str(), "--help" | "-h")) {
        return CliOutput::success(render_help());
    }

    if matches!(args, [arg] if matches!(arg.as_str(), "commands" | "all")) {
        return CliOutput::success(render_command_reference());
    }

    CliOutput::failure(2, "usage: conu help [commands]\ncontentsDisplayed=false")
}

fn render_command_reference() -> String {
    r"conu command reference

Usage:
  conu
  conu menu
  conu dashboard
  conu init
  conu status [--json]
  conu ready <agent-id> <display-name> [--kind <kind>] [--presence <ready|busy|idle|offline>] [--connect <agent-id>] [--stream-kind <kind>] [--room <room-id>] [--room-name <display-name>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence-capability <true|false>] [--json]
  conu agents [--json]
  conu agents prepare <agent-id> <display-name> [--kind <kind>] [--presence <ready|busy|idle|offline>] [--connect <agent-id>] [--stream-kind <kind>] [--room <room-id>] [--room-name <display-name>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence-capability <true|false>] [--json]
  conu agents register <agent-id> <display-name> [--kind <kind>] [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--presence <true|false>] [--json]
  conu agents export <agent-id> [--json]
  conu agents trust <agent-id> <display-name> --node <peer-node-id> --kind <kind> --signing-key <hex> --signature <hex> --signature-key-id <id> [--json]
  conu agents heartbeat <agent-id> [--presence <ready|busy|idle|offline>] [--json]
  conu chat
  conu chat <from-agent> <to-agent>
  conu chat <from-agent> <to-agent> (--stdin|--file <path>) [--json]
  conu send <from-agent> <to-agent> (--stdin|--file <path>) [--json]
  conu send <from-agent> <to-agent> --peer <peer-node-id> (--stdin|--file <path>) [--json]
  conu inbox [agent-id] [--json]
  conu next <agent-id> [--json]
  conu history <agent-id> [--after <envelope-id>] [--limit <count>] [--newest-first] [--json]
  conu wait <agent-id> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu receive <agent-id> <envelope-id> --output <file> [--json]
  conu receive <agent-id> --latest --output <file> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu pull <agent-id> --dir <directory> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu reply <agent-id> <envelope-id> (--stdin|--file <path>) [--json]
  conu reply <agent-id> --latest (--stdin|--file <path>) [--json]
  conu messages send <from-agent> <to-agent> (--stdin|--file <path>) [--json]
  conu messages send <from-agent> <to-agent> --peer <peer-node-id> (--stdin|--file <path>) [--json]
  conu messages inbox [agent-id] [--json]
  conu messages history <agent-id> [--after <envelope-id>] [--limit <count>] [--newest-first] [--json]
  conu messages reply <agent-id> <envelope-id> (--stdin|--file <path>) [--json]
  conu messages reply <agent-id> --latest (--stdin|--file <path>) [--json]
  conu messages wait <agent-id> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu messages receive <agent-id> <envelope-id> --output <file> [--json]
  conu messages receive <agent-id> --latest --output <file> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu messages pull <agent-id> --dir <directory> [--after <envelope-id>] [--timeout-ms <milliseconds>] [--interval-ms <milliseconds>] [--process-ipc] [--json]
  conu messages receipts [--json]
  conu relay sync [--wait-ms <milliseconds>] [--json]
  conu relay credential status [--json]
  conu relay credential set --stdin [--json]
  conu relay credential clear [--json]
  conu streams [--json]
  conu streams open <from-agent> <to-agent> [--kind <kind>] [--json]
  conu streams write <stream-id> --stdin [--json]
  conu streams close <stream-id> [--json]
  conu rooms [--json]
  conu rooms create <room-id> <display-name> --agent <agent-id> [--json]
  conu rooms join <room-id> <agent-id> [--json]
  conu rooms publish <room-id> <from-agent> <topic> --stdin [--json]
  conu rooms policy [<room-id> <agent-id> <topic> [--publish <true|false>] [--subscribe <true|false>]] [--json]
  conu rooms events [--json]
  conu sessions [--json]
  conu sessions sync [--json]
  conu routes [--json]
  conu routes sync [--json]
  conu routes probes [--json]
  conu logs rotate [--max-bytes <bytes>] [--keep <count>] [--json]
  conu telemetry snapshot [--json]
  conu update check --policy-file <path> [--sha256-file <path>] [--signature-file <path>] [--gpg-verify] [--json]
  conu security audit [--json]
  conu security rotate storage --confirm [--json]
  conu security rotate identity --confirm-peer-refresh [--json]
  conu security retire identity --confirm-peer-refresh-complete [--json]
  conu security retire storage --confirm [--json]
  conu identity export [--relay <ws://host:port|wss://host/path>] [--direct <quic://host:port>] [--json]
  conu peers [--json]
  conu peers trust --card <file|-> [--json]
  conu peers trust <peer-node-id> <display-name> --exchange-key <hex> [--relay <ws://host:port|wss://host/path>] [--direct <quic://host:port>] [--signing-key <hex> --signature <hex> --signature-key-id <id>] [--json]
  conu peers policy [<peer-node-id> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>]] [--json]
  conu peers revoke <peer-node-id> [--json]
  conu pair [--json]
  conu join <code> [--json]
  conu connect
  conu connect local <from-agent> <to-agent> [--kind <kind>] [--json]
  conu connect room <room-id> <agent-id> [--json]
  conu watch
  conu setup [local] [--start] [--from <agent-id>] [--to <agent-id>] [--from-name <display-name>] [--to-name <display-name>] [--from-kind <kind>] [--to-kind <kind>] [--room <room-id>] [--room-name <display-name>] [--json]
  conu doctor [--json]
  conu smoke [local] [--json]
  conu start [--json]
  conu stop [--json]
  conu components
  conu --help
  conu --version

Interactive TTY:
  conu         opens the Up/Down menu
  conu connect opens the connection selector
  conu chat    asks for sender, receiver, and one message

conU carries local and relay-backed peer-encrypted messages while payload contents remain hidden. conUD pumps configured relay routes automatically."
        .to_string()
}

fn render_start_report(report: &StartRuntimeReport, json: bool) -> String {
    let status = &report.status;

    if json {
        return format!(
            r#"{{
  "status": "{}",
  "launched": {},
  "pid": {},
  "health": "{}",
  "relayPump": "auto_when_configured",
  "contentsDisplayed": false
}}"#,
            status.state.as_str(),
            report.launched,
            json_u32(status.pid),
            json_escape(runtime_health_label(status))
        );
    }

    let action = if report.launched {
        "launched"
    } else {
        "already running"
    };

    format!(
        r"conU start

status: {action}
conUD: {}
pid: {}
health: {}
relay pump: auto when configured

privacy
  payload view  contents are not displayed by conU",
        runtime_state_label(status),
        runtime_pid_label(status),
        runtime_health_label(status)
    )
}

fn spawn_conud_daemon(daemon: &Path, home_override: Option<&PathBuf>) -> io::Result<Child> {
    #[cfg(windows)]
    {
        let script = format!(
            "Start-Process -FilePath {} -ArgumentList '--serve' -WindowStyle Hidden",
            powershell_quote(&daemon.display().to_string())
        );
        let mut command = Command::new("powershell");
        command
            .arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(home) = home_override {
            command.env("CONU_HOME", home);
        }
        command.spawn()
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new(daemon);
        command
            .arg("--serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(home) = home_override {
            command.env("CONU_HOME", home);
        }
        command.spawn()
    }
}

#[cfg(windows)]
fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn render_stop_report(report: &StopReport, json: bool) -> String {
    if json {
        return format!(
            r#"{{
  "requested": {},
  "status": "{}",
  "pid": {},
  "contentsDisplayed": false
}}"#,
            report.requested,
            report.status.state.as_str(),
            json_u32(report.status.pid)
        );
    }

    let action = if report.requested {
        "stop requested"
    } else {
        "not running"
    };

    format!(
        r"conU stop

status: {action}
conUD: {}
pid: {}

privacy
  payload view  contents are not displayed by conU",
        runtime_state_label(&report.status),
        runtime_pid_label(&report.status)
    )
}

fn initialization_label(snapshot: &StateSnapshot) -> &'static str {
    if snapshot.is_initialized() {
        "initialized"
    } else {
        "not_initialized"
    }
}

fn ready_label(is_ready: bool) -> &'static str {
    if is_ready { "ready" } else { "not_initialized" }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn empty_security_audit() -> SecurityAudit {
    SecurityAudit {
        initialized: false,
        identity_signing_key: false,
        identity_exchange_key: false,
        storage_key: false,
        replay_cache: false,
        key_rotation_plan: false,
        local_payload_encryption: false,
        signed_agent_cards: false,
        peer_key_exchange: false,
        secret_storage_backend: "uninitialized".to_string(),
        secrets_os_protected: false,
        contents_displayed: false,
    }
}

fn created_label(created: bool) -> &'static str {
    if created { "created" } else { "kept" }
}

fn runtime_state_label(status: &RuntimeStatus) -> &'static str {
    match status.state {
        RuntimeState::Offline => "offline",
        RuntimeState::Starting => "starting",
        RuntimeState::Running => "running",
        RuntimeState::Stopping => "stopping",
        RuntimeState::Stopped => "stopped",
        RuntimeState::Stale => "stale",
    }
}

fn runtime_health_label(status: &RuntimeStatus) -> &'static str {
    match status.state {
        RuntimeState::Starting | RuntimeState::Running | RuntimeState::Stopping => {
            "file heartbeat ok"
        }
        RuntimeState::Stale => "stale heartbeat",
        RuntimeState::Offline | RuntimeState::Stopped => "offline",
    }
}

fn runtime_pid_label(status: &RuntimeStatus) -> String {
    status
        .pid
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn optional_u64_label(value: Option<u64>) -> String {
    value
        .map(|value| format!("{value}s"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn trusted_peer_count(peers: &[TrustedPeer]) -> usize {
    peers
        .iter()
        .filter(|peer| peer.status == TrustStatus::Trusted)
        .count()
}

fn open_stream_count(stream_records: &[StreamRecord]) -> usize {
    stream_records
        .iter()
        .filter(|stream| stream.state.as_str() == "open")
        .count()
}

fn selected_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.is_selected())
        .count()
}

fn selected_direct_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.is_selected() && route.transport == RouteTransport::DirectQuic)
        .count()
}

fn selected_relay_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.is_selected() && route.transport == RouteTransport::RelayWebSocket)
        .count()
}

fn relay_fallback_route_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.relay_fallback)
        .count()
}

fn nat_traversal_unavailable_count(route_records: &[RouteRecord]) -> usize {
    route_records
        .iter()
        .filter(|route| route.failure_reason.as_deref() == Some("nat_traversal_unavailable"))
        .count()
}

fn json_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_string_array(values: &[&str]) -> String {
    let items = values
        .iter()
        .map(|value| json_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{items}]")
}

fn json_optional_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn resolve_conud_executable() -> PathBuf {
    if let Ok(value) = env::var("CONUD_EXE")
        && !value.trim().is_empty()
    {
        return PathBuf::from(value);
    }

    if let Ok(mut path) = env::current_exe() {
        path.set_file_name(format!("conud{}", env::consts::EXE_SUFFIX));
        if path.exists() {
            return path;
        }
    }

    PathBuf::from(format!("conud{}", env::consts::EXE_SUFFIX))
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            value if value.is_control() => escaped.push_str(&format!("\\u{:04x}", value as u32)),
            value => escaped.push(value),
        }
    }

    escaped
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn optional_json_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn is_help_request(args: &[String]) -> bool {
    matches!(args, [arg] if matches!(arg.as_str(), "--help" | "-h" | "help"))
}

fn json_flag(args: &[String]) -> Result<bool, CliOutput> {
    let mut json = false;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            return Err(unknown_option_error());
        }
    }
    Ok(json)
}

fn join_code(args: &[String]) -> Result<&str, CliOutput> {
    let mut code = None;
    for arg in args {
        if arg == "--json" {
            continue;
        }
        if code.is_some() {
            return Err(CliOutput::failure(2, "usage: conu join <code> [--json]"));
        }
        code = Some(arg.as_str());
    }

    match code {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(CliOutput::failure(2, "usage: conu join <code> [--json]")),
    }
}

fn reject_args(args: &[String]) -> Option<CliOutput> {
    args.first().map(|_arg| unexpected_argument_error())
}

fn finish(mut output: String) -> String {
    while output.ends_with('\n') {
        output.pop();
    }
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn dashboard_renders_control_room() {
        let home = temp_home("dashboard");
        let output = run_with_home(Vec::<String>::new(), Some(home.clone()));
        let explicit = run_with_home(["dashboard"], Some(home));

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("control room"));
        assert!(output.stdout.contains("next actions"));
        assert!(output.stdout.contains("conu menu"));
        assert!(output.stdout.contains("conu setup --start"));
        assert!(output.stdout.contains("conu smoke"));
        assert!(!output.stdout.contains("agent.beta"));
        assert!(!output.stdout.contains("conu update apply"));
        assert!(output.stderr.is_empty());
        assert_eq!(explicit.code, 0);
        assert!(explicit.stdout.contains("control room"));
        assert!(explicit.stderr.is_empty());
    }

    #[test]
    fn dashboard_next_actions_use_registered_agents_after_setup() {
        let home = temp_home("dashboard-ready");
        let setup = run_with_home(["setup", "local"], Some(home.clone()));
        assert_eq!(setup.code, 0, "{}", setup.stderr);

        let output = run_with_home(["dashboard"], Some(home));

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("agent.alpha:ready"));
        assert!(output.stdout.contains("agent.beta:ready"));
        assert!(output.stdout.contains("conu chat agent.alpha agent.beta"));
        assert!(
            output
                .stdout
                .contains("conu send agent.alpha agent.beta --file ./message.bin --json")
        );
        assert!(output.stdout.contains("conu inbox agent.beta"));
        assert!(output.stdout.contains("conu next agent.beta --json"));
        assert!(output.stdout.contains("conu history agent.beta"));
        assert!(
            output
                .stdout
                .contains("conu wait agent.beta --process-ipc --timeout-ms 30000 --json")
        );
        assert!(!output.stdout.contains("conu update apply"));
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn next_for_unregistered_agent_suggests_ready_without_paths_or_payloads() {
        let home = temp_home("next-unregistered");

        let output = run_with_home(["next", "agent.new", "--json"], Some(home.clone()));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"agentId\": \"agent.new\""));
        assert!(output.stdout.contains("\"registered\": false"));
        assert!(output.stdout.contains("\"inboxMessages\": 0"));
        assert!(
            output
                .stdout
                .contains("conu ready agent.new <display-name> --json")
        );
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains(home.to_str().expect("path utf8")));
        assert!(!output.stdout.contains("private message"));
    }

    #[test]
    fn next_for_ready_agent_suggests_wait_when_inbox_is_empty() {
        let home = temp_home("next-ready-empty");
        register_test_agent(&home, "agent.receiver");

        let output = run_with_home(["next", "agent.receiver"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("conU next"));
        assert!(output.stdout.contains("registered: yes"));
        assert!(output.stdout.contains("presence: ready"));
        assert!(output.stdout.contains("inboxMessages: 0"));
        assert!(
            output
                .stdout
                .contains("conu wait agent.receiver --process-ipc --timeout-ms 30000 --json")
        );
        assert!(
            output
                .stdout
                .contains("conu agents heartbeat agent.receiver --presence ready --json")
        );
        assert!(!output.stdout.contains("private message"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(output.stdout.contains("pathDisplayed=false"));
    }

    #[test]
    fn next_for_ready_agent_with_inbox_suggests_pull_and_latest_reply_without_payload() {
        let home = temp_home("next-ready-inbox");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message contents",
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");

        let output = run_with_home(["next", "agent.receiver", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"registered\": true"));
        assert!(output.stdout.contains("\"inboxMessages\": 1"));
        assert!(output.stdout.contains(&inbox[0].envelope_id));
        assert!(output.stdout.contains("\"fromAgentId\":\"agent.sender\""));
        assert!(
            output
                .stdout
                .contains("conu pull agent.receiver --dir ./agent-inbox --process-ipc --json")
        );
        assert!(
            output
                .stdout
                .contains("conu reply agent.receiver --latest --file ./reply.bin --json")
        );
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn menu_command_renders_terminal_launcher_without_payloads() {
        let home = temp_home("menu");
        let output = run_with_home(["menu"], Some(home));

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("Use Up/Down"));
        assert!(output.stdout.contains("conu dashboard"));
        assert!(output.stdout.contains("conu setup --start"));
        assert!(output.stdout.contains("conu connect"));
        assert!(output.stdout.contains("conu inbox"));
        assert!(output.stdout.contains("conu status"));
        assert!(output.stdout.contains("conu smoke"));
        assert_eq!(output.stdout.matches("conu connect").count(), 1);
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(!output.stdout.contains("private message contents"));
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn default_help_is_short_and_points_to_command_reference() {
        for args in [vec!["--help"], vec!["help"]] {
            let output = run(args);

            assert_eq!(output.code, 0, "{}", output.stderr);
            assert!(output.stdout.contains("Start:"));
            assert!(output.stdout.contains("conu setup --start"));
            assert!(output.stdout.contains("conu help commands"));
            assert!(output.stdout.contains("contentsDisplayed=false"));
            assert!(!output.stdout.contains("conu agents prepare <agent-id>"));
            assert!(output.stderr.is_empty());
        }
    }

    #[test]
    fn help_commands_keeps_full_command_reference() {
        for args in [vec!["help", "commands"], vec!["help", "all"]] {
            let output = run(args);

            assert_eq!(output.code, 0, "{}", output.stderr);
            assert!(output.stdout.contains("conu command reference"));
            assert!(output.stdout.contains("conu agents prepare <agent-id>"));
            assert!(output.stdout.contains("conu relay credential set --stdin"));
            assert!(output.stdout.contains("payload contents remain hidden"));
            assert!(output.stderr.is_empty());
        }
    }

    #[test]
    fn connect_menu_items_offer_setup_for_empty_state() {
        let home = temp_home("connect-menu-empty");
        let items = connect_menu_items(Some(home.clone()));

        assert!(
            items
                .iter()
                .any(|item| item.command == "conu setup --start" && item.title == "Setup")
        );
        assert!(
            items
                .iter()
                .any(|item| item.command == "conu pair" && item.title == "Pair peer")
        );
        assert!(
            items
                .iter()
                .any(|item| item.command == "conu watch" && item.title == "Watch")
        );
        assert!(
            items
                .iter()
                .all(|item| !item.command.contains("private payload"))
        );
    }

    #[test]
    fn terminal_chat_prompt_payload_is_bounded_without_echoing_contents() {
        assert_eq!(
            terminal_chat_payload_from_line("hello agent\n").expect("payload accepted"),
            b"hello agent"
        );

        let empty = terminal_chat_payload_from_line("\r\n").expect_err("empty payload fails");
        assert!(empty.contains("message was empty"));
        assert!(!empty.contains("\r\n"));

        let secret_marker = "private-terminal-chat-marker";
        let mut oversized = secret_marker.to_string();
        oversized.push_str(&"a".repeat(TERMINAL_CHAT_MAX_BYTES));
        let error = terminal_chat_payload_from_line(&oversized).expect_err("oversized fails");
        assert!(error.contains("message exceeds"));
        assert!(!error.contains(secret_marker));
    }

    #[test]
    fn connect_menu_items_offer_real_local_actions_after_setup() {
        let home = temp_home("connect-menu-ready");
        let setup = run_with_home(["setup", "local"], Some(home.clone()));
        assert_eq!(setup.code, 0, "{}", setup.stderr);
        let prepared = run_with_home(
            ["agents", "prepare", "agent.third", "Third"],
            Some(home.clone()),
        );
        assert_eq!(prepared.code, 0, "{}", prepared.stderr);

        let items = connect_menu_items(Some(home.clone()));

        assert!(items.iter().any(|item| {
            item.command == "conu connect local agent.alpha agent.beta"
                && item.title == "Local stream"
        }));
        assert!(items.iter().any(|item| {
            item.command == "conu chat agent.alpha agent.beta"
                && item.title == "Local chat"
                && matches!(
                    item.action,
                    ConnectMenuAction::PromptLocalChat {
                        ref from_agent_id,
                        ref to_agent_id
                    } if from_agent_id == "agent.alpha" && to_agent_id == "agent.beta"
                )
        }));
        assert!(items.iter().any(|item| {
            item.command == "conu connect room room.dev agent.third" && item.title == "Room join"
        }));
        assert!(items.iter().all(|item| {
            !item
                .command
                .contains("local setup private payload contents")
        }));

        let selector = run_with_home(["connect"], Some(home));
        assert_eq!(selector.code, 0, "{}", selector.stderr);
        assert!(
            selector
                .stdout
                .contains("conu connect room room.dev agent.third")
        );
        assert!(selector.stdout.contains("conu chat agent.alpha agent.beta"));
        assert!(
            !selector
                .stdout
                .contains("conu connect room room.dev agent.alpha")
        );
    }

    #[test]
    fn smoke_local_verifies_delivery_without_persisting_temp_state() {
        let home = temp_home("smoke-local");
        let output = run_with_home(["smoke", "local"], Some(home.clone()));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: passed"));
        assert!(output.stdout.contains("agents registered: 2"));
        assert!(output.stdout.contains("messages delivered: 1"));
        assert!(output.stdout.contains("receipts: 1"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(
            !output
                .stdout
                .contains(&"Z".repeat(LOCAL_SMOKE_PAYLOAD.len()))
        );
        assert!(output.stderr.is_empty());

        let smoke_root = home.join("conu-smoke");
        let entries = fs::read_dir(smoke_root)
            .expect("smoke root remains")
            .collect::<Result<Vec<_>, _>>()
            .expect("smoke root entries read");
        assert!(entries.is_empty(), "temp smoke homes should be removed");
    }

    #[test]
    fn smoke_local_json_reports_metadata_only() {
        let home = temp_home("smoke-local-json");
        let output = run_with_home(["smoke", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"passed\""));
        assert!(output.stdout.contains("\"mode\": \"local\""));
        assert!(output.stdout.contains("\"registeredAgents\": 2"));
        assert!(output.stdout.contains("\"deliveredMessages\": 1"));
        assert!(output.stdout.contains("\"tempStatePersisted\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            !output
                .stdout
                .contains(&"Z".repeat(LOCAL_SMOKE_PAYLOAD.len()))
        );
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn setup_local_prepares_persistent_agent_playground() {
        let home = temp_home("setup-local");
        let output = run_with_home(["setup", "local"], Some(home.clone()));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: ready"));
        assert!(output.stdout.contains("mode: reusable local state"));
        assert!(output.stdout.contains("agent.alpha -> agent.beta"));
        assert!(
            output
                .stdout
                .contains("agent kinds: local-agent -> local-agent")
        );
        assert!(output.stdout.contains("message: delivered"));
        assert!(
            output
                .stdout
                .contains("conu connect local agent.alpha agent.beta")
        );
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(
            !output
                .stdout
                .contains("local setup private payload contents")
        );
        assert!(output.stderr.is_empty());

        let agents = agents::list_local_agents(Some(home.clone())).expect("agents read");
        assert!(agents.iter().any(|agent| {
            agent.agent_id == LOCAL_SETUP_FROM_AGENT
                && agent.capabilities.messages
                && agent.capabilities.streams
                && agent.capabilities.rooms
        }));
        assert!(agents.iter().any(|agent| {
            agent.agent_id == LOCAL_SETUP_TO_AGENT
                && agent.capabilities.messages
                && agent.capabilities.streams
                && agent.capabilities.rooms
        }));

        let inbox = messages::list_agent_inbox(Some(home.clone()), LOCAL_SETUP_TO_AGENT)
            .expect("helper inbox reads");
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].payload_bytes, LOCAL_SETUP_PAYLOAD.len());

        let second = run_with_home(["setup", "--json"], Some(home));
        assert_eq!(second.code, 0, "{}", second.stderr);
        assert!(second.stdout.contains("\"status\": \"ready\""));
        assert!(second.stdout.contains("\"persistentState\": true"));
        assert!(second.stdout.contains("\"contentsDisplayed\": false"));
        assert!(second.stdout.contains("\"from\": \"agent.alpha\""));
        assert!(second.stdout.contains("\"to\": \"agent.beta\""));
        assert!(second.stdout.contains("\"fromKind\": \"local-agent\""));
        assert!(second.stdout.contains("\"toKind\": \"local-agent\""));
        assert!(second.stdout.contains("\"toAgentJoined\": false"));
        assert!(second.stdout.contains("\"created\": false"));
        assert!(
            !second
                .stdout
                .contains("local setup private payload contents")
        );
        assert!(second.stderr.is_empty());
    }

    #[test]
    fn setup_local_can_include_existing_runtime_status() {
        let home = temp_home("setup-local-start");
        let _lease = runtime::acquire_runtime(Some(home.clone())).expect("runtime starts");
        let output = run_with_home(["setup", "--start"], Some(home.clone()));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: ready"));
        assert!(output.stdout.contains("runtime: running (already running"));
        assert!(output.stdout.contains("pid "));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(
            !output
                .stdout
                .contains("local setup private payload contents")
        );
        assert!(output.stderr.is_empty());

        let json = run_with_home(["setup", "local", "--start", "--json"], Some(home));
        assert_eq!(json.code, 0, "{}", json.stderr);
        assert!(json.stdout.contains("\"runtime\": {"));
        assert!(json.stdout.contains("\"requested\": true"));
        assert!(json.stdout.contains("\"status\": \"running\""));
        assert!(json.stdout.contains("\"launched\": false"));
        assert!(json.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!json.stdout.contains("local setup private payload contents"));
        assert!(json.stderr.is_empty());
    }

    #[test]
    fn setup_local_accepts_custom_agent_pair_and_room() {
        let home = temp_home("setup-local-custom");
        let output = run_with_home(
            [
                "setup",
                "local",
                "--from",
                "agent.frontend",
                "--to",
                "agent.qa",
                "--from-name",
                "Frontend Agent",
                "--to-name",
                "QA Agent",
                "--from-kind",
                "browser-agent",
                "--to-kind",
                "test-agent",
                "--room",
                "room.release",
                "--room-name",
                "Release Room",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("agent.frontend -> agent.qa"));
        assert!(
            output
                .stdout
                .contains("agent kinds: browser-agent -> test-agent")
        );
        assert!(output.stdout.contains("room: room.release"));
        assert!(
            output
                .stdout
                .contains("conu connect local agent.frontend agent.qa")
        );
        assert!(output.stdout.contains("conu wait agent.qa"));
        assert!(
            output
                .stdout
                .contains("conu rooms publish room.release agent.frontend build")
        );
        assert!(!output.stdout.contains("agent.alpha"));
        assert!(!output.stdout.contains("agent.beta"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(output.stderr.is_empty());

        let agents = agents::list_local_agents(Some(home.clone())).expect("agents read");
        assert!(agents.iter().any(|agent| {
            agent.agent_id == "agent.frontend"
                && agent.display_name == "Frontend Agent"
                && agent.kind == "browser-agent"
                && agent.capabilities.messages
                && agent.capabilities.streams
                && agent.capabilities.rooms
        }));
        assert!(agents.iter().any(|agent| {
            agent.agent_id == "agent.qa"
                && agent.display_name == "QA Agent"
                && agent.kind == "test-agent"
                && agent.capabilities.messages
                && agent.capabilities.streams
                && agent.capabilities.rooms
        }));

        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.qa").expect("inbox reads");
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].from_agent_id, "agent.frontend");
        assert_eq!(inbox[0].to_agent_id, "agent.qa");
        assert_eq!(inbox[0].payload_bytes, LOCAL_SETUP_PAYLOAD.len());

        let json = run_with_home(
            [
                "setup",
                "--from",
                "agent.frontend",
                "--to",
                "agent.qa",
                "--room",
                "room.release",
                "--json",
            ],
            Some(home.clone()),
        );

        assert_eq!(json.code, 0, "{}", json.stderr);
        assert!(json.stdout.contains("\"from\": \"agent.frontend\""));
        assert!(json.stdout.contains("\"to\": \"agent.qa\""));
        assert!(json.stdout.contains("\"fromKind\": \"browser-agent\""));
        assert!(json.stdout.contains("\"toKind\": \"test-agent\""));
        assert!(json.stdout.contains("\"roomId\": \"room.release\""));
        assert!(json.stdout.contains("\"toAgentJoined\": false"));
        assert!(json.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!json.stdout.contains("local setup private payload contents"));
        assert!(json.stderr.is_empty());

        let agents_after_repeat =
            agents::list_local_agents(Some(home)).expect("agents read after repeat setup");
        assert!(agents_after_repeat.iter().any(|agent| {
            agent.agent_id == "agent.frontend"
                && agent.display_name == "Frontend Agent"
                && agent.kind == "browser-agent"
        }));
        assert!(agents_after_repeat.iter().any(|agent| {
            agent.agent_id == "agent.qa"
                && agent.display_name == "QA Agent"
                && agent.kind == "test-agent"
        }));
    }

    #[test]
    fn simple_agent_messenger_commands_work_end_to_end() {
        let home = temp_home("simple-agent-messenger");
        let setup = run_with_home(["setup", "local"], Some(home.clone()));
        assert_eq!(setup.code, 0, "{}", setup.stderr);

        let send_secret = b"private short send payload";
        let send = run_with_home_and_stdin(
            ["send", "agent.alpha", "agent.beta", "--stdin"],
            Some(home.clone()),
            send_secret.to_vec(),
        );
        assert_eq!(send.code, 0, "{}", send.stderr);
        assert!(send.stdout.contains("conU send"));
        assert!(!send.stdout.contains("private short send payload"));
        assert!(send.stderr.is_empty());

        let wait = run_with_home(
            [
                "wait",
                "agent.beta",
                "--process-ipc",
                "--timeout-ms",
                "1000",
                "--json",
            ],
            Some(home.clone()),
        );
        assert_eq!(wait.code, 0, "{}", wait.stderr);
        assert!(!wait.stdout.contains("private short send payload"));
        let wait_json: Value = serde_json::from_str(&wait.stdout).expect("wait json parses");
        let first_envelope = wait_json
            .get("message")
            .and_then(Value::as_object)
            .and_then(|message| message.get("envelopeId"))
            .and_then(Value::as_str)
            .expect("wait returns envelope")
            .to_string();

        let inbox = run_with_home(["inbox", "agent.beta", "--json"], Some(home.clone()));
        assert_eq!(inbox.code, 0, "{}", inbox.stderr);
        assert!(inbox.stdout.contains("\"agentId\": \"agent.beta\""));
        assert!(inbox.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!inbox.stdout.contains("private short send payload"));

        let history = run_with_home(
            ["history", "agent.beta", "--limit", "20", "--json"],
            Some(home.clone()),
        );
        assert_eq!(history.code, 0, "{}", history.stderr);
        assert!(history.stdout.contains("\"totalMessages\""));
        assert!(history.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!history.stdout.contains("private short send payload"));

        let receive_path = home.join("received-short.bin");
        let receive = run_with_home(
            vec![
                "receive".to_string(),
                "agent.beta".to_string(),
                first_envelope.clone(),
                "--output".to_string(),
                receive_path.display().to_string(),
                "--json".to_string(),
            ],
            Some(home.clone()),
        );
        assert_eq!(receive.code, 0, "{}", receive.stderr);
        assert!(receive.stdout.contains("\"status\": \"written\""));
        assert!(receive.stdout.contains("\"pathDisplayed\": false"));
        assert!(!receive.stdout.contains(&receive_path.display().to_string()));
        assert_eq!(
            fs::read(&receive_path).expect("received payload reads"),
            send_secret
        );

        let chat_secret = b"private chat prompt payload";
        let chat = run_with_home_and_stdin(
            ["chat", "agent.alpha", "agent.beta", "--stdin"],
            Some(home.clone()),
            chat_secret.to_vec(),
        );
        assert_eq!(chat.code, 0, "{}", chat.stderr);
        assert!(chat.stdout.contains("conU chat"));
        assert!(!chat.stdout.contains("private chat prompt payload"));

        let chat_wait = run_with_home(
            [
                "wait",
                "agent.beta",
                "--after",
                &first_envelope,
                "--process-ipc",
                "--timeout-ms",
                "1000",
                "--json",
            ],
            Some(home.clone()),
        );
        assert_eq!(chat_wait.code, 0, "{}", chat_wait.stderr);
        let chat_wait_json: Value =
            serde_json::from_str(&chat_wait.stdout).expect("chat wait json parses");
        let chat_envelope = chat_wait_json
            .get("message")
            .and_then(Value::as_object)
            .and_then(|message| message.get("envelopeId"))
            .and_then(Value::as_str)
            .expect("chat wait returns envelope")
            .to_string();

        let reply_secret = b"private reply payload";
        let reply = run_with_home_and_stdin(
            vec![
                "reply".to_string(),
                "agent.beta".to_string(),
                chat_envelope,
                "--stdin".to_string(),
                "--json".to_string(),
            ],
            Some(home.clone()),
            reply_secret.to_vec(),
        );
        assert_eq!(reply.code, 0, "{}", reply.stderr);
        assert!(!reply.stdout.contains("private reply payload"));

        let alpha_wait = run_with_home(
            [
                "wait",
                "agent.alpha",
                "--process-ipc",
                "--timeout-ms",
                "1000",
                "--json",
            ],
            Some(home),
        );
        assert_eq!(alpha_wait.code, 0, "{}", alpha_wait.stderr);
        assert!(
            alpha_wait
                .stdout
                .contains("\"fromAgentId\": \"agent.beta\"")
        );
        assert!(alpha_wait.stdout.contains("\"toAgentId\": \"agent.alpha\""));
        assert!(!alpha_wait.stdout.contains("private reply payload"));
    }

    #[test]
    fn setup_local_rejects_same_agent_pair() {
        let home = temp_home("setup-local-same-agent");
        let output = run_with_home(
            ["setup", "--from", "agent.same", "--to", "agent.same"],
            Some(home),
        );

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("--from and --to must be different"));
        assert!(output.stderr.contains("usage:"));
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn connect_selector_suggests_useful_next_steps() {
        let home = temp_home("connect-selector");
        let empty = run_with_home(["connect"], Some(home.clone()));

        assert_eq!(empty.code, 0);
        assert!(empty.stdout.contains("conu setup --start"));
        assert!(!empty.stdout.contains("conu agents prepare agent.alpha"));
        assert!(!empty.stdout.contains("conu agents prepare agent.beta"));
        assert!(empty.stdout.contains("conu pair"));

        register_test_agent(&home, "agent.alpha");
        register_test_agent(&home, "agent.beta");
        let ready = run_with_home(["connect"], Some(home));

        assert_eq!(ready.code, 0);
        assert!(
            ready
                .stdout
                .contains("conu connect local agent.alpha agent.beta")
        );
        assert!(ready.stdout.contains("contents are not displayed"));
        assert!(!ready.stdout.contains("private message contents"));
        assert!(ready.stderr.is_empty());
    }

    #[test]
    fn phase_fourteen_commands_are_registered() {
        let home = temp_home("commands");

        for command in [
            "init",
            "menu",
            "setup",
            "smoke",
            "status",
            "ready",
            "agents",
            "streams",
            "rooms",
            "sessions",
            "security",
            "pair",
            "peers",
            "routes",
            "connect",
            "dashboard",
            "watch",
            "doctor",
            "telemetry",
            "update",
            "stop",
        ] {
            let output = run_with_home([command], Some(home.clone()));
            assert_eq!(output.code, 0, "{command} failed: {}", output.stderr);
        }

        let receipts = run_with_home(["messages", "receipts"], Some(home));
        assert_eq!(receipts.code, 0);
    }

    #[test]
    fn command_group_help_exits_successfully() {
        for args in [
            vec!["init", "--help"],
            vec!["status", "--help"],
            vec!["ready", "--help"],
            vec!["agents", "--help"],
            vec!["agents", "-h"],
            vec!["agents", "help"],
            vec!["agents", "register", "--help"],
            vec!["agents", "prepare", "--help"],
            vec!["agents", "heartbeat", "--help"],
            vec!["agents", "export", "--help"],
            vec!["agents", "trust", "--help"],
            vec!["identity", "--help"],
            vec!["identity", "-h"],
            vec!["identity", "help"],
            vec!["identity", "export", "--help"],
            vec!["peers", "--help"],
            vec!["peers", "-h"],
            vec!["peers", "help"],
            vec!["peers", "trust", "--help"],
            vec!["peers", "policy", "--help"],
            vec!["peers", "revoke", "--help"],
            vec!["send", "--help"],
            vec!["chat", "--help"],
            vec!["inbox", "--help"],
            vec!["next", "--help"],
            vec!["history", "--help"],
            vec!["wait", "--help"],
            vec!["receive", "--help"],
            vec!["reply", "--help"],
            vec!["connect", "--help"],
            vec!["connect", "-h"],
            vec!["connect", "help"],
            vec!["connect", "local", "--help"],
            vec!["connect", "room", "--help"],
            vec!["streams", "--help"],
            vec!["streams", "open", "--help"],
            vec!["streams", "write", "--help"],
            vec!["streams", "close", "--help"],
            vec!["rooms", "--help"],
            vec!["rooms", "create", "--help"],
            vec!["rooms", "join", "--help"],
            vec!["rooms", "publish", "--help"],
            vec!["rooms", "events", "--help"],
            vec!["rooms", "policy", "--help"],
            vec!["sessions", "--help"],
            vec!["sessions", "sync", "--help"],
            vec!["routes", "--help"],
            vec!["routes", "sync", "--help"],
            vec!["routes", "probes", "--help"],
            vec!["pair", "--help"],
            vec!["join", "--help"],
            vec!["watch", "--help"],
            vec!["doctor", "--help"],
            vec!["components", "--help"],
            vec!["start", "--help"],
            vec!["stop", "--help"],
            vec!["messages", "--help"],
            vec!["messages", "-h"],
            vec!["messages", "help"],
            vec!["messages", "send", "--help"],
            vec!["messages", "inbox", "--help"],
            vec!["messages", "history", "--help"],
            vec!["messages", "reply", "--help"],
            vec!["messages", "wait", "--help"],
            vec!["messages", "receive", "--help"],
            vec!["messages", "receipts", "--help"],
            vec!["relay", "--help"],
            vec!["relay", "-h"],
            vec!["relay", "help"],
            vec!["relay", "credential", "--help"],
            vec!["relay", "credential", "set", "--help"],
            vec!["relay", "credential", "status", "--help"],
            vec!["relay", "credential", "clear", "--help"],
        ] {
            let output = run(args.clone());

            assert_eq!(output.code, 0, "{args:?} failed: {}", output.stderr);
            assert!(output.stdout.contains("usage:"));
            assert!(output.stderr.is_empty());
        }
    }

    #[test]
    fn relay_credential_nested_help_is_specific_and_token_safe() {
        for (args, expected) in [
            (
                vec!["relay", "credential", "set", "--help"],
                "conu relay credential set --stdin",
            ),
            (
                vec!["relay", "credential", "status", "--help"],
                "conu relay credential status",
            ),
            (
                vec!["relay", "credential", "clear", "--help"],
                "conu relay credential clear",
            ),
        ] {
            let output = run(args);

            assert_eq!(output.code, 0, "{}", output.stderr);
            assert!(output.stdout.contains(expected));
            assert!(output.stdout.contains("contentsDisplayed=false"));
            assert!(!output.stdout.contains("relay-secret-token"));
            assert!(output.stderr.is_empty());
        }
    }

    #[test]
    fn update_check_validates_signed_policy_metadata_without_payloads() {
        let home = temp_home("update-check-secret-local-path");
        let policy = write_update_policy_fixture(&home, false);
        let policy_path = policy.to_str().expect("policy path");

        let output = run(["update", "check", "--policy-file", policy_path, "--json"]);
        let text_output = run(["update", "check", "--policy-file", policy_path]);

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(text_output.code, 0, "{}", text_output.stderr);
        assert!(
            output
                .stdout
                .contains("\"status\": \"update_policy_valid\"")
        );
        assert!(output.stdout.contains("\"version\": \"0.1.0\""));
        assert!(output.stdout.contains("\"sha256SidecarMatched\": true"));
        assert!(output.stdout.contains("\"signatureSidecarPresent\": true"));
        assert!(output.stdout.contains("\"autoApply\": false"));
        assert!(
            output
                .stdout
                .contains("\"manualVerificationRequired\": true")
        );
        assert!(output.stdout.contains("\"policyFile\": \"local\""));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(text_output.stdout.contains("local; pathDisplayed=false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains(policy_path));
        assert!(!text_output.stdout.contains(policy_path));
        assert!(!output.stdout.contains("secret-local-path"));
        assert!(!text_output.stdout.contains("secret-local-path"));
        assert!(!output.stdout.contains("BEGIN PGP SIGNATURE"));
        assert!(!text_output.stdout.contains("BEGIN PGP SIGNATURE"));
        assert!(!output.stdout.contains("private message contents"));
        assert!(!text_output.stdout.contains("private message contents"));
    }

    #[test]
    fn update_check_rejects_duplicate_policy_json_keys_without_leaking_shadow_value() {
        let home = temp_home("update-check-duplicate-policy-json");
        let policy = write_update_policy_fixture(&home, false);
        let policy_path = policy.to_str().expect("policy path");
        let shadow_value = "do-not-print-this-shadow-value";
        let mut policy_text = fs::read_to_string(&policy).expect("policy reads");
        let trimmed_len = policy_text.trim_end().len();
        policy_text.truncate(trimmed_len);
        policy_text.pop();
        policy_text.push_str(&format!(",\n  \"version\": \"{shadow_value}\"\n}}\n"));
        fs::write(&policy, policy_text.as_bytes()).expect("policy rewrite succeeds");
        let digest = sha256_hex(policy_text.as_bytes());
        fs::write(
            sidecar_path(&policy, ".sha256"),
            format!("{digest}  conu-0.1.0-update-policy.json\n"),
        )
        .expect("policy sidecar rewrite succeeds");

        let output = run(["update", "check", "--policy-file", policy_path]);

        assert_eq!(output.code, 1);
        assert!(
            output
                .stderr
                .contains("release update policy JSON is invalid")
        );
        assert!(output.stderr.contains("duplicate JSON key: version"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(!output.stderr.contains(shadow_value));
        assert!(!output.stderr.contains(policy_path));
        assert!(!output.stderr.contains("BEGIN PGP SIGNATURE"));
        assert!(!output.stderr.contains("private message contents"));
    }

    #[test]
    fn update_check_failure_redacts_local_policy_path() {
        let home = temp_home("update-check-error-secret-local-path");
        let policy = home.join("conu-0.1.0-update-policy.json");
        fs::create_dir_all(&policy).expect("policy marker dir creates");
        let policy_path = policy.to_str().expect("policy path");
        let local_path_text = home.display().to_string();

        let output = run(["update", "check", "--policy-file", policy_path]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("path is not a regular file"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(!output.stderr.contains(&local_path_text));
        assert!(!output.stderr.contains("secret-local-path"));
        assert!(!output.stderr.contains(policy_path));
        assert!(!output.stderr.contains("BEGIN PGP SIGNATURE"));
        assert!(!output.stderr.contains("private message contents"));
    }

    #[test]
    fn update_check_validates_downloaded_remote_policy_metadata_without_payloads() {
        let home = temp_home("update-remote-check");
        let policy = write_update_policy_fixture(&home, false);
        let sidecar = sidecar_path(&policy, ".sha256");
        let signature = sidecar_path(&policy, ".asc");
        let download = temp_home("update-remote-download");
        let policy_url = "https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu-0.1.0-update-policy.json";
        let sha256_url = format!("{policy_url}.sha256");
        let signature_url = format!("{policy_url}.asc");
        let policy_name = asset_name_from_update_url(policy_url, "policy-url").expect("asset name");
        let downloaded_policy = write_downloaded_update_file(
            &download,
            &policy_name,
            &fs::read(&policy).expect("policy reads"),
        )
        .expect("downloaded policy writes");
        let downloaded_sidecar = write_downloaded_update_file(
            &download,
            &format!("{policy_name}.sha256"),
            &fs::read(&sidecar).expect("sidecar reads"),
        )
        .expect("downloaded sidecar writes");
        let downloaded_signature = write_downloaded_update_file(
            &download,
            &format!("{policy_name}.asc"),
            &fs::read(&signature).expect("signature reads"),
        )
        .expect("downloaded signature writes");

        let report = check_release_update_policy_files(
            UpdateCheckFiles {
                policy_file: downloaded_policy,
                sha256_file: downloaded_sidecar,
                signature_file: downloaded_signature,
                source: UpdateCheckSource::Remote,
                policy_location: policy_url.to_string(),
                sha256_location: sha256_url,
                signature_location: signature_url,
            },
            false,
        )
        .expect("remote policy validates");
        let rendered = render_update_check_json(&report);

        assert!(rendered.contains("\"source\": \"remote\""));
        assert!(rendered.contains("\"policyUrl\": \"https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu-0.1.0-update-policy.json\""));
        assert!(rendered.contains("\"sha256SidecarMatched\": true"));
        assert!(rendered.contains("\"signatureSidecarPresent\": true"));
        assert!(!rendered.contains(&download.display().to_string()));
        assert!(!rendered.contains("BEGIN PGP SIGNATURE"));
        assert!(!rendered.contains("private message contents"));
    }

    #[test]
    fn update_check_rejects_unsafe_remote_policy_url() {
        let output = run([
            "update",
            "check",
            "--policy-url",
            "https://127.0.0.1/conu-0.1.0-update-policy.json",
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("host must be public"));
    }

    #[test]
    fn update_check_rejects_malformed_remote_policy_url_authorities() {
        for url in [
            "https://github.com:/conu-0.1.0-update-policy.json",
            "https://github.com:bad/conu-0.1.0-update-policy.json",
            "https://github.com:443x/conu-0.1.0-update-policy.json",
            "https://:443/conu-0.1.0-update-policy.json",
            "https://github.com%20.evil/conu-0.1.0-update-policy.json",
            "https://github.com%40evil.test/conu-0.1.0-update-policy.json",
            "https://github.com\\evil.test/conu-0.1.0-update-policy.json",
        ] {
            let output = run(["update", "check", "--policy-url", url]);

            assert_eq!(output.code, 1, "{url}: {}", output.stderr);
            assert!(
                output.stderr.contains("authority is invalid"),
                "{url}: {}",
                output.stderr
            );
            assert!(!output.stderr.contains("private message contents"));
        }
    }

    #[test]
    fn update_policy_metadata_url_validation_rejects_malformed_authorities() {
        for url in [
            "https://github.com:/releases/download/v0.1.0",
            "https://github.com:bad/releases/download/v0.1.0",
            "https://github.com:443x/releases/download/v0.1.0",
            "https://:443/releases/download/v0.1.0",
            "https://github.com%20.evil/releases/download/v0.1.0",
            "https://github.com%40evil.test/releases/download/v0.1.0",
            "https://github.com\\evil.test/releases/download/v0.1.0",
        ] {
            let error =
                validate_public_https_url(url, "releaseBaseUrl").expect_err("URL should fail");
            assert!(error.contains("authority is invalid"), "{url}: {error}");
        }
    }

    #[test]
    fn update_check_rejects_traversal_shaped_remote_policy_url_paths() {
        for (url, expected) in [
            (
                "https://github.com/imthegoodboy/conU/releases/download/../conu-0.1.0-update-policy.json",
                "path must not contain dot segments",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/%2e%2e/conu-0.1.0-update-policy.json",
                "path must not contain dot segments",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/v0.1.0%2fother/conu-0.1.0-update-policy.json",
                "path must not contain encoded separators",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/v0.1.0%5cother/conu-0.1.0-update-policy.json",
                "path must not contain encoded separators",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/bad%zz/conu-0.1.0-update-policy.json",
                "URL is invalid",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/v0.1.0/%00/conu-0.1.0-update-policy.json",
                "whitespace or control characters",
            ),
        ] {
            let output = run(["update", "check", "--policy-url", url]);

            assert_eq!(output.code, 1, "{url}: {}", output.stderr);
            assert!(output.stderr.contains(expected), "{url}: {}", output.stderr);
            assert!(!output.stderr.contains("private message contents"));
        }
    }

    #[test]
    fn update_policy_metadata_url_validation_rejects_traversal_shaped_paths() {
        for (url, expected) in [
            (
                "https://github.com/imthegoodboy/conU/releases/download/../v0.1.0",
                "path must not contain dot segments",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/%2e%2e/v0.1.0",
                "path must not contain dot segments",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/v0.1.0%2fother",
                "path must not contain encoded separators",
            ),
            (
                "https://github.com/imthegoodboy/conU/releases/download/v0.1.0/%00",
                "whitespace or control characters",
            ),
        ] {
            let error =
                validate_public_https_url(url, "releaseBaseUrl").expect_err("URL should fail");
            assert!(error.contains(expected), "{url}: {error}");
        }
    }

    #[test]
    fn update_check_rejects_non_public_ipv6_remote_policy_urls() {
        for host in [
            "[fc00::1]",
            "[fd12:3456:789a::1]",
            "[fe80::1]",
            "[fec0::1]",
            "[2001:db8::1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:10.0.0.1]",
            "[::127.0.0.1]",
        ] {
            let url = format!("https://{host}/conu-0.1.0-update-policy.json");
            let output = run(["update", "check", "--policy-url", url.as_str()]);

            assert_eq!(output.code, 1, "{host}: {}", output.stderr);
            assert!(output.stderr.contains("host must be public"));
            assert!(!output.stderr.contains("private message contents"));
        }
    }

    #[test]
    fn update_public_ip_filter_rejects_non_global_special_ranges() {
        for value in [
            "0.1.2.3",
            "100.64.0.1",
            "192.0.0.1",
            "192.88.99.1",
            "198.18.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "fe80::1",
            "fec0::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff",
            "5f00::1",
            "64:ff9b:1::1",
            "64:ff9b::10.0.0.1",
            "2002::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::10.0.0.1",
        ] {
            let ip = value.parse::<IpAddr>().expect("test IP parses");
            assert!(!is_public_ip(ip), "{value} should be non-public");
        }

        for value in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
            "64:ff9b::8.8.8.8",
            "::8.8.8.8",
        ] {
            let ip = value.parse::<IpAddr>().expect("test IP parses");
            assert!(is_public_ip(ip), "{value} should be public");
        }
    }

    #[test]
    fn update_check_rejects_mixed_local_and_remote_sources() {
        let output = run([
            "update",
            "check",
            "--policy-file",
            "dist/conu-0.1.0-update-policy.json",
            "--policy-url",
            "https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu-0.1.0-update-policy.json",
        ]);

        assert_eq!(output.code, 2);
    }

    #[cfg(unix)]
    #[test]
    fn update_check_rejects_symlinked_policy_file_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-check-symlink-policy");
        let target = home.join("outside-policy-target");
        let policy = home.join("conu-0.1.0-update-policy.json");
        fs::create_dir_all(&home).expect("home creates");
        fs::write(&target, b"private message contents").expect("target writes");
        symlink(&target, &policy).expect("policy symlink creates");

        let output = run([
            "update",
            "check",
            "--policy-file",
            policy.to_str().expect("policy path"),
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("path is not a regular file"));
        assert!(!output.stderr.contains("private message contents"));
        assert!(
            fs::symlink_metadata(&policy)
                .expect("policy symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_downloaded_metadata_write_rejects_existing_file_without_overwrite() {
        let download_dir = temp_home("update-downloaded-metadata-existing");
        fs::create_dir_all(&download_dir).expect("download dir creates");
        let filename = "conu-0.1.0-update-policy.json";
        let existing = download_dir.join(filename);
        fs::write(&existing, b"existing policy metadata").expect("existing metadata writes");

        let error = write_downloaded_update_file(&download_dir, filename, b"new metadata")
            .expect_err("existing downloaded metadata should fail closed");

        assert!(error.contains("downloaded release update policy file already exists"));
        assert_eq!(
            fs::read(&existing).expect("existing metadata reads"),
            b"existing policy metadata"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_downloaded_metadata_write_rejects_symlink_target_without_writing_target() {
        use std::os::unix::fs::symlink;

        let download_dir = temp_home("update-downloaded-metadata-symlink");
        fs::create_dir_all(&download_dir).expect("download dir creates");
        let filename = "conu-0.1.0-update-policy.json";
        let target = download_dir.join(filename);
        let outside_target = download_dir.join("outside-metadata-target");
        symlink(&outside_target, &target).expect("metadata symlink creates");

        let error = write_downloaded_update_file(&download_dir, filename, b"new metadata")
            .expect_err("symlink downloaded metadata should fail closed");

        assert!(error.contains("downloaded release update policy file already exists"));
        assert!(!outside_target.exists());
        assert!(
            fs::symlink_metadata(&target)
                .expect("metadata symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_download_verifies_selected_platform_artifact_without_payloads() {
        let artifact_bytes = b"public conU release archive bytes";
        let artifact_sha = sha256_hex(artifact_bytes);
        let home = temp_home("update-download");
        let policy = write_update_policy_fixture_with_asset_sha(&home, false, &artifact_sha);
        let validated = validate_release_update_policy(&UpdateCheckArgs {
            policy_file: Some(policy),
            policy_url: None,
            sha256_file: None,
            sha256_url: None,
            signature_file: None,
            signature_url: None,
            gpg_verify: false,
            json: true,
        })
        .expect("policy validates");
        let asset =
            select_update_platform_archive(&validated.policy, "linux-x64").expect("asset selects");
        let output_dir = temp_home("update-download-secret-local-path");
        let output_dir_text = output_dir.display().to_string();
        let sha256_bytes = format!("{artifact_sha}  {}\n", asset.filename);
        let signature_bytes =
            b"-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n";
        let files = write_verified_update_artifact_files(
            &asset,
            artifact_bytes,
            sha256_bytes.as_bytes(),
            signature_bytes,
            &output_dir,
            false,
        )
        .expect("artifact writes");
        let report = UpdateArtifactDownloadReport {
            policy: validated.report,
            target: asset.target,
            filename: asset.filename,
            url: asset.url,
            artifact_file: files.artifact_file.clone(),
            sha256_file: files.sha256_file,
            signature_file: files.signature_file,
            bytes: files.bytes,
            sha256: artifact_sha,
            gpg_verified: false,
        };
        let rendered = render_update_download_json(&report);
        let rendered_text = render_update_download_text(&report);

        assert_eq!(
            fs::read(&files.artifact_file).expect("artifact reads"),
            artifact_bytes
        );
        assert!(rendered.contains("\"status\": \"update_artifact_downloaded\""));
        assert!(rendered.contains("\"target\": \"linux-x64\""));
        assert!(rendered.contains("\"artifactFile\": \"local\""));
        assert!(rendered.contains("\"sha256File\": \"local\""));
        assert!(rendered.contains("\"signatureFile\": \"local\""));
        assert!(rendered.contains("\"pathDisplayed\": false"));
        assert!(rendered_text.contains("local; pathDisplayed=false"));
        assert!(rendered.contains("\"sha256SidecarMatched\": true"));
        assert!(rendered.contains("\"signatureSidecarPresent\": true"));
        assert!(rendered.contains("\"updateApplied\": false"));
        assert!(rendered.contains("\"contentsDisplayed\": false"));
        assert!(!rendered.contains(&output_dir_text));
        assert!(!rendered_text.contains(&output_dir_text));
        assert!(!rendered.contains("secret-local-path"));
        assert!(!rendered_text.contains("secret-local-path"));
        assert!(!rendered.contains("BEGIN PGP SIGNATURE"));
        assert!(!rendered_text.contains("BEGIN PGP SIGNATURE"));
        assert!(!rendered.contains("public conU release archive bytes"));
        assert!(!rendered_text.contains("public conU release archive bytes"));
        assert!(!rendered.contains("private message contents"));
        assert!(!rendered_text.contains("private message contents"));
    }

    #[test]
    fn update_download_rejects_checksum_drift_before_output() {
        let expected_bytes = b"expected public release archive";
        let expected_sha = sha256_hex(expected_bytes);
        let home = temp_home("update-download-drift");
        let policy = write_update_policy_fixture_with_asset_sha(&home, false, &expected_sha);
        let validated = validate_release_update_policy(&UpdateCheckArgs {
            policy_file: Some(policy),
            policy_url: None,
            sha256_file: None,
            sha256_url: None,
            signature_file: None,
            signature_url: None,
            gpg_verify: false,
            json: false,
        })
        .expect("policy validates");
        let asset =
            select_update_platform_archive(&validated.policy, "linux-x64").expect("asset selects");
        let output_dir = temp_home("update-download-drift-output");
        let signature_bytes =
            b"-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n";
        let err = write_verified_update_artifact_files(
            &asset,
            b"tampered public release archive",
            format!("{expected_sha}  {}\n", asset.filename).as_bytes(),
            signature_bytes,
            &output_dir,
            false,
        )
        .expect_err("checksum drift rejects");

        assert!(err.contains("SHA-256 did not match policy"));
        assert!(!output_dir.exists());
    }

    #[test]
    fn update_download_rejects_existing_sidecar_before_partial_output() {
        let artifact_bytes = b"public conU release archive bytes";
        let artifact_sha = sha256_hex(artifact_bytes);
        let home = temp_home("update-download-existing-sidecar");
        let policy = write_update_policy_fixture_with_asset_sha(&home, false, &artifact_sha);
        let validated = validate_release_update_policy(&UpdateCheckArgs {
            policy_file: Some(policy),
            policy_url: None,
            sha256_file: None,
            sha256_url: None,
            signature_file: None,
            signature_url: None,
            gpg_verify: false,
            json: false,
        })
        .expect("policy validates");
        let asset =
            select_update_platform_archive(&validated.policy, "linux-x64").expect("asset selects");
        let output_dir = temp_home("update-download-existing-sidecar-output");
        fs::create_dir_all(&output_dir).expect("output dir writes");
        let existing_sidecar = output_dir.join(format!("{}.sha256", asset.filename));
        fs::write(&existing_sidecar, "existing").expect("existing sidecar writes");
        let signature_bytes =
            b"-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n";
        let err = write_verified_update_artifact_files(
            &asset,
            artifact_bytes,
            format!("{artifact_sha}  {}\n", asset.filename).as_bytes(),
            signature_bytes,
            &output_dir,
            false,
        )
        .expect_err("existing output rejects");

        assert!(err.contains("output already exists"));
        assert!(!output_dir.join(&asset.filename).exists());
        assert!(existing_sidecar.exists());
    }

    #[test]
    fn update_download_output_write_rejects_existing_file_without_overwrite() {
        let output_dir = temp_home("update-download-existing-output");
        fs::create_dir_all(&output_dir).expect("output dir creates");
        let filename = "conu-0.1.0-linux-x64.tar.gz";
        let existing = output_dir.join(filename);
        fs::write(&existing, b"existing public archive").expect("existing output writes");

        let error = write_update_output_file(&output_dir, filename, b"new archive", "archive")
            .expect_err("existing output should fail closed");

        assert!(error.contains("output already exists"));
        assert_eq!(
            fs::read(&existing).expect("existing output reads"),
            b"existing public archive"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_download_output_write_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let output_dir = temp_home("update-download-output-symlink");
        fs::create_dir_all(&output_dir).expect("output dir creates");
        let filename = "conu-0.1.0-linux-x64.tar.gz";
        let outside = output_dir.join("outside-archive");
        let output = output_dir.join(filename);
        fs::write(&outside, b"existing outside archive").expect("outside writes");
        symlink(&outside, &output).expect("output symlink creates");

        let error = write_update_output_file(&output_dir, filename, b"new archive", "archive")
            .expect_err("symlink output should fail closed");

        assert!(error.contains("output already exists"));
        assert_eq!(
            fs::read(&outside).expect("outside reads"),
            b"existing outside archive"
        );
        assert!(
            fs::symlink_metadata(&output)
                .expect("output symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_download_output_write_rejects_symlinked_output_directory() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-download-output-dir-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let outside = home.join("outside");
        fs::create_dir_all(&outside).expect("outside dir creates");
        let output_dir = home.join("output");
        symlink(&outside, &output_dir).expect("output dir symlink creates");

        let error = write_update_output_file(
            &output_dir,
            "conu-0.1.0-linux-x64.tar.gz",
            b"new archive",
            "archive",
        )
        .expect_err("symlinked output directory should fail closed");

        assert!(error.contains("output directory is not a directory"));
        assert_eq!(
            fs::read_dir(&outside).expect("outside dir reads").count(),
            0
        );
        assert!(
            fs::symlink_metadata(&output_dir)
                .expect("output dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_download_requires_output_dir() {
        let output = run([
            "update",
            "download",
            "--policy-file",
            "dist/conu-0.1.0-update-policy.json",
        ]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("conu update download"));
    }

    #[test]
    fn update_failure_redacts_local_paths_without_hiding_public_urls() {
        let error = concat!(
            r#"release update install-dir is not a directory: C:\secret-local-path\bin"#,
            "\n",
            "downloaded https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu.zip ",
            "into /tmp/secret-local-path/conu.tar.gz",
            "\n",
            "relative dist/secret-local-path/conu.zip failed"
        );
        let redacted = redact_update_failure_paths(error);

        assert!(
            redacted
                .contains("https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu.zip")
        );
        assert!(redacted.contains("local; pathDisplayed=false"));
        assert!(!redacted.contains("secret-local-path"));
        assert!(!redacted.contains(r#"C:\"#));
        assert!(!redacted.contains("/tmp/"));
        assert!(!redacted.contains("dist/"));
    }

    #[test]
    fn update_apply_dry_run_validates_archive_without_installing() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let archive_bytes = update_archive_fixture_bytes(&target, false);
        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-secret-local-path");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let install_dir = home.join("install-bin");
        let local_path_text = home.display().to_string();

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--dry-run",
            "--json",
        ]);
        let text_output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--dry-run",
        ]);

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(text_output.code, 0, "{}", text_output.stderr);
        assert!(output.stdout.contains("\"status\": \"update_apply_ready\""));
        assert!(output.stdout.contains("\"archiveFile\": \"local\""));
        assert!(output.stdout.contains("\"installDir\": \"local\""));
        assert!(output.stdout.contains("\"backupDir\": null"));
        assert!(output.stdout.contains("\"targetFile\": \"local\""));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(text_output.stdout.contains("local; pathDisplayed=false"));
        assert!(output.stdout.contains("\"dryRun\": true"));
        assert!(output.stdout.contains("\"updateApplied\": false"));
        assert!(output.stdout.contains("\"sha256SidecarMatched\": true"));
        assert!(output.stdout.contains("\"signatureSidecarPresent\": true"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains(&local_path_text));
        assert!(!text_output.stdout.contains(&local_path_text));
        assert!(!output.stdout.contains("secret-local-path"));
        assert!(!text_output.stdout.contains("secret-local-path"));
        assert!(!output.stdout.contains("fixture binary bytes"));
        assert!(!text_output.stdout.contains("fixture binary bytes"));
        assert!(!output.stdout.contains("BEGIN PGP SIGNATURE"));
        assert!(!text_output.stdout.contains("BEGIN PGP SIGNATURE"));
        assert!(!install_dir.exists());
    }

    #[test]
    fn update_apply_failure_redacts_install_dir_path() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let archive_bytes = update_archive_fixture_bytes(&target, false);
        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-error-secret-local-path");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let install_dir = home.join("install-bin");
        fs::write(&install_dir, b"not a directory").expect("install marker writes");
        let local_path_text = home.display().to_string();

        let output = run(vec![
            "update".to_string(),
            "apply".to_string(),
            "--policy-file".to_string(),
            policy.to_str().expect("policy path").to_string(),
            "--artifact-file".to_string(),
            artifact.to_str().expect("artifact path").to_string(),
            "--install-dir".to_string(),
            install_dir.to_str().expect("install path").to_string(),
            "--dry-run".to_string(),
            "--target".to_string(),
            target,
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("install-dir is not a directory"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(!output.stderr.contains(&local_path_text));
        assert!(!output.stderr.contains("secret-local-path"));
        assert!(!output.stderr.contains("fixture binary bytes"));
        assert!(!output.stderr.contains("BEGIN PGP SIGNATURE"));
    }

    #[test]
    fn update_apply_rejects_duplicate_archive_manifest_keys_without_values() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let secret_target = "secret-local-target";
        let duplicate_target_manifest = format!(
            "version = \"0.1.0\"\ntarget = \"{target}\"\ntarget = \"{secret_target}\"\npayload_contents_included = false\n"
        );
        let duplicate_target_archive =
            update_archive_fixture_bytes_with_manifest(&target, &duplicate_target_manifest);

        let duplicate_target_error =
            stage_update_archive_binaries(&filename, &duplicate_target_archive, &target)
                .expect_err("duplicate manifest target should fail closed");

        assert!(duplicate_target_error.contains("duplicate key target"));
        assert!(!duplicate_target_error.contains(secret_target));

        let duplicate_payload_manifest = format!(
            "version = \"0.1.0\"\ntarget = \"{target}\"\npayload_contents_included = false\npayload_contents_included = true\n"
        );
        let duplicate_payload_archive =
            update_archive_fixture_bytes_with_manifest(&target, &duplicate_payload_manifest);

        let duplicate_payload_error =
            stage_update_archive_binaries(&filename, &duplicate_payload_archive, &target)
                .expect_err("duplicate payload guard should fail closed");

        assert!(duplicate_payload_error.contains("duplicate key payload_contents_included"));
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_dry_run_rejects_symlinked_install_dir_without_installing() {
        use std::os::unix::fs::symlink;

        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let archive_bytes = update_archive_fixture_bytes(&target, false);
        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-dry-run-install-dir-symlink");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let outside = home.join("outside-install");
        fs::create_dir_all(&outside).expect("outside install dir creates");
        let install_dir = home.join("install-bin");
        symlink(&outside, &install_dir).expect("install dir symlink creates");

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--dry-run",
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("install-dir is not a directory"));
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside install dir reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&install_dir)
                .expect("install dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_confirm_installs_expected_binaries_and_backup() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let archive_bytes = update_archive_fixture_bytes(&target, false);
        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-confirm-secret-local-path");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let install_dir = home.join("install-bin");
        let local_path_text = home.display().to_string();
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let existing_conu = install_dir.join(update_binary_filename("conu"));
        fs::write(&existing_conu, b"old conu binary").expect("existing binary writes");

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--confirm",
            "--json",
        ]);

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"update_applied\""));
        assert!(output.stdout.contains("\"updateApplied\": true"));
        assert!(output.stdout.contains("\"dryRun\": false"));
        assert!(output.stdout.contains("\"archiveFile\": \"local\""));
        assert!(output.stdout.contains("\"installDir\": \"local\""));
        assert!(output.stdout.contains("\"backupDir\": \"local\""));
        assert!(output.stdout.contains("\"targetFile\": \"local\""));
        assert!(output.stdout.contains("\"backupFile\": \"local\""));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        for name in UPDATE_BINARY_NAMES {
            let installed = install_dir.join(update_binary_filename(name));
            assert_eq!(
                fs::read(&installed).expect("installed binary reads"),
                update_archive_binary_bytes(name)
            );
        }
        let backup_root = install_dir.join(".conu-update-backups");
        let backups = fs::read_dir(&backup_root)
            .expect("backup root exists")
            .collect::<Result<Vec<_>, _>>()
            .expect("backup entries read");
        assert_eq!(backups.len(), 1);
        let backed_up_conu = backups[0].path().join(update_binary_filename("conu"));
        assert_eq!(
            fs::read(backed_up_conu).expect("backup reads"),
            b"old conu binary"
        );
        assert!(!output.stdout.contains(&local_path_text));
        assert!(!output.stdout.contains("secret-local-path"));
        assert!(!output.stdout.contains("old conu binary"));
        assert!(!output.stdout.contains("fixture binary bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_confirm_rejects_symlinked_install_dir_without_writing_target() {
        use std::os::unix::fs::symlink;

        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let archive_bytes = update_archive_fixture_bytes(&target, false);
        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-confirm-install-dir-symlink");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let outside = home.join("outside-install");
        fs::create_dir_all(&outside).expect("outside install dir creates");
        let install_dir = home.join("install-bin");
        symlink(&outside, &install_dir).expect("install dir symlink creates");

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--confirm",
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("install-dir is not a directory"));
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside install dir reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&install_dir)
                .expect("install dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_backup_dir_skips_existing_candidate() {
        let home = temp_home("update-apply-backup-dir");
        let install_dir = home.join("install-bin");
        let stale = install_dir.join(".conu-update-backups").join("0.1.0-42-0");
        fs::create_dir_all(&stale).expect("stale backup dir creates");

        let created = create_update_apply_backup_dir_with_nonce(&install_dir, "0.1.0", 42)
            .expect("unique backup dir creates");

        assert_ne!(created, stale);
        assert_eq!(
            created.file_name().and_then(|value| value.to_str()),
            Some("0.1.0-42-1")
        );
        assert!(created.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_backup_dir_rejects_symlinked_backup_root() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-backup-root-symlink");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let outside = home.join("outside-backups");
        fs::create_dir_all(&outside).expect("outside backup dir creates");
        let backup_root = install_dir.join(".conu-update-backups");
        symlink(&outside, &backup_root).expect("backup root symlink creates");

        let error = create_update_apply_backup_dir_with_nonce(&install_dir, "0.1.0", 42)
            .expect_err("symlinked backup root should fail closed");

        assert!(error.contains("release update backup root is not a directory"));
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside backup dir reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&backup_root)
                .expect("backup root symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_install_rejects_symlinked_backup_dir_without_writing_outside() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-backup-dir-symlink");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let target_file = install_dir.join(&filename);
        fs::write(&target_file, b"current binary").expect("target writes");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"new conu binary").expect("source binary writes");
        let backup_root = install_dir.join(".conu-update-backups");
        fs::create_dir_all(&backup_root).expect("backup root creates");
        let outside = home.join("outside-backup-dir");
        fs::create_dir_all(&outside).expect("outside backup dir creates");
        let backup_dir = backup_root.join("swapped");
        symlink(&outside, &backup_dir).expect("backup dir symlink creates");
        let staged = StagedUpdateBinary {
            name: "conu".to_string(),
            source_file,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let error = install_staged_update_binaries(&[staged], &install_dir, Some(&backup_dir))
            .expect_err("symlinked backup dir should fail closed");

        assert!(error.contains("release update backup directory is not a directory"));
        assert_eq!(
            fs::read(&target_file).expect("target remains readable"),
            b"current binary"
        );
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside backup dir reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&backup_dir)
                .expect("backup dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_temp_install_target_skips_existing_candidate() {
        let home = temp_home("update-apply-temp-target");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let stale = install_dir.join(format!(".{filename}.conu-update-new-42-0"));
        fs::write(&stale, b"stale temp target").expect("stale temp target writes");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"new conu binary").expect("source binary writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let created = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect("unique temp target creates");

        let expected_name = format!(".{filename}.conu-update-new-42-1");
        assert_ne!(created, stale);
        assert_eq!(
            created.file_name().and_then(|value| value.to_str()),
            Some(expected_name.as_str())
        );
        assert_eq!(
            fs::read(&created).expect("created temp target reads"),
            b"new conu binary"
        );
        assert_eq!(
            fs::read(&stale).expect("stale temp target reads"),
            b"stale temp target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_temp_install_target_rejects_symlinked_install_parent_without_writing_outside() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-temp-install-parent-symlink");
        let outside = home.join("outside-install");
        fs::create_dir_all(&outside).expect("outside install dir creates");
        let install_dir = home.join("install-bin");
        symlink(&outside, &install_dir).expect("install dir symlink creates");
        let filename = update_binary_filename("conu");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"new conu binary").expect("source binary writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let error = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect_err("symlinked install parent should fail closed");

        assert!(error.contains("release update install-dir is not a directory"));
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside install dir reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&install_dir)
                .expect("install dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_temp_install_target_sets_executable_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let home = temp_home("update-apply-temp-target-permissions");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"new conu binary").expect("source binary writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let created = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect("temp target creates");

        let mode = fs::metadata(&created)
            .expect("created temp target metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn update_apply_temp_install_target_verify_accepts_created_target() {
        let home = temp_home("update-apply-temp-target-verify-accepts");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"new conu binary").expect("source binary writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };
        let created = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect("temp target creates");

        verify_update_temp_install_target(&report, &created).expect("created temp target verifies");
    }

    #[test]
    fn update_apply_temp_install_target_verify_rejects_same_length_replacement() {
        let home = temp_home("update-apply-temp-target-verify-replacement");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"new conu binary").expect("source binary writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };
        let created = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect("temp target creates");
        fs::remove_file(&created).expect("temp target removes");
        fs::write(&created, b"bad conu binary").expect("replacement temp target writes");

        let error = verify_update_temp_install_target(&report, &created)
            .expect_err("same-length temp target replacement should fail closed");

        assert!(
            error.contains("release update temporary install target changed before installing")
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_permission_setter_uses_open_file_handle_not_path() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let home = temp_home("update-apply-permissions-handle");
        fs::create_dir_all(&home).expect("home creates");
        let actual = home.join("actual-binary");
        let outside = home.join("outside-binary");
        let symlink_path = home.join("symlink-path");
        fs::write(&actual, b"actual").expect("actual writes");
        fs::write(&outside, b"outside").expect("outside writes");
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o600))
            .expect("actual permissions set");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))
            .expect("outside permissions set");
        symlink(&outside, &symlink_path).expect("symlink creates");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&actual)
            .expect("actual opens");

        set_update_binary_file_permissions(&file, &symlink_path)
            .expect("permissions set through file handle");

        let actual_mode = fs::metadata(&actual)
            .expect("actual metadata")
            .permissions()
            .mode()
            & 0o777;
        let outside_mode = fs::metadata(&outside)
            .expect("outside metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(actual_mode, 0o755);
        assert_eq!(outside_mode, 0o600);
        assert!(
            fs::symlink_metadata(&symlink_path)
                .expect("symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_temp_install_target_rejects_same_length_source_tamper() {
        let home = temp_home("update-apply-temp-source-tamper");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"bad conu binary").expect("tampered source writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let error = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect_err("same-length staged source tamper should fail closed");

        assert!(error.contains("release update staged binary changed while preparing"));
        let entries = fs::read_dir(&install_dir)
            .expect("install dir reads")
            .collect::<Result<Vec<_>, _>>()
            .expect("install entries read");
        assert!(entries.is_empty());
    }

    #[test]
    fn update_apply_temp_install_target_rejects_directory_source() {
        let home = temp_home("update-apply-temp-directory-source");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let source_file = home.join("staged").join(&filename);
        fs::create_dir_all(&source_file).expect("directory source creates");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let error = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect_err("directory staged source should fail closed");

        assert!(error.contains("release update staged binary path is not a regular file"));
        let entries = fs::read_dir(&install_dir)
            .expect("install dir reads")
            .collect::<Result<Vec<_>, _>>()
            .expect("install entries read");
        assert!(entries.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_temp_install_target_rejects_symlink_source_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-temp-symlink-source");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        let outside_source = home.join("outside-staged-source");
        fs::write(&outside_source, b"new conu binary").expect("outside source writes");
        symlink(&outside_source, &source_file).expect("source symlink creates");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file: source_file.clone(),
            target_file: install_dir.join(&filename),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let error = create_update_temp_install_target(&report, &install_dir, &filename, 42)
            .expect_err("symlink staged source should fail closed");

        assert!(error.contains("release update staged binary path is not a regular file"));
        assert_eq!(
            fs::read(&outside_source).expect("outside source reads"),
            b"new conu binary"
        );
        assert!(
            fs::symlink_metadata(&source_file)
                .expect("source symlink metadata")
                .file_type()
                .is_symlink()
        );
        let entries = fs::read_dir(&install_dir)
            .expect("install dir reads")
            .collect::<Result<Vec<_>, _>>()
            .expect("install entries read");
        assert!(entries.is_empty());
    }

    #[test]
    fn update_apply_staged_binary_rejects_existing_path_without_overwrite() {
        let home = temp_home("update-apply-existing-staged");
        fs::create_dir_all(&home).expect("staging dir creates");
        let staged = home.join(update_binary_filename("conu"));
        fs::write(&staged, b"existing staged binary").expect("existing staged file writes");
        let mut reader = &b"new staged binary"[..];

        let error = write_update_staged_binary(
            &staged,
            &mut reader,
            b"new staged binary".len() as u64,
            "conu-0.1.0-linux-x64.tar.gz",
            "conu",
        )
        .expect_err("existing staged path should fail closed");

        assert!(error.contains("could not stage conu"));
        assert_eq!(
            fs::read(&staged).expect("existing staged file reads"),
            b"existing staged binary"
        );
    }

    #[test]
    fn update_apply_final_replacement_rejects_directory_target() {
        let home = temp_home("update-apply-final-directory-target");
        let install_dir = home.join("install-bin");
        let target_file = install_dir.join(update_binary_filename("conu"));
        fs::create_dir_all(&target_file).expect("directory target creates");

        let error = remove_existing_update_install_target(&target_file)
            .expect_err("directory final install target should fail closed");

        assert!(error.contains("release update install target is not a regular file"));
        assert!(target_file.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_final_replacement_rejects_symlink_target_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-final-symlink-target");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        let outside_target = home.join("outside-final-target");
        symlink(&outside_target, &target_file).expect("target symlink creates");

        let error = remove_existing_update_install_target(&target_file)
            .expect_err("symlink final install target should fail closed");

        assert!(error.contains("release update install target is not a regular file"));
        assert!(!outside_target.exists());
        assert!(
            fs::symlink_metadata(&target_file)
                .expect("target symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_final_replacement_rejects_symlinked_install_parent_without_removing_outside() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-final-parent-symlink");
        let outside = home.join("outside-install");
        fs::create_dir_all(&outside).expect("outside install dir creates");
        let filename = update_binary_filename("conu");
        let outside_target = outside.join(&filename);
        fs::write(&outside_target, b"outside binary").expect("outside binary writes");
        let install_dir = home.join("install-bin");
        symlink(&outside, &install_dir).expect("install dir symlink creates");
        let target_file = install_dir.join(&filename);

        let error = remove_existing_update_install_target(&target_file)
            .expect_err("symlinked install parent should fail closed");

        assert!(error.contains("release update install-dir is not a directory"));
        assert_eq!(
            fs::read(&outside_target).expect("outside target remains readable"),
            b"outside binary"
        );
        assert!(
            fs::symlink_metadata(&install_dir)
                .expect("install dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_backup_rejects_unplanned_existing_target() {
        let home = temp_home("update-apply-backup-unplanned-target");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let target_file = install_dir.join(&filename);
        fs::write(&target_file, b"late existing target").expect("target writes");
        let source_dir = home.join("staged");
        fs::create_dir_all(&source_dir).expect("source dir creates");
        let source_file = source_dir.join(&filename);
        fs::write(&source_file, b"new conu binary").expect("source binary writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file,
            target_file: target_file.clone(),
            backup_file: None,
            bytes: b"new conu binary".len() as u64,
            sha256: sha256_hex(b"new conu binary"),
        };

        let error = back_up_existing_update_binaries(&[report])
            .expect_err("unplanned target should fail closed");

        assert!(error.contains("release update backup path was not prepared"));
        assert_eq!(
            fs::read(&target_file).expect("target remains readable"),
            b"late existing target"
        );
    }

    #[test]
    fn update_apply_backup_rejects_existing_backup_without_overwrite() {
        let home = temp_home("update-apply-existing-backup");
        let install_dir = home.join("install-bin");
        let backup_dir = install_dir.join(".conu-update-backups").join("existing");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let filename = update_binary_filename("conu");
        let target_file = install_dir.join(&filename);
        let backup_file = backup_dir.join(&filename);
        fs::write(&target_file, b"current binary").expect("target writes");
        fs::write(&backup_file, b"existing backup").expect("backup writes");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file: home.join("unused-staged"),
            target_file: target_file.clone(),
            backup_file: Some(backup_file.clone()),
            bytes: b"current binary".len() as u64,
            sha256: sha256_hex(b"current binary"),
        };

        let error = back_up_existing_update_binaries(&[report])
            .expect_err("existing backup should fail closed");

        assert!(error.contains("release update backup target already exists"));
        assert_eq!(
            fs::read(&backup_file).expect("backup remains readable"),
            b"existing backup"
        );
        assert_eq!(
            fs::read(&target_file).expect("target remains readable"),
            b"current binary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_backup_rejects_symlink_backup_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-symlink-backup");
        let install_dir = home.join("install-bin");
        let backup_dir = install_dir.join(".conu-update-backups").join("symlink");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let filename = update_binary_filename("conu");
        let target_file = install_dir.join(&filename);
        let backup_file = backup_dir.join(&filename);
        let outside_target = home.join("outside-backup-target");
        fs::write(&target_file, b"current binary").expect("target writes");
        symlink(&outside_target, &backup_file).expect("backup symlink creates");
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file: home.join("unused-staged"),
            target_file: target_file.clone(),
            backup_file: Some(backup_file.clone()),
            bytes: b"current binary".len() as u64,
            sha256: sha256_hex(b"current binary"),
        };

        let error = back_up_existing_update_binaries(&[report])
            .expect_err("symlink backup should fail closed");

        assert!(error.contains("release update backup target already exists"));
        assert!(!outside_target.exists());
        assert!(
            fs::symlink_metadata(&backup_file)
                .expect("backup symlink metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(&target_file).expect("target remains readable"),
            b"current binary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_backup_rejects_symlinked_install_parent_without_backing_up_outside() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-backup-install-parent-symlink");
        let outside = home.join("outside-install");
        fs::create_dir_all(&outside).expect("outside install dir creates");
        let filename = update_binary_filename("conu");
        let outside_target = outside.join(&filename);
        fs::write(&outside_target, b"outside binary").expect("outside target writes");
        let install_dir = home.join("install-bin");
        symlink(&outside, &install_dir).expect("install dir symlink creates");
        let backup_dir = home.join("backups").join("run");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let backup_file = backup_dir.join(&filename);
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file: home.join("unused-staged"),
            target_file: install_dir.join(&filename),
            backup_file: Some(backup_file.clone()),
            bytes: b"outside binary".len() as u64,
            sha256: sha256_hex(b"outside binary"),
        };

        let error = back_up_existing_update_binaries(&[report])
            .expect_err("symlinked install parent should fail closed");

        assert!(error.contains("release update install-dir is not a directory"));
        assert!(!backup_file.exists());
        assert_eq!(
            fs::read(&outside_target).expect("outside target remains readable"),
            b"outside binary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_backup_rejects_symlinked_backup_root_without_writing_outside() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-backup-root-swapped");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let target_file = install_dir.join(&filename);
        fs::write(&target_file, b"current binary").expect("target writes");
        let outside_root = home.join("outside-backup-root");
        let outside_run = outside_root.join("swapped");
        fs::create_dir_all(&outside_run).expect("outside backup run creates");
        let backup_root = install_dir.join(".conu-update-backups");
        symlink(&outside_root, &backup_root).expect("backup root symlink creates");
        let backup_file = backup_root.join("swapped").join(&filename);
        let report = UpdateApplyBinaryReport {
            name: "conu".to_string(),
            source_file: home.join("unused-staged"),
            target_file: target_file.clone(),
            backup_file: Some(backup_file.clone()),
            bytes: b"current binary".len() as u64,
            sha256: sha256_hex(b"current binary"),
        };

        let error = back_up_existing_update_binaries(&[report])
            .expect_err("symlinked backup root should fail closed");

        assert!(error.contains("release update backup root is not a directory"));
        assert!(!outside_run.join(&filename).exists());
        assert_eq!(
            fs::read(&target_file).expect("target remains readable"),
            b"current binary"
        );
        assert!(
            fs::symlink_metadata(&backup_root)
                .expect("backup root symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_backup_detects_source_replacement_after_open() {
        let home = temp_home("update-apply-backup-source-open-swap");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        let replacement = install_dir.join("replacement-conu");
        fs::write(&target_file, b"current binary").expect("target writes");
        fs::write(&replacement, b"changed binary").expect("replacement writes");
        let metadata = fs::symlink_metadata(&target_file).expect("target metadata");
        let source_file = fs::File::open(&target_file).expect("target opens");
        fs::rename(&replacement, &target_file).expect("target swaps");

        let error = ensure_update_install_target_unchanged_while_backing_up(
            &target_file,
            &metadata,
            &source_file,
        )
        .expect_err("swapped backup source should fail closed");

        assert!(error.contains("release update install target changed while backing up"));
        assert_eq!(
            fs::read(&target_file).expect("replacement target reads"),
            b"changed binary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_backup_detects_source_replacement_before_open() {
        let home = temp_home("update-apply-backup-source-before-open-swap");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let filename = update_binary_filename("conu");
        let target_file = install_dir.join(&filename);
        let replacement = install_dir.join("replacement-conu");
        let backup_dir = install_dir.join(".conu-update-backups").join("source-swap");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let backup_file = backup_dir.join(&filename);
        fs::write(&target_file, b"current binary").expect("target writes");
        let metadata = fs::symlink_metadata(&target_file).expect("target metadata");
        fs::write(&replacement, b"changed binary").expect("replacement writes");
        fs::rename(&replacement, &target_file).expect("target swaps");
        let source_file = fs::File::open(&target_file).expect("target opens");

        let error = ensure_update_install_target_unchanged_while_backing_up(
            &target_file,
            &metadata,
            &source_file,
        )
        .expect_err("pre-open swapped backup source should fail closed");

        assert!(error.contains("release update install target changed while backing up"));
        assert!(!backup_file.exists());
        assert_eq!(
            fs::read(&target_file).expect("replacement target reads"),
            b"changed binary"
        );
    }

    #[test]
    fn update_apply_backup_cleanup_removes_regular_backup_file() {
        let home = temp_home("update-apply-backup-cleanup-regular");
        let install_dir = home.join("install-bin");
        let backup_dir = install_dir.join(".conu-update-backups").join("cleanup");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let backup_file = backup_dir.join(update_binary_filename("conu"));
        fs::write(&backup_file, b"partial backup").expect("backup writes");

        remove_update_backup_file_if_safe(&backup_file);

        assert!(!backup_file.exists());
        assert!(backup_dir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_backup_cleanup_rejects_symlinked_backup_dir_without_removing_outside() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-backup-cleanup-symlink-dir");
        let install_dir = home.join("install-bin");
        let backup_root = install_dir.join(".conu-update-backups");
        fs::create_dir_all(&backup_root).expect("backup root creates");
        let outside = home.join("outside-backup-dir");
        fs::create_dir_all(&outside).expect("outside backup dir creates");
        let filename = update_binary_filename("conu");
        let outside_backup = outside.join(&filename);
        fs::write(&outside_backup, b"outside backup").expect("outside backup writes");
        let backup_dir = backup_root.join("cleanup");
        symlink(&outside, &backup_dir).expect("backup dir symlink creates");
        let backup_file = backup_dir.join(&filename);

        remove_update_backup_file_if_safe(&backup_file);

        assert_eq!(
            fs::read(&outside_backup).expect("outside backup remains readable"),
            b"outside backup"
        );
        assert!(
            fs::symlink_metadata(&backup_dir)
                .expect("backup dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_restore_backup_reports_missing_backup() {
        let home = temp_home("update-apply-missing-backup");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        fs::write(&target_file, b"partial update target").expect("target writes");
        let missing_backup = install_dir
            .join(".conu-update-backups")
            .join("missing-conu");

        let error = restore_update_backup(&target_file, &missing_backup)
            .expect_err("missing backup should be reported");

        assert!(error.contains("could not inspect release update backup file"));
        assert_eq!(
            fs::read(&target_file).expect("target remains readable"),
            b"partial update target"
        );
    }

    #[test]
    fn update_apply_restore_backup_rejects_directory_backup_without_writing_target() {
        let home = temp_home("update-apply-directory-restore-backup");
        let install_dir = home.join("install-bin");
        let backup_dir = install_dir.join(".conu-update-backups").join("restore");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        let backup_file = backup_dir.join(update_binary_filename("conu"));
        fs::create_dir_all(&backup_file).expect("directory backup creates");

        let error = restore_update_backup(&target_file, &backup_file)
            .expect_err("directory backup should fail closed");

        assert!(error.contains("release update backup file is not a regular file"));
        assert!(!target_file.exists());
        assert!(backup_file.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_restore_backup_rejects_symlink_backup_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-symlink-restore-backup");
        let install_dir = home.join("install-bin");
        let backup_dir = install_dir.join(".conu-update-backups").join("restore");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        let backup_file = backup_dir.join(update_binary_filename("conu"));
        let outside_backup = home.join("outside-restore-backup");
        fs::write(&outside_backup, b"backup binary").expect("outside backup writes");
        symlink(&outside_backup, &backup_file).expect("backup symlink creates");

        let error = restore_update_backup(&target_file, &backup_file)
            .expect_err("symlink backup should fail closed");

        assert!(error.contains("release update backup file is not a regular file"));
        assert!(!target_file.exists());
        assert_eq!(
            fs::read(&outside_backup).expect("outside backup reads"),
            b"backup binary"
        );
        assert!(
            fs::symlink_metadata(&backup_file)
                .expect("backup symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_restore_backup_rejects_symlinked_backup_dir_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-symlink-restore-backup-dir");
        let install_dir = home.join("install-bin");
        fs::create_dir_all(&install_dir).expect("install dir creates");
        let backup_root = install_dir.join(".conu-update-backups");
        fs::create_dir_all(&backup_root).expect("backup root creates");
        let outside_backup_dir = home.join("outside-restore-backup-dir");
        fs::create_dir_all(&outside_backup_dir).expect("outside backup dir creates");
        let backup_dir = backup_root.join("restore");
        symlink(&outside_backup_dir, &backup_dir).expect("backup dir symlink creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        let backup_file = backup_dir.join(update_binary_filename("conu"));
        let outside_backup = outside_backup_dir.join(update_binary_filename("conu"));
        fs::write(&outside_backup, b"backup binary").expect("outside backup writes");

        let error = restore_update_backup(&target_file, &backup_file)
            .expect_err("symlinked backup dir should fail closed");

        assert!(error.contains("release update backup directory is not a directory"));
        assert!(!target_file.exists());
        assert_eq!(
            fs::read(&outside_backup).expect("outside backup reads"),
            b"backup binary"
        );
        assert!(
            fs::symlink_metadata(&backup_dir)
                .expect("backup dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_restore_backup_rejects_existing_target_without_overwrite() {
        let home = temp_home("update-apply-existing-restore-target");
        let install_dir = home.join("install-bin");
        let backup_dir = install_dir.join(".conu-update-backups").join("restore");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        let backup_file = backup_dir.join(update_binary_filename("conu"));
        fs::write(&target_file, b"unexpected restore target").expect("target writes");
        fs::write(&backup_file, b"backup binary").expect("backup writes");

        let error = restore_update_backup(&target_file, &backup_file)
            .expect_err("existing restore target should fail closed");

        assert!(error.contains("release update restore target already exists"));
        assert_eq!(
            fs::read(&target_file).expect("target remains readable"),
            b"unexpected restore target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_restore_backup_rejects_symlink_target_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-symlink-restore-target");
        let install_dir = home.join("install-bin");
        let backup_dir = install_dir.join(".conu-update-backups").join("restore");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let target_file = install_dir.join(update_binary_filename("conu"));
        let backup_file = backup_dir.join(update_binary_filename("conu"));
        let outside_target = home.join("outside-restore-target");
        fs::write(&backup_file, b"backup binary").expect("backup writes");
        symlink(&outside_target, &target_file).expect("restore target symlink creates");

        let error = restore_update_backup(&target_file, &backup_file)
            .expect_err("symlink restore target should fail closed");

        assert!(error.contains("release update restore target already exists"));
        assert!(!outside_target.exists());
        assert!(
            fs::symlink_metadata(&target_file)
                .expect("restore symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_apply_restore_backup_rejects_symlinked_install_parent_without_writing_outside() {
        use std::os::unix::fs::symlink;

        let home = temp_home("update-apply-restore-parent-symlink");
        let outside = home.join("outside-install");
        fs::create_dir_all(&outside).expect("outside install dir creates");
        let install_dir = home.join("install-bin");
        symlink(&outside, &install_dir).expect("install dir symlink creates");
        let backup_dir = home
            .join("real-install")
            .join(".conu-update-backups")
            .join("restore");
        fs::create_dir_all(&backup_dir).expect("backup dir creates");
        let filename = update_binary_filename("conu");
        let backup_file = backup_dir.join(&filename);
        fs::write(&backup_file, b"backup binary").expect("backup writes");
        let target_file = install_dir.join(&filename);

        let error = restore_update_backup(&target_file, &backup_file)
            .expect_err("symlinked install parent should fail closed");

        assert!(error.contains("release update install-dir is not a directory"));
        assert!(!outside.join(&filename).exists());
        assert_eq!(
            fs::read(&backup_file).expect("backup remains readable"),
            b"backup binary"
        );
        assert!(
            fs::symlink_metadata(&install_dir)
                .expect("install dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn update_apply_rejects_checksum_drift_before_install() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let archive_bytes = update_archive_fixture_bytes(&target, false);
        let expected_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-drift-secret-local-path");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &expected_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, b"tampered archive bytes");
        let install_dir = home.join("install-bin");
        let local_path_text = home.display().to_string();

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--confirm",
            "--json",
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("SHA-256 did not match policy"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(!output.stderr.contains(&local_path_text));
        assert!(!output.stderr.contains("secret-local-path"));
        assert!(!output.stderr.contains("tampered archive bytes"));
        assert!(!output.stderr.contains("BEGIN PGP SIGNATURE"));
        assert!(!install_dir.exists());
    }

    #[test]
    fn update_apply_rejects_unsafe_archive_member_before_install() {
        let target = update_apply_test_target();
        let filename = update_zip_archive_fixture_name(&target);
        let archive_bytes = update_zip_archive_fixture_bytes(&target, true);
        let direct_error = stage_update_archive_binaries(&filename, &archive_bytes, &target)
            .expect_err("unsafe archive member should fail closed");
        assert_update_archive_member_error_redacted(&direct_error, "unsafe path", "../bin/conu");

        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-unsafe");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let install_dir = home.join("install-bin");

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--dry-run",
            "--json",
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("unsafe path"));
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(!output.stderr.contains("../bin/conu"));
        assert!(!install_dir.exists());
    }

    #[test]
    fn update_apply_rejects_invalid_tar_member_path_without_path() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let raw_member = b"conu-secret-local-path-\xff/bin/conu";
        let archive_bytes =
            update_archive_fixture_bytes_with_raw_member_name(raw_member, b"secret payload");
        let error = stage_update_archive_binaries(&filename, &archive_bytes, &target)
            .expect_err("invalid tar member path should fail closed");

        assert_update_archive_member_error_redacted(
            &error,
            "member path is invalid",
            "secret-local-path",
        );
        assert!(!error.contains("secret payload"), "{error}");
    }

    #[test]
    fn update_apply_rejects_duplicate_archive_member_without_path() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let root = format!("conu-0.1.0-{target}");
        let duplicate_path = format!("{root}/bin/{}", update_binary_filename("conu"));
        let archive_bytes =
            update_archive_fixture_bytes_with_extra_file(&target, &duplicate_path, b"duplicate");
        let error = stage_update_archive_binaries(&filename, &archive_bytes, &target)
            .expect_err("duplicate archive member should fail closed");

        assert_update_archive_member_error_redacted(&error, "duplicated path", &duplicate_path);
    }

    #[test]
    fn update_apply_rejects_unexpected_binary_archive_member_without_path() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let root = format!("conu-0.1.0-{target}");
        let unexpected_path = format!("{root}/unexpected/{}", update_binary_filename("conu"));
        let archive_bytes =
            update_archive_fixture_bytes_with_extra_file(&target, &unexpected_path, b"unexpected");
        let error = stage_update_archive_binaries(&filename, &archive_bytes, &target)
            .expect_err("unexpected binary archive member should fail closed");

        assert_update_archive_member_error_redacted(
            &error,
            "unexpected binary path",
            &unexpected_path,
        );
    }

    #[test]
    fn update_apply_rejects_unexpected_archive_root_before_install() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let wrong_root = format!("conu-9.9.9-{target}");
        let archive_bytes = update_archive_fixture_bytes_with_root(&target, &wrong_root, false);
        let direct_error = stage_update_archive_binaries(&filename, &archive_bytes, &target)
            .expect_err("unexpected archive root should fail closed");
        assert_update_archive_member_error_redacted(&direct_error, "unexpected root", &wrong_root);

        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-wrong-root");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let install_dir = home.join("install-bin");

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--dry-run",
            "--json",
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("unexpected root"));
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(!output.stderr.contains(&wrong_root));
        assert!(!output.stderr.contains("fixture binary bytes"));
        assert!(!install_dir.exists());
    }

    #[test]
    fn update_apply_rejects_mixed_rooted_and_rootless_archive_before_install() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let archive_bytes = update_archive_fixture_bytes_with_mixed_root(&target);
        let mixed_member = format!("bin/{}", update_binary_filename("conu"));
        let direct_error = stage_update_archive_binaries(&filename, &archive_bytes, &target)
            .expect_err("mixed archive root styles should fail closed");
        assert_update_archive_member_error_redacted(
            &direct_error,
            "mixes rooted and rootless",
            &mixed_member,
        );

        let archive_sha = sha256_hex(&archive_bytes);
        let home = temp_home("update-apply-mixed-root");
        let policy =
            write_update_policy_fixture_for_asset(&home, false, &archive_sha, &target, &filename);
        let artifact = write_update_artifact_fixture(&home, &filename, &archive_bytes);
        let install_dir = home.join("install-bin");

        let output = run([
            "update",
            "apply",
            "--policy-file",
            policy.to_str().expect("policy path"),
            "--artifact-file",
            artifact.to_str().expect("artifact path"),
            "--install-dir",
            install_dir.to_str().expect("install path"),
            "--dry-run",
            "--json",
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("mixes rooted and rootless"));
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(!output.stderr.contains(&mixed_member));
        assert!(!output.stderr.contains("fixture binary bytes"));
        assert!(!install_dir.exists());
    }

    #[test]
    fn update_apply_archive_bound_failures_are_redacted() {
        let target = update_apply_test_target();
        let filename = update_archive_fixture_name(&target);
        let root = format!("conu-0.1.0-{target}");

        let mut count_scan =
            UpdateArchiveScan::new(&target, &filename).expect("count scan creates");
        let mut count_error = None;
        for index in 0..=MAX_UPDATE_ARCHIVE_ENTRIES {
            let raw_name = format!("{root}/docs/secret-count-bound-{index}.txt");
            match count_scan.record_member(&filename, &raw_name, 0, false) {
                Ok(_) => {}
                Err(error) => {
                    count_error = Some(error);
                    break;
                }
            }
        }
        let count_error = count_error.expect("member count bound fails");
        assert_update_archive_member_error_redacted(
            &count_error,
            "contains more than",
            "secret-count-bound",
        );

        let mut total_scan =
            UpdateArchiveScan::new(&target, &filename).expect("total scan creates");
        let mut total_error = None;
        for index in 0..5 {
            let raw_name = format!("{root}/docs/secret-total-bound-{index}.bin");
            match total_scan.record_member(
                &filename,
                &raw_name,
                MAX_UPDATE_ARCHIVE_MEMBER_BYTES,
                false,
            ) {
                Ok(_) => {}
                Err(error) => {
                    total_error = Some(error);
                    break;
                }
            }
        }
        let total_error = total_error.expect("uncompressed total bound fails");
        assert_update_archive_member_error_redacted(
            &total_error,
            "uncompressed contents exceed",
            "secret-total-bound",
        );
    }

    #[test]
    fn update_apply_requires_dry_run_or_confirm() {
        let output = run([
            "update",
            "apply",
            "--policy-file",
            "dist/conu-0.1.0-update-policy.json",
            "--artifact-file",
            "dist/conu-0.1.0-linux-x64.tar.gz",
            "--install-dir",
            "bin",
        ]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("conu update apply"));
    }

    #[test]
    fn update_check_rejects_auto_apply_policy() {
        let home = temp_home("update-auto-apply");
        let policy = write_update_policy_fixture(&home, true);

        let output = run([
            "update",
            "check",
            "--policy-file",
            policy.to_str().expect("policy path"),
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("must not enable autoApply"));
        assert!(!output.stderr.contains("BEGIN PGP SIGNATURE"));
    }

    #[test]
    fn update_check_rejects_checksum_drift() {
        let home = temp_home("update-checksum");
        let policy = write_update_policy_fixture(&home, false);
        let sidecar = policy.with_file_name(format!(
            "{}.sha256",
            policy.file_name().unwrap().to_string_lossy()
        ));
        fs::write(
            &sidecar,
            format!(
                "{}  {}\n",
                "f".repeat(64),
                policy.file_name().unwrap().to_string_lossy()
            ),
        )
        .expect("sidecar writes");

        let output = run([
            "update",
            "check",
            "--policy-file",
            policy.to_str().expect("policy path"),
        ]);

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("checksum did not match"));
    }

    #[test]
    fn pair_and_join_create_trusted_peer() {
        let home = temp_home("pair-join");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);

        let join = run_with_home(["join", &code], Some(home.clone()));
        let peers = run_with_home(["peers"], Some(home));

        assert_eq!(pair.code, 0, "{}", pair.stderr);
        assert_eq!(join.code, 0, "{}", join.stderr);
        assert!(join.stdout.contains("status: trusted"));
        assert!(peers.stdout.contains("peer_"));
        assert!(peers.stdout.contains("trusted"));
    }

    #[test]
    fn peers_json_and_revoke_are_metadata_only() {
        let home = temp_home("peers-revoke");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home.clone()), &invite.code).expect("join");

        let peers = run_with_home(["peers", "--json"], Some(home.clone()));
        let revoke = run_with_home(
            ["peers", "revoke", &joined.peer.peer_node_id, "--json"],
            Some(home.clone()),
        );
        let revoked = run_with_home(["peers"], Some(home));

        assert_eq!(peers.code, 0, "{}", peers.stderr);
        assert!(peers.stdout.contains("\"status\": \"trusted\""));
        assert!(peers.stdout.contains("\"contentsDisplayed\": false"));
        assert_eq!(revoke.code, 0, "{}", revoke.stderr);
        assert!(revoke.stdout.contains("\"status\": \"revoked\""));
        assert!(revoked.stdout.contains("revoked"));
    }

    #[test]
    fn peer_policy_cli_sets_scoped_grants_without_payloads() {
        let home = temp_home("peer-policy");
        let invite = trust::create_pairing_invite(Some(home.clone())).expect("invite creates");
        let joined = trust::join_pairing_code(Some(home.clone()), &invite.code).expect("join");

        let updated = run_with_home(
            [
                "peers",
                "policy",
                &joined.peer.peer_node_id,
                "--messages",
                "true",
                "--streams",
                "true",
                "--rooms",
                "false",
                "--json",
            ],
            Some(home.clone()),
        );
        let listed = run_with_home(["peers", "policy", "--json"], Some(home.clone()));
        let read = run_with_home(
            ["peers", "policy", &joined.peer.peer_node_id, "--json"],
            Some(home),
        );

        assert_eq!(updated.code, 0, "{}", updated.stderr);
        assert_eq!(listed.code, 0, "{}", listed.stderr);
        assert_eq!(read.code, 0, "{}", read.stderr);
        assert!(updated.stdout.contains("\"messages\": true"));
        assert!(updated.stdout.contains("\"streams\": true"));
        assert!(updated.stdout.contains("\"rooms\": false"));
        assert!(listed.stdout.contains(&joined.peer.peer_node_id));
        assert!(read.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!updated.stdout.contains("private message contents"));
        assert!(!listed.stdout.contains("private message contents"));
        assert!(!read.stdout.contains("private message contents"));
    }

    #[test]
    fn signed_peer_card_cli_import_verifies_without_payloads() {
        let alice_home = temp_home("signed-peer-alice");
        let bob_home = temp_home("signed-peer-bob");
        let card = trust::export_peer_card(Some(bob_home)).expect("bob card exports");
        let output = run_with_home(
            vec![
                "peers".to_string(),
                "trust".to_string(),
                card.node_id.clone(),
                card.display_name.clone(),
                "--exchange-key".to_string(),
                card.exchange_public_key_hex.clone(),
                "--relay".to_string(),
                card.relay_endpoint.clone(),
                "--signing-key".to_string(),
                card.signing_public_key_hex.clone().expect("card signed"),
                "--signature".to_string(),
                card.signature_hex.clone().expect("card signature"),
                "--signature-key-id".to_string(),
                card.signature_key_id
                    .clone()
                    .expect("card signature key id"),
                "--json".to_string(),
            ],
            Some(alice_home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"peerCardSigned\": true"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private message contents"));
        assert!(
            !output
                .stdout
                .contains(card.signature_hex.as_deref().unwrap_or(""))
        );
    }

    #[test]
    fn signed_peer_card_cli_imports_json_file_without_payloads() {
        let alice_home = temp_home("signed-peer-card-file-alice");
        let bob_home = temp_home("signed-peer-card-file-bob");
        fs::create_dir_all(&alice_home).expect("alice fixture dir creates");
        let exported = run_with_home(
            [
                "identity",
                "export",
                "--relay",
                "wss://relay.example.com/conu",
                "--json",
            ],
            Some(bob_home),
        );
        let card_path = alice_home.join("bob-peer-card.json");
        fs::write(&card_path, &exported.stdout).expect("peer card writes");

        let output = run_with_home(
            vec![
                "peers".to_string(),
                "trust".to_string(),
                "--card".to_string(),
                card_path.display().to_string(),
                "--json".to_string(),
            ],
            Some(alice_home.clone()),
        );
        let peers = trust::list_peers(Some(alice_home)).expect("trusted peers read");

        assert_eq!(exported.code, 0, "{}", exported.stderr);
        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"peerCardSigned\": true"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].relay_endpoint.as_deref(),
            Some("wss://relay.example.com/conu")
        );
        assert!(!output.stdout.contains("private message contents"));
        assert!(!output.stdout.contains("signatureHex"));
    }

    #[test]
    fn signed_peer_card_cli_imports_json_stdin_without_payloads() {
        let alice_home = temp_home("signed-peer-card-stdin-alice");
        let bob_home = temp_home("signed-peer-card-stdin-bob");
        let exported = run_with_home(
            [
                "identity",
                "export",
                "--relay",
                "wss://relay.example.com/conu",
                "--json",
            ],
            Some(bob_home),
        );
        assert_eq!(exported.code, 0, "{}", exported.stderr);
        let output = run_with_home_and_stdin(
            ["peers", "trust", "--card", "-", "--json"],
            Some(alice_home),
            exported.stdout.into_bytes(),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"peerCardSigned\": true"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private message contents"));
        assert!(!output.stdout.contains("signatureHex"));
    }

    #[test]
    fn signed_peer_card_cli_rejects_endpoint_override_without_payloads() {
        let alice_home = temp_home("signed-peer-card-override-alice");
        let bob_home = temp_home("signed-peer-card-override-bob");
        fs::create_dir_all(&alice_home).expect("alice fixture dir creates");
        let exported = run_with_home(
            [
                "identity",
                "export",
                "--relay",
                "wss://relay.example.com/conu",
                "--json",
            ],
            Some(bob_home),
        );
        let card_path = alice_home.join("bob-peer-card.json");
        fs::write(&card_path, &exported.stdout).expect("peer card writes");

        let output = run_with_home(
            vec![
                "peers".to_string(),
                "trust".to_string(),
                "--card".to_string(),
                card_path.display().to_string(),
                "--relay".to_string(),
                "wss://other.example.com/conu".to_string(),
                "--json".to_string(),
            ],
            Some(alice_home),
        );

        assert_eq!(exported.code, 0, "{}", exported.stderr);
        assert_eq!(output.code, 2);
        assert!(
            output
                .stderr
                .contains("re-export with conu identity export")
        );
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(!output.stderr.contains("private message contents"));
        assert!(!output.stderr.contains("signatureHex"));
    }

    #[test]
    fn signed_agent_card_cli_export_and_import_verifies_without_payloads() {
        let alice_home = temp_home("signed-agent-alice");
        let bob_home = temp_home("signed-agent-bob");
        let bob_peer_card =
            trust::export_peer_card(Some(bob_home.clone())).expect("bob peer card exports");
        trust::trust_peer_card(Some(alice_home.clone()), bob_peer_card).expect("alice trusts bob");
        register_test_agent(&bob_home, "agent.bob");

        let exported = run_with_home(
            ["agents", "export", "agent.bob", "--json"],
            Some(bob_home.clone()),
        );
        let card =
            agents::export_agent_card(Some(bob_home), "agent.bob").expect("agent card exports");
        let trusted = run_with_home(
            vec![
                "agents".to_string(),
                "trust".to_string(),
                card.agent_id.clone(),
                card.display_name.clone(),
                "--node".to_string(),
                card.node_id.clone(),
                "--kind".to_string(),
                card.kind.clone(),
                "--messages".to_string(),
                card.capabilities.messages.to_string(),
                "--streams".to_string(),
                card.capabilities.streams.to_string(),
                "--rooms".to_string(),
                card.capabilities.rooms.to_string(),
                "--files".to_string(),
                card.capabilities.files.to_string(),
                "--presence".to_string(),
                card.capabilities.presence.to_string(),
                "--signing-key".to_string(),
                card.signing_public_key_hex.clone(),
                "--signature".to_string(),
                card.signature_hex.clone(),
                "--signature-key-id".to_string(),
                card.signature_key_id.clone(),
                "--json".to_string(),
            ],
            Some(alice_home.clone()),
        );
        let sync = run_with_home(["sessions", "sync"], Some(alice_home.clone()));
        let agents = run_with_home(["agents", "--json"], Some(alice_home));

        assert_eq!(exported.code, 0, "{}", exported.stderr);
        assert_eq!(trusted.code, 0, "{}", trusted.stderr);
        assert_eq!(sync.code, 0, "{}", sync.stderr);
        assert!(exported.stdout.contains("\"agentCardSigned\": true"));
        assert!(trusted.stdout.contains("\"agentCardSigned\": true"));
        assert!(agents.stdout.contains("\"agentId\": \"agent.bob\""));
        assert!(agents.stdout.contains("\"agentCardSigned\": true"));
        assert!(agents.stdout.contains("\"streams\": true"));
        assert!(agents.stdout.contains("\"rooms\": true"));
        assert!(!trusted.stdout.contains(&card.signature_hex));
        assert!(!agents.stdout.contains("private message contents"));
    }

    #[test]
    fn sessions_sync_makes_remote_agent_visible() {
        let home = temp_home("sessions-sync");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);
        let join = run_with_home(["join", &code], Some(home.clone()));
        let sync = run_with_home(["sessions", "sync"], Some(home.clone()));
        let sessions = run_with_home(["sessions"], Some(home.clone()));
        let agents = run_with_home(["agents", "--json"], Some(home.clone()));
        let status = run_with_home(["status", "--json"], Some(home));

        assert_eq!(join.code, 0, "{}", join.stderr);
        assert_eq!(sync.code, 0, "{}", sync.stderr);
        assert!(sync.stdout.contains("remote agents: 1"));
        assert!(sessions.stdout.contains("connected"));
        assert!(agents.stdout.contains("\"remote\": ["));
        assert!(agents.stdout.contains("agent.remote."));
        assert!(status.stdout.contains("\"remote\": 1"));
        assert!(status.stdout.contains("\"sessions\": 1"));
        assert!(!agents.stdout.contains("private message contents"));
    }

    #[test]
    fn routes_sync_selects_relay_fallback_without_payloads() {
        let home = temp_home("routes-relay");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);
        let join = run_with_home(["join", &code], Some(home.clone()));
        let sync = run_with_home(["routes", "sync", "--json"], Some(home.clone()));
        let routes = run_with_home(["routes", "--json"], Some(home.clone()));
        let probes = run_with_home(["routes", "probes"], Some(home));

        assert_eq!(join.code, 0, "{}", join.stderr);
        assert_eq!(sync.code, 0, "{}", sync.stderr);
        assert!(sync.stdout.contains("\"selectedRelay\": 1"));
        assert!(sync.stdout.contains("\"relayFallbacks\": 1"));
        assert!(routes.stdout.contains("\"transport\": \"relay-websocket\""));
        assert!(routes.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            probes
                .stdout
                .contains("payload view  contents are not displayed")
        );
        assert!(!routes.stdout.contains("private message contents"));
        assert!(!probes.stdout.contains("private message contents"));
    }

    #[test]
    fn cli_display_renderers_redact_sensitive_endpoint_parts() {
        let relay_endpoint = "wss://user:relay-secret@relay.example.com/conu/private-token?token=query-secret#frag-secret";
        let direct_endpoint = "quic://user:direct-secret@direct.example.com:9443/direct/private?token=direct-query#direct-frag";
        assert_eq!(
            display_network_endpoint(relay_endpoint),
            "wss://relay.example.com; endpointPathDisplayed=false"
        );
        assert_eq!(
            display_network_endpoint(direct_endpoint),
            "quic://direct.example.com:9443; endpointPathDisplayed=false"
        );
        assert_eq!(
            display_network_endpoint("not-an-endpoint"),
            "endpointDisplayed=false"
        );

        let session = RemoteSession {
            peer_node_id: "peer.node".to_string(),
            display_name: "Peer".to_string(),
            state: conu_core::sessions::RemoteSessionState::Connected,
            route: "relay-websocket".to_string(),
            relay_endpoint: relay_endpoint.to_string(),
            reconnect_attempts: 0,
            remote_agent_count: 1,
            last_seen_unix: 1,
            updated_at_unix: 1,
        };
        let route = RouteRecord {
            route_id: "route.peer".to_string(),
            peer_node_id: "peer.node".to_string(),
            display_name: "Peer".to_string(),
            transport: RouteTransport::RelayWebSocket,
            endpoint: relay_endpoint.to_string(),
            state: conu_core::routes::RouteState::Selected,
            score: 80,
            latency_ms: Some(80),
            direct_attempted: false,
            relay_fallback: false,
            nat_profile: conu_core::routes::NatProfile::Public,
            candidate_source: "none".to_string(),
            candidate_kind: "none".to_string(),
            rendezvous_state: "not_configured".to_string(),
            failure_reason: None,
            updated_at_unix: 1,
        };
        let probe = RouteProbe {
            probe_id: "probe.peer".to_string(),
            route_id: "route.peer".to_string(),
            peer_node_id: "peer.node".to_string(),
            transport: RouteTransport::RelayWebSocket,
            endpoint: relay_endpoint.to_string(),
            outcome: "selected".to_string(),
            score: 80,
            latency_ms: Some(80),
            candidate_source: "none".to_string(),
            candidate_kind: "none".to_string(),
            rendezvous_state: "not_configured".to_string(),
            created_at_unix: 1,
        };
        let peer = TrustedPeer {
            peer_node_id: "peer.node".to_string(),
            display_name: "Peer".to_string(),
            status: conu_core::trust::TrustStatus::Trusted,
            source: "test".to_string(),
            pairing_code_hash: "pair.hash".to_string(),
            exchange_public_key_hex: Some("exchange".to_string()),
            relay_endpoint: Some(relay_endpoint.to_string()),
            direct_quic_endpoint: Some(direct_endpoint.to_string()),
            signing_public_key_hex: None,
            signature_algorithm: None,
            signature_key_id: None,
            signature_hex: None,
            created_at_unix: 1,
            updated_at_unix: 1,
        };

        let outputs = [
            render_sessions_json(&[session], &[]),
            render_routes_json(std::slice::from_ref(&route)),
            render_routes_text(std::slice::from_ref(&route)),
            render_route_line(&route),
            render_route_probes_json(&[probe]),
            render_peers_json(std::slice::from_ref(&peer)),
            render_peers_text(&[peer]),
        ];

        for output in outputs {
            assert!(output.contains("wss://relay.example.com"));
            assert!(output.contains("endpointPathDisplayed=false"));
            assert!(!output.contains("user:relay-secret"));
            assert!(!output.contains("relay-secret"));
            assert!(!output.contains("private-token"));
            assert!(!output.contains("token=query-secret"));
            assert!(!output.contains("query-secret"));
            assert!(!output.contains("frag-secret"));
            assert!(!output.contains("/conu"));
            assert!(!output.contains("user:direct-secret"));
            assert!(!output.contains("direct-secret"));
            assert!(!output.contains("token=direct-query"));
            assert!(!output.contains("direct-query"));
            assert!(!output.contains("direct-frag"));
            assert!(!output.contains("/direct/private"));
        }
    }

    #[test]
    fn routes_sync_keeps_relay_selected_for_inactive_direct_quic_candidate() {
        let home = temp_home("routes-direct");
        let pair = run_with_home(["pair"], Some(home.clone()));
        let code = pairing_code_from_output(&pair.stdout);
        let join = run_with_home(["join", &code], Some(home.clone()));
        let peer_id = join
            .stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("peer: "))
            .expect("peer id line")
            .to_string();
        let config_key = format!("direct_quic_{}", config_key_suffix_for_test(&peer_id));
        fs::write(
            state::StatePaths::from_home(home.clone()).config,
            format!(
                "version = \"1\"\ndefault_relay = \"ws://127.0.0.1:8787\"\nnat_profile = \"public\"\n{config_key} = \"quic://127.0.0.1:9443\"\n"
            ),
        )
        .expect("config writes");

        let sync = run_with_home(["routes", "sync", "--json"], Some(home.clone()));
        let routes = run_with_home(["routes"], Some(home.clone()));
        let session_sync = run_with_home(["sessions", "sync"], Some(home.clone()));
        let sessions = run_with_home(["sessions"], Some(home));

        assert_eq!(join.code, 0, "{}", join.stderr);
        assert_eq!(sync.code, 0, "{}", sync.stderr);
        assert!(sync.stdout.contains("\"directAvailable\": 0"));
        assert!(sync.stdout.contains("\"selectedDirect\": 0"));
        assert!(sync.stdout.contains("\"selectedRelay\": 1"));
        assert!(sync.stdout.contains("\"natTraversalUnavailable\": 0"));
        assert!(routes.stdout.contains("direct-quic"));
        assert!(routes.stdout.contains("direct_quic_probe_failed"));
        assert!(routes.stdout.contains("source peer_config"));
        assert!(routes.stdout.contains("kind host"));
        assert!(routes.stdout.contains("rendezvous candidate_exchanged"));
        assert!(session_sync.stdout.contains("sessions: 1"));
        assert!(sessions.stdout.contains("route relay-websocket"));
        assert!(!routes.stdout.contains("private message contents"));
    }

    #[test]
    fn streams_flow_and_watch_are_metadata_only() {
        let home = temp_home("streams-flow");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");

        let opened = run_with_home(
            ["streams", "open", "agent.sender", "agent.receiver"],
            Some(home.clone()),
        );
        let stream_id = stream_id_from_output(&opened.stdout);
        let written = run_with_home_and_stdin(
            ["streams", "write", &stream_id, "--stdin"],
            Some(home.clone()),
            b"private message contents".to_vec(),
        );
        let watch = run_with_home(["watch"], Some(home.clone()));
        let closed = run_with_home(["streams", "close", &stream_id], Some(home.clone()));
        let listed = run_with_home(["streams", "--json"], Some(home));

        assert_eq!(opened.code, 0, "{}", opened.stderr);
        assert_eq!(written.code, 0, "{}", written.stderr);
        assert_eq!(closed.code, 0, "{}", closed.stderr);
        assert!(written.stdout.contains("bytes: 24"));
        assert!(watch.stdout.contains("private packets"));
        assert!(watch.stdout.contains("contents      not displayed"));
        assert!(listed.stdout.contains("\"streams\": ["));
        assert!(listed.stdout.contains("\"state\": \"closed\""));
        assert!(!watch.stdout.contains("private message contents"));
        assert!(!listed.stdout.contains("private message contents"));
    }

    #[test]
    fn rooms_flow_and_connect_are_metadata_only() {
        let home = temp_home("rooms-flow");
        register_test_agent(&home, "agent.codex");
        register_test_agent(&home, "agent.hermes");

        let connected = run_with_home(
            ["connect", "local", "agent.codex", "agent.hermes", "--json"],
            Some(home.clone()),
        );
        let created = run_with_home(
            [
                "rooms",
                "create",
                "room.dev",
                "Dev Room",
                "--agent",
                "agent.codex",
            ],
            Some(home.clone()),
        );
        let joined = run_with_home(
            ["rooms", "join", "room.dev", "agent.hermes", "--json"],
            Some(home.clone()),
        );
        let published = run_with_home_and_stdin(
            [
                "rooms",
                "publish",
                "room.dev",
                "agent.hermes",
                "build",
                "--stdin",
                "--json",
            ],
            Some(home.clone()),
            b"private message contents".to_vec(),
        );
        let events = run_with_home(["rooms", "events"], Some(home.clone()));
        let watch = run_with_home(["watch"], Some(home));

        assert_eq!(connected.code, 0, "{}", connected.stderr);
        assert_eq!(created.code, 0, "{}", created.stderr);
        assert_eq!(joined.code, 0, "{}", joined.stderr);
        assert_eq!(published.code, 0, "{}", published.stderr);
        assert!(connected.stdout.contains("\"status\": \"connected\""));
        assert!(created.stdout.contains("status: created"));
        assert!(joined.stdout.contains("\"participants\": 2"));
        assert!(published.stdout.contains("\"payloadBytes\": 24"));
        assert!(published.stdout.contains("\"localDeliveries\": 1"));
        assert!(events.stdout.contains("topic build"));
        assert!(watch.stdout.contains("room events"));
        assert!(watch.stdout.contains("room/relay"));
        assert!(!published.stdout.contains("private message contents"));
        assert!(!events.stdout.contains("private message contents"));
        assert!(!watch.stdout.contains("private message contents"));
    }

    #[test]
    fn rooms_policy_cli_sets_topic_grants_without_payloads() {
        let home = temp_home("rooms-policy");
        register_test_agent(&home, "agent.codex");
        register_test_agent(&home, "agent.hermes");
        let created = run_with_home(
            [
                "rooms",
                "create",
                "room.dev",
                "Dev Room",
                "--agent",
                "agent.codex",
            ],
            Some(home.clone()),
        );
        let joined = run_with_home(
            ["rooms", "join", "room.dev", "agent.hermes"],
            Some(home.clone()),
        );
        let publisher = run_with_home(
            [
                "rooms",
                "policy",
                "room.dev",
                "agent.hermes",
                "build",
                "--publish",
                "true",
                "--subscribe",
                "false",
                "--json",
            ],
            Some(home.clone()),
        );
        let subscriber = run_with_home(
            [
                "rooms",
                "policy",
                "room.dev",
                "agent.codex",
                "build",
                "--publish",
                "false",
                "--subscribe",
                "true",
            ],
            Some(home.clone()),
        );
        let listed = run_with_home(["rooms", "policy", "--json"], Some(home.clone()));
        let published = run_with_home_and_stdin(
            [
                "rooms",
                "publish",
                "room.dev",
                "agent.hermes",
                "build",
                "--stdin",
                "--json",
            ],
            Some(home),
            b"private message contents".to_vec(),
        );

        assert_eq!(created.code, 0, "{}", created.stderr);
        assert_eq!(joined.code, 0, "{}", joined.stderr);
        assert_eq!(publisher.code, 0, "{}", publisher.stderr);
        assert_eq!(subscriber.code, 0, "{}", subscriber.stderr);
        assert_eq!(listed.code, 0, "{}", listed.stderr);
        assert_eq!(published.code, 0, "{}", published.stderr);
        assert!(publisher.stdout.contains("\"publish\": true"));
        assert!(publisher.stdout.contains("\"subscribe\": false"));
        assert!(subscriber.stdout.contains("status: updated"));
        assert!(listed.stdout.contains("\"topicPolicies\":"));
        assert!(published.stdout.contains("\"localDeliveries\": 1"));
        assert!(!publisher.stdout.contains("private message contents"));
        assert!(!listed.stdout.contains("private message contents"));
        assert!(!published.stdout.contains("private message contents"));
    }

    #[test]
    fn security_audit_reports_hardened_controls_without_keys_or_payloads() {
        let home = temp_home("security-audit");
        let output = run_with_home(["security", "audit", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"localPayloadEncryption\": true"));
        assert!(output.stdout.contains("\"signedAgentCards\": true"));
        assert!(output.stdout.contains("\"peerKeyExchange\": true"));
        assert!(output.stdout.contains("\"replayCache\": true"));
        assert!(output.stdout.contains("\"secretStorageBackend\":"));
        assert!(output.stdout.contains("\"secretsOsProtected\":"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("secret_key_hex"));
        assert!(!output.stdout.contains("dpapi_hex"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn security_rotate_storage_requires_confirmation_and_hides_payloads() {
        let unconfirmed = run_with_home(
            ["security", "rotate", "storage", "--json"],
            Some(temp_home("security-rotate-unconfirmed")),
        );
        assert_eq!(unconfirmed.code, 2);
        assert!(unconfirmed.stderr.contains("requires --confirm"));

        let home = temp_home("security-rotate");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let before_key = security::ensure_security_state(Some(home.clone()))
            .expect("security state")
            .storage_key_id;

        let output = run_with_home(
            ["security", "rotate", "storage", "--confirm", "--json"],
            Some(home.clone()),
        );
        let after_key = security::ensure_security_state(Some(home.clone()))
            .expect("security state")
            .storage_key_id;
        let payload =
            messages::read_message_payload(Some(home), "agent.receiver", &inbox[0].envelope_id)
                .expect("payload reads after rotation");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_ne!(before_key, after_key);
        assert!(output.stdout.contains("\"status\": \"rotated\""));
        assert!(output.stdout.contains("\"filesMigrated\": 1"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert_eq!(payload.as_bytes(), b"private message contents");
        assert!(!output.stdout.contains("private message contents"));
        assert!(!output.stdout.contains("key_hex"));
        assert!(!output.stdout.contains("dpapi_hex"));
    }

    #[test]
    fn security_rotate_identity_requires_peer_refresh_and_hides_keys() {
        let unconfirmed = run_with_home(
            ["security", "rotate", "identity", "--json"],
            Some(temp_home("security-rotate-identity-unconfirmed")),
        );
        assert_eq!(unconfirmed.code, 2);
        assert!(unconfirmed.stderr.contains("--confirm-peer-refresh"));

        let home = temp_home("security-rotate-identity");
        let before = security::ensure_security_state(Some(home.clone())).expect("security state");
        let output = run_with_home(
            [
                "security",
                "rotate",
                "identity",
                "--confirm-peer-refresh",
                "--json",
            ],
            Some(home.clone()),
        );
        let after = security::ensure_security_state(Some(home.clone())).expect("security state");
        let exported = run_with_home(["identity", "export", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_ne!(before.signing_key_id, after.signing_key_id);
        assert_ne!(before.exchange_key_id, after.exchange_key_id);
        assert!(output.stdout.contains("\"status\": \"rotated\""));
        assert!(output.stdout.contains("\"peerCardRefreshRequired\": true"));
        assert!(
            output
                .stdout
                .contains("\"signedAgentCardRefreshRequired\": true")
        );
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains(&before.signing_public_key_hex));
        assert!(!output.stdout.contains(&before.exchange_public_key_hex));
        assert!(!output.stdout.contains("secret_key_hex"));
        assert!(!output.stdout.contains("dpapi_hex"));
        assert_eq!(exported.code, 0, "{}", exported.stderr);
        assert!(exported.stdout.contains(&after.signing_key_id));
        assert!(exported.stdout.contains(&after.exchange_public_key_hex));
    }

    #[test]
    fn security_retire_identity_requires_refresh_confirmation_and_hides_keys() {
        let unconfirmed = run_with_home(
            ["security", "retire", "identity", "--json"],
            Some(temp_home("security-retire-identity-unconfirmed")),
        );
        assert_eq!(unconfirmed.code, 2);
        assert!(
            unconfirmed
                .stderr
                .contains("--confirm-peer-refresh-complete")
        );

        let home = temp_home("security-retire-identity");
        let before = security::ensure_security_state(Some(home.clone())).expect("security state");
        let rotated = run_with_home(
            [
                "security",
                "rotate",
                "identity",
                "--confirm-peer-refresh",
                "--json",
            ],
            Some(home.clone()),
        );
        let after_rotation =
            security::ensure_security_state(Some(home.clone())).expect("security state");
        let retired = run_with_home(
            [
                "security",
                "retire",
                "identity",
                "--confirm-peer-refresh-complete",
                "--json",
            ],
            Some(home.clone()),
        );
        let after_retirement =
            security::ensure_security_state(Some(home.clone())).expect("security state");
        let archive_dir = home.join("security").join("identity-keys");
        let archive_count = fs::read_dir(&archive_dir)
            .map(|entries| entries.count())
            .unwrap_or_default();

        assert_eq!(rotated.code, 0, "{}", rotated.stderr);
        assert_eq!(retired.code, 0, "{}", retired.stderr);
        assert_ne!(before.signing_key_id, after_rotation.signing_key_id);
        assert_ne!(before.exchange_key_id, after_rotation.exchange_key_id);
        assert_eq!(
            after_rotation.signing_key_id,
            after_retirement.signing_key_id
        );
        assert_eq!(
            after_rotation.exchange_key_id,
            after_retirement.exchange_key_id
        );
        assert_eq!(archive_count, 0);
        assert!(retired.stdout.contains("\"status\": \"retired\""));
        assert!(
            retired
                .stdout
                .contains("\"peerCardRefreshConfirmed\": true")
        );
        assert!(
            retired
                .stdout
                .contains("\"oldKeyDecryptCompatibilityRetired\": true")
        );
        assert!(retired.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!retired.stdout.contains(&before.signing_public_key_hex));
        assert!(!retired.stdout.contains(&before.exchange_public_key_hex));
        assert!(!retired.stdout.contains("secret_key_hex"));
        assert!(!retired.stdout.contains("dpapi_hex"));
    }

    #[test]
    fn security_retire_storage_requires_confirmation_and_hides_payloads() {
        let unconfirmed = run_with_home(
            ["security", "retire", "storage", "--json"],
            Some(temp_home("security-retire-unconfirmed")),
        );
        assert_eq!(unconfirmed.code, 2);
        assert!(unconfirmed.stderr.contains("requires --confirm"));

        let home = temp_home("security-retire");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");

        let rotated = run_with_home(
            ["security", "rotate", "storage", "--confirm", "--json"],
            Some(home.clone()),
        );
        let retired = run_with_home(
            ["security", "retire", "storage", "--confirm", "--json"],
            Some(home.clone()),
        );
        let payload =
            messages::read_message_payload(Some(home), "agent.receiver", &inbox[0].envelope_id)
                .expect("payload reads after retirement");

        assert_eq!(rotated.code, 0, "{}", rotated.stderr);
        assert_eq!(retired.code, 0, "{}", retired.stderr);
        assert!(retired.stdout.contains("\"status\": \"retired\""));
        assert!(retired.stdout.contains("\"retiredStorageKeys\": 1"));
        assert!(retired.stdout.contains("\"retainedStorageKeys\": 0"));
        assert!(retired.stdout.contains("\"contentsDisplayed\": false"));
        assert_eq!(payload.as_bytes(), b"private message contents");
        assert!(!retired.stdout.contains("private message contents"));
        assert!(!retired.stdout.contains("key_hex"));
        assert!(!retired.stdout.contains("dpapi_hex"));
    }

    #[test]
    fn relay_credential_cli_uses_stdin_and_never_prints_token() {
        let home = temp_home("relay-credential");
        let token = b"stored-relay-token-1234567890".to_vec();
        let stored = run_with_home_and_stdin(
            ["relay", "credential", "set", "--stdin", "--json"],
            Some(home.clone()),
            token.clone(),
        );
        let status = run_with_home(
            ["relay", "credential", "status", "--json"],
            Some(home.clone()),
        );
        let cleared = run_with_home(
            ["relay", "credential", "clear", "--json"],
            Some(home.clone()),
        );
        let after_clear = run_with_home(["relay", "credential", "status", "--json"], Some(home));
        let token_text = String::from_utf8(token).expect("token utf8");

        assert_eq!(stored.code, 0, "{}", stored.stderr);
        assert_eq!(status.code, 0, "{}", status.stderr);
        assert_eq!(cleared.code, 0, "{}", cleared.stderr);
        assert_eq!(after_clear.code, 0, "{}", after_clear.stderr);
        assert!(stored.stdout.contains("\"status\": \"stored\""));
        assert!(stored.stdout.contains("\"configured\": true"));
        assert!(stored.stdout.contains("\"secretStorageBackend\":"));
        assert!(stored.stdout.contains("\"contentsDisplayed\": false"));
        assert!(status.stdout.contains("\"configured\": true"));
        assert!(cleared.stdout.contains("\"configured\": false"));
        assert!(after_clear.stdout.contains("\"configured\": false"));
        assert!(!stored.stdout.contains(&token_text));
        assert!(!status.stdout.contains(&token_text));
        assert!(!stored.stdout.contains("dpapi_hex"));
        assert!(!status.stdout.contains("token_hex"));
    }

    #[test]
    fn doctor_reports_setup_and_privacy_without_payloads() {
        let home = temp_home("doctor");
        let before_init = run_with_home(["doctor", "--json"], Some(home.clone()));
        let init = run_with_home(["init"], Some(home.clone()));
        let after_init = run_with_home(["doctor"], Some(home.clone()));

        assert_eq!(before_init.code, 0, "{}", before_init.stderr);
        assert!(before_init.stdout.contains("\"status\": \"needs_init\""));
        assert_eq!(init.code, 0, "{}", init.stderr);
        assert_eq!(after_init.code, 0, "{}", after_init.stderr);
        assert!(after_init.stdout.contains("conU doctor"));
        assert!(
            before_init
                .stdout
                .contains("\"controlledRelayReady\": false")
        );
        assert!(
            before_init
                .stdout
                .contains("\"managedPublicNetworkReady\": false")
        );
        assert!(after_init.stdout.contains("controlled relay"));
        assert!(after_init.stdout.contains("managed network    not ready"));
        assert!(
            after_init
                .stdout
                .contains("payload view       contents are not displayed")
        );
        assert!(
            !after_init
                .stdout
                .contains("hosted relay auth/TLS and streams remain future work")
        );
        assert!(!after_init.stdout.contains("private message contents"));
    }

    #[test]
    fn doctor_detects_payload_text_in_logs() {
        let home = temp_home("doctor-logs");
        state::init_state(Some(home.clone())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(
            paths.logs_dir.join("bad.log"),
            "event=test private message contents\n",
        )
        .expect("log writes");

        let output = run_with_home(["doctor", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"privacy_attention\""));
        assert!(output.stdout.contains("\"payloadSafe\": false"));
        assert!(
            !output
                .stdout
                .contains("event=test private message contents")
        );
    }

    #[test]
    fn logs_rotate_archives_metadata_without_payload_output() {
        let home = temp_home("logs-rotate");
        state::init_state(Some(home.clone())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(
            paths.logs_dir.join("messages.log"),
            "event=delivery envelope=env_1 payload=not_observed\n",
        )
        .expect("log writes");

        let output = run_with_home(
            [
                "logs",
                "rotate",
                "--max-bytes",
                "8",
                "--keep",
                "2",
                "--json",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"filesRotated\": 1"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(paths.logs_dir.join("messages.log.1").exists());
        assert!(!output.stdout.contains("event=delivery"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn doctor_scans_rotated_log_archives_without_printing_contents() {
        let home = temp_home("doctor-log-archives");
        state::init_state(Some(home.clone())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(
            paths.logs_dir.join("messages.log.1"),
            "event=test private message contents\n",
        )
        .expect("archive writes");

        let output = run_with_home(["doctor", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"privacy_attention\""));
        assert!(output.stdout.contains("\"payloadSafe\": false"));
        assert!(output.stdout.contains("\"scannedFiles\": 1"));
        assert!(
            !output
                .stdout
                .contains("event=test private message contents")
        );
    }

    #[cfg(unix)]
    #[test]
    fn doctor_rejects_symlinked_logs_without_reading_targets() {
        let home = temp_home("doctor-log-symlink");
        state::init_state(Some(home.clone())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        let outside_log = home.join("outside-target.log");
        fs::write(&outside_log, "event=outside relay-secret-token\n").expect("target writes");
        std::os::unix::fs::symlink(&outside_log, paths.logs_dir.join("linked.log"))
            .expect("symlink creates");

        let output = run_with_home(["doctor", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"privacy_attention\""));
        assert!(output.stdout.contains("\"payloadSafe\": false"));
        assert!(output.stdout.contains("\"scannedFiles\": 1"));
        assert!(output.stdout.contains("\"issues\": 1"));
        assert!(!output.stdout.contains("relay-secret-token"));
        assert_eq!(
            fs::read_to_string(&outside_log).expect("target reads"),
            "event=outside relay-secret-token\n"
        );
        let linked_metadata =
            fs::symlink_metadata(paths.logs_dir.join("linked.log")).expect("link metadata");
        assert!(linked_metadata.file_type().is_symlink());
    }

    #[test]
    fn doctor_rejects_oversized_logs_without_loading_contents() {
        let home = temp_home("doctor-log-oversized");
        state::init_state(Some(home.clone())).expect("state initializes");
        let paths = state::StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        let oversized = vec![b'a'; (MAX_DOCTOR_LOG_SCAN_BYTES + 1) as usize];
        fs::write(paths.logs_dir.join("huge.log"), oversized).expect("oversized log writes");

        let output = run_with_home(["doctor", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"privacy_attention\""));
        assert!(output.stdout.contains("\"payloadSafe\": false"));
        assert!(output.stdout.contains("\"scannedFiles\": 1"));
        assert!(output.stdout.contains("\"issues\": 1"));
        assert!(!output.stdout.contains("aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn telemetry_snapshot_json_is_allowlisted_and_payload_safe() {
        let home = temp_home("telemetry-json");
        register_test_agent(&home, "agent.codex");
        register_test_agent(&home, "agent.hermes");
        let opened = run_with_home(
            ["streams", "open", "agent.codex", "agent.hermes"],
            Some(home.clone()),
        );
        assert_eq!(opened.code, 0, "{}", opened.stderr);
        let stream_id = stream_id_from_output(&opened.stdout);
        let written = run_with_home_and_stdin(
            ["streams", "write", &stream_id, "--stdin"],
            Some(home.clone()),
            b"private message contents".to_vec(),
        );
        assert_eq!(written.code, 0, "{}", written.stderr);
        let paths = state::StatePaths::from_home(home.clone());
        fs::create_dir_all(&paths.logs_dir).expect("logs directory");
        fs::write(
            paths.logs_dir.join("bad.log"),
            "event=test payload_text private message contents secret_key_hex\n",
        )
        .expect("log writes");

        let output = run_with_home(["telemetry", "snapshot", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(
            output
                .stdout
                .contains("\"schema\": \"conu.telemetry.snapshot.v1\"")
        );
        assert!(output.stdout.contains("\"fieldAllowlist\": ["));
        assert!(output.stdout.contains("\"fieldAllowlistOnly\": true"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(output.stdout.contains("\"local\": 2"));
        assert!(output.stdout.contains("\"total\": 1"));
        assert!(output.stdout.contains("\"payloadSafe\": false"));
        assert!(output.stdout.contains("\"issues\": 1"));
        assert!(!output.stdout.contains("agent.codex"));
        assert!(!output.stdout.contains("agent.hermes"));
        assert!(!output.stdout.contains(&stream_id));
        assert!(!output.stdout.contains("private message contents"));
        assert!(!output.stdout.contains("payload_text"));
        assert!(!output.stdout.contains("secret_key_hex"));
        assert!(!output.stdout.contains("payload_ciphertext_hex"));
    }

    #[test]
    fn telemetry_snapshot_text_uses_counts_without_identifiers() {
        let home = temp_home("telemetry-text");
        register_test_agent(&home, "agent.codex");

        let output = run_with_home(["telemetry", "snapshot"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("conU telemetry snapshot"));
        assert!(output.stdout.contains("field allowlist"));
        assert!(output.stdout.contains("local             1"));
        assert!(
            output
                .stdout
                .contains("payload view      contents are not displayed")
        );
        assert!(!output.stdout.contains("agent.codex"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn join_rejects_unknown_local_pairing_code() {
        let output = run_with_home(["join", "123456"], Some(temp_home("join-missing")));

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("not available locally"));
    }

    #[test]
    fn agents_register_queues_metadata_request() {
        let home = temp_home("agent-register-queued");

        let output = run_with_home(
            [
                "agents",
                "register",
                "agent.codex",
                "Codex Desktop",
                "--kind",
                "coding-agent",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: queued"));
        assert!(
            output
                .stdout
                .contains("payload view  contents are not displayed")
        );
        assert!(state::StatePaths::from_home(home).ipc_inbox_dir.exists());
    }

    #[test]
    fn agents_register_persists_explicit_capabilities() {
        let home = temp_home("agent-register-capabilities");

        let output = run_with_home(
            [
                "agents",
                "register",
                "agent.codex",
                "Codex Desktop",
                "--kind",
                "coding-agent",
                "--streams",
                "true",
                "--rooms",
                "true",
                "--json",
            ],
            Some(home.clone()),
        );
        agents::process_gateway_requests(Some(home.clone())).expect("request processes");
        let agents = run_with_home(["agents", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"streams\": true"));
        assert!(output.stdout.contains("\"rooms\": true"));
        assert!(agents.stdout.contains("\"agentId\": \"agent.codex\""));
        assert!(agents.stdout.contains("\"streams\": true"));
        assert!(agents.stdout.contains("\"rooms\": true"));
    }

    #[test]
    fn agents_prepare_registers_ready_agent_and_optional_stream_room() {
        let home = temp_home("agent-prepare");

        let peer = run_with_home(
            ["agents", "prepare", "agent.peer", "Peer Agent"],
            Some(home.clone()),
        );
        let output = run_with_home(
            [
                "agents",
                "prepare",
                "agent.worker",
                "Worker Agent",
                "--connect",
                "agent.peer",
                "--room",
                "room.workshop",
                "--room-name",
                "Workshop",
            ],
            Some(home.clone()),
        );

        assert_eq!(peer.code, 0, "{}", peer.stderr);
        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: ready"));
        assert!(output.stdout.contains("agent: agent.worker"));
        assert!(output.stdout.contains("presence: ready"));
        assert!(output.stdout.contains("stream:"));
        assert!(output.stdout.contains("room: room.workshop"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(!output.stdout.contains("private message contents"));

        let agents = agents::list_local_agents(Some(home.clone())).expect("agents list");
        let worker = agents
            .iter()
            .find(|agent| agent.agent_id == "agent.worker")
            .expect("worker registered");
        assert_eq!(worker.presence, AgentPresence::Ready);
        assert!(worker.capabilities.messages);
        assert!(worker.capabilities.streams);
        assert!(worker.capabilities.rooms);
        assert!(!worker.capabilities.files);
        assert!(worker.capabilities.presence);

        let stream_records = streams::list_streams(Some(home.clone())).expect("streams list");
        assert!(stream_records.iter().any(|stream| {
            stream.from_agent_id == "agent.worker"
                && stream.to_agent_id == "agent.peer"
                && stream.kind == "message"
                && stream.state.as_str() == "open"
        }));

        let room_records = rooms::list_rooms(Some(home.clone())).expect("rooms list");
        let room = room_records
            .iter()
            .find(|room| room.room_id == "room.workshop")
            .expect("room created");
        assert!(
            room.participants
                .iter()
                .any(|participant| participant.agent_id == "agent.worker")
        );

        let json = run_with_home(
            [
                "agents",
                "prepare",
                "agent.worker",
                "Worker Agent",
                "--connect",
                "agent.peer",
                "--room",
                "room.workshop",
                "--json",
            ],
            Some(home),
        );

        assert_eq!(json.code, 0, "{}", json.stderr);
        assert!(json.stdout.contains("\"status\": \"ready\""));
        assert!(json.stdout.contains("\"agentId\": \"agent.worker\""));
        assert!(json.stdout.contains("\"presence\": \"ready\""));
        assert!(json.stdout.contains("\"streamId\":"));
        assert!(json.stdout.contains("\"roomId\": \"room.workshop\""));
        assert!(json.stdout.contains("\"created\": false"));
        assert!(json.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!json.stdout.contains("private message contents"));
    }

    #[test]
    fn ready_short_command_prepares_agent_with_stream_room_and_json() {
        let home = temp_home("agent-ready-short");

        let peer = run_with_home(["ready", "agent.peer", "Peer Agent"], Some(home.clone()));
        let output = run_with_home(
            [
                "ready",
                "agent.worker",
                "Worker Agent",
                "--kind",
                "coding-agent",
                "--connect",
                "agent.peer",
                "--room",
                "room.workshop",
                "--json",
            ],
            Some(home.clone()),
        );

        assert_eq!(peer.code, 0, "{}", peer.stderr);
        assert!(peer.stdout.contains("conU ready"));
        assert!(!peer.stdout.contains("conU agents prepare"));
        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"ready\""));
        assert!(output.stdout.contains("\"agentId\": \"agent.worker\""));
        assert!(output.stdout.contains("\"kind\": \"coding-agent\""));
        assert!(output.stdout.contains("\"presence\": \"ready\""));
        assert!(output.stdout.contains("\"streamId\":"));
        assert!(output.stdout.contains("\"roomId\": \"room.workshop\""));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private message contents"));
        assert!(output.stderr.is_empty());

        let agents = agents::list_local_agents(Some(home.clone())).expect("agents list");
        assert!(agents.iter().any(|agent| {
            agent.agent_id == "agent.worker"
                && agent.display_name == "Worker Agent"
                && agent.kind == "coding-agent"
                && agent.presence == AgentPresence::Ready
        }));

        let stream_records = streams::list_streams(Some(home.clone())).expect("streams list");
        assert!(stream_records.iter().any(|stream| {
            stream.from_agent_id == "agent.worker"
                && stream.to_agent_id == "agent.peer"
                && stream.kind == "message"
        }));

        let room_records = rooms::list_rooms(Some(home)).expect("rooms list");
        assert!(room_records.iter().any(|room| {
            room.room_id == "room.workshop"
                && room
                    .participants
                    .iter()
                    .any(|participant| participant.agent_id == "agent.worker")
        }));
    }

    #[test]
    fn agents_prepare_rejects_self_connect() {
        let output = run_with_home(
            [
                "agents",
                "prepare",
                "agent.same",
                "Same Agent",
                "--connect",
                "agent.same",
            ],
            Some(temp_home("agent-prepare-self-connect")),
        );

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("--connect must be different"));
    }

    #[test]
    fn agents_prepare_rejects_contradictory_options_before_state_mutation() {
        let home = temp_home("agent-prepare-contradictory");
        let output = run_with_home(
            [
                "agents",
                "prepare",
                "agent.worker",
                "Worker Agent",
                "--connect",
                "agent.peer",
                "--streams",
                "false",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("--connect requires --streams true"));
        assert!(!state::StatePaths::from_home(home).agent_registry.exists());
    }

    #[test]
    fn agents_list_persisted_local_agent() {
        let home = temp_home("agent-list");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        agents::submit_registration(Some(home.clone()), registration).expect("request submits");
        agents::process_gateway_requests(Some(home.clone())).expect("request processes");

        let output = run_with_home(["agents"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("agent.codex"));
        assert!(output.stdout.contains("Codex Desktop"));
        assert!(output.stdout.contains("ready"));
    }

    #[test]
    fn agents_json_lists_persisted_local_agent() {
        let home = temp_home("agent-json");
        let registration = AgentRegistration::new("agent.codex", "Codex Desktop", "coding-agent")
            .expect("valid registration");
        agents::submit_registration(Some(home.clone()), registration).expect("request submits");
        agents::process_gateway_requests(Some(home.clone())).expect("request processes");

        let output = run_with_home(["agents", "--json"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"agentId\": \"agent.codex\""));
        assert!(output.stdout.contains("\"displayName\": \"Codex Desktop\""));
    }

    #[test]
    fn agents_heartbeat_queues_presence_request() {
        let home = temp_home("agent-heartbeat");
        let output = run_with_home(
            ["agents", "heartbeat", "agent.codex", "--presence", "busy"],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: queued"));
        assert!(output.stdout.contains("presence: busy"));
    }

    #[test]
    fn messages_send_delivers_opaque_stdin_payload() {
        let home = temp_home("message-send-delivered");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");

        let output = run_with_home_and_stdin(
            [
                "messages",
                "send",
                "agent.sender",
                "agent.receiver",
                "--stdin",
            ],
            Some(home.clone()),
            b"private message contents".to_vec(),
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let receipts = messages::list_receipts(Some(home)).expect("receipts read");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("status: delivered"));
        assert!(output.stdout.contains("envelope: env_"));
        assert!(output.stdout.contains("bytes: 24"));
        assert!(!output.stdout.contains("private message contents"));
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].from_agent_id, "agent.sender");
        assert_eq!(inbox[0].to_agent_id, "agent.receiver");
        assert_eq!(inbox[0].payload_bytes, 24);
        assert!(receipts.iter().any(|receipt| {
            receipt.envelope_id == inbox[0].envelope_id
                && receipt.status == "delivered_local"
                && receipt.payload_bytes == 24
        }));
    }

    #[test]
    fn messages_send_reads_payload_file_without_displaying_path_or_contents() {
        let home = temp_home("message-send-file");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let payload_path = home.join("private-message.bin");
        fs::write(&payload_path, b"private file message").expect("payload file writes");

        let output = run_with_home(
            [
                "send",
                "agent.sender",
                "agent.receiver",
                "--file",
                payload_path.to_str().expect("path utf8"),
                "--json",
            ],
            Some(home.clone()),
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let payload =
            messages::read_message_payload(Some(home), "agent.receiver", &inbox[0].envelope_id)
                .expect("payload reads");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(payload.as_bytes(), b"private file message");
        assert!(output.stdout.contains("\"status\": \"delivered\""));
        assert!(output.stdout.contains("\"payloadBytes\": 20"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private file message"));
        assert!(
            !output
                .stdout
                .contains(payload_path.to_str().expect("path utf8"))
        );
    }

    #[test]
    fn messages_send_file_errors_do_not_display_path_or_contents() {
        let home = temp_home("message-send-file-error");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let payload_path = home.join("oversized-secret-message.bin");
        fs::write(
            &payload_path,
            vec![b's'; (MAX_CLI_PAYLOAD_FILE_BYTES + 1) as usize],
        )
        .expect("oversized payload file writes");

        let output = run_with_home(
            [
                "messages",
                "send",
                "agent.sender",
                "agent.receiver",
                "--file",
                payload_path.to_str().expect("path utf8"),
                "--json",
            ],
            Some(home),
        );

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("payload file exceeds"));
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(
            !output
                .stderr
                .contains(payload_path.to_str().expect("path utf8"))
        );
        assert!(!output.stderr.contains("oversized-secret-message"));
    }

    #[test]
    fn messages_reply_reads_payload_file_without_displaying_path_or_contents() {
        let home = temp_home("message-reply-file");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private original message",
        );
        let receiver_inbox = messages::list_agent_inbox(Some(home.clone()), "agent.receiver")
            .expect("receiver inbox reads");
        let payload_path = home.join("private-reply.bin");
        fs::write(&payload_path, b"private file reply").expect("reply file writes");

        let output = run_with_home(
            [
                "reply",
                "agent.receiver",
                &receiver_inbox[0].envelope_id,
                "--file",
                payload_path.to_str().expect("path utf8"),
                "--json",
            ],
            Some(home.clone()),
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.sender").expect("inbox reads");
        let payload =
            messages::read_message_payload(Some(home), "agent.sender", &inbox[0].envelope_id)
                .expect("reply payload reads");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(payload.as_bytes(), b"private file reply");
        assert!(output.stdout.contains("\"status\": \"delivered\""));
        assert!(output.stdout.contains("\"payloadBytes\": 18"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private file reply"));
        assert!(!output.stdout.contains("private original message"));
        assert!(
            !output
                .stdout
                .contains(payload_path.to_str().expect("path utf8"))
        );
    }

    #[test]
    fn messages_reply_latest_targets_newest_sender_without_payload() {
        let home = temp_home("message-reply-latest");
        register_test_agent(&home, "agent.first");
        register_test_agent(&home, "agent.latest");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.first",
            "agent.receiver",
            b"old private message",
        );
        deliver_test_message(
            &home,
            "agent.latest",
            "agent.receiver",
            b"newest private message",
        );
        let receiver_inbox = messages::list_agent_inbox(Some(home.clone()), "agent.receiver")
            .expect("receiver inbox reads");
        let latest_envelope_id = receiver_inbox
            .last()
            .expect("latest message exists")
            .envelope_id
            .clone();

        let output = run_with_home_and_stdin(
            [
                "messages",
                "reply",
                "agent.receiver",
                "--latest",
                "--stdin",
                "--json",
            ],
            Some(home.clone()),
            b"latest reply secret".to_vec(),
        );
        let first_inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.first").expect("first inbox");
        let latest_inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.latest").expect("latest inbox");
        let payload = messages::read_message_payload(
            Some(home),
            "agent.latest",
            &latest_inbox[0].envelope_id,
        )
        .expect("latest reply payload reads");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(first_inbox.is_empty());
        assert_eq!(latest_inbox.len(), 1);
        assert_eq!(latest_inbox[0].from_agent_id, "agent.receiver");
        assert_eq!(latest_inbox[0].to_agent_id, "agent.latest");
        assert_eq!(payload.as_bytes(), b"latest reply secret");
        assert!(output.stdout.contains("\"status\": \"delivered\""));
        assert!(
            output
                .stdout
                .contains("\"fromAgentId\": \"agent.receiver\"")
        );
        assert!(output.stdout.contains("\"toAgentId\": \"agent.latest\""));
        assert!(output.stdout.contains(&format!(
            "\"inReplyToEnvelopeId\": \"{}\"",
            latest_envelope_id
        )));
        assert!(output.stdout.contains("\"payloadBytes\": 19"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("old private message"));
        assert!(!output.stdout.contains("newest private message"));
        assert!(!output.stdout.contains("latest reply secret"));
    }

    #[test]
    fn top_level_reply_latest_reads_file_without_displaying_path_or_contents() {
        let home = temp_home("top-level-reply-latest-file");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private original message",
        );
        let payload_path = home.join("latest-reply.bin");
        fs::write(&payload_path, b"private latest file reply").expect("reply file writes");

        let output = run_with_home(
            [
                "reply",
                "agent.receiver",
                "--latest",
                "--file",
                payload_path.to_str().expect("path utf8"),
                "--json",
            ],
            Some(home.clone()),
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.sender").expect("inbox reads");
        let payload =
            messages::read_message_payload(Some(home), "agent.sender", &inbox[0].envelope_id)
                .expect("reply payload reads");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(payload.as_bytes(), b"private latest file reply");
        assert!(output.stdout.contains("\"status\": \"delivered\""));
        assert!(output.stdout.contains("\"payloadBytes\": 25"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private latest file reply"));
        assert!(!output.stdout.contains("private original message"));
        assert!(
            !output
                .stdout
                .contains(payload_path.to_str().expect("path utf8"))
        );
    }

    #[test]
    fn messages_reply_latest_empty_inbox_is_safe() {
        let home = temp_home("message-reply-latest-empty");
        register_test_agent(&home, "agent.receiver");

        let output = run_with_home_and_stdin(
            ["messages", "reply", "agent.receiver", "--latest", "--stdin"],
            Some(home.clone()),
            b"private reply contents".to_vec(),
        );

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("latest reply target"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(!output.stderr.contains("private reply contents"));
        assert!(!output.stderr.contains(home.to_str().expect("path utf8")));
    }

    #[test]
    fn messages_send_peer_queues_encrypted_relay_payload() {
        let alice_home = temp_home("remote-message-alice");
        let bob_home = temp_home("remote-message-bob");
        let bob_card = trust::export_peer_card(Some(bob_home)).expect("bob card exports");
        register_test_agent(&alice_home, "agent.sender");

        let trusted = run_with_home(
            [
                "peers",
                "trust",
                &bob_card.node_id,
                &bob_card.display_name,
                "--exchange-key",
                &bob_card.exchange_public_key_hex,
                "--relay",
                &bob_card.relay_endpoint,
                "--json",
            ],
            Some(alice_home.clone()),
        );
        let policy = run_with_home(
            [
                "peers",
                "policy",
                &bob_card.node_id,
                "--messages",
                "true",
                "--json",
            ],
            Some(alice_home.clone()),
        );
        let sent = run_with_home_and_stdin(
            [
                "messages",
                "send",
                "agent.sender",
                "agent.remote",
                "--peer",
                &bob_card.node_id,
                "--stdin",
                "--json",
            ],
            Some(alice_home.clone()),
            b"private message contents".to_vec(),
        );
        let request = std::fs::read_dir(state::StatePaths::from_home(alice_home).relay_outbox_dir)
            .expect("relay outbox reads")
            .next()
            .expect("relay request exists")
            .expect("relay request entry");
        let request_text = std::fs::read_to_string(request.path()).expect("request reads");

        assert_eq!(trusted.code, 0, "{}", trusted.stderr);
        assert_eq!(policy.code, 0, "{}", policy.stderr);
        assert_eq!(sent.code, 0, "{}", sent.stderr);
        assert!(sent.stdout.contains("\"status\": \"queued_remote\""));
        assert!(request_text.contains("payload_privacy = \"peer_encrypted\""));
        assert!(request_text.contains("payload_ciphertext_hex"));
        assert!(!request_text.contains("private message contents"));
    }

    #[test]
    fn messages_inbox_lists_metadata_without_payload() {
        let home = temp_home("message-inbox");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");

        let output = run_with_home(["messages", "inbox", "agent.receiver"], Some(home));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("from agent.sender"));
        assert!(output.stdout.contains("bytes 24"));
        assert!(
            output
                .stdout
                .contains("payload view  contents are not displayed")
        );
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn messages_inbox_json_lists_metadata_without_payload() {
        let home = temp_home("message-inbox-json");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes([7, 8, 9]),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");

        let output = run_with_home(
            ["messages", "inbox", "agent.receiver", "--json"],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"fromAgentId\": \"agent.sender\""));
        assert!(output.stdout.contains("\"payloadBytes\": 3"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
    }

    #[test]
    fn messages_inbox_overview_lists_agent_counts_without_payload() {
        let home = temp_home("message-inbox-overview");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");

        let output = run_with_home(["inbox"], Some(home.clone()));

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("agent inboxes"));
        assert!(
            output
                .stdout
                .contains("agent.sender  messages 0  newest none")
        );
        assert!(output.stdout.contains("agent.receiver  messages 1"));
        assert!(output.stdout.contains("from agent.sender"));
        assert!(output.stdout.contains("conu inbox <agent-id>"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(!output.stdout.contains("private message contents"));

        let json = run_with_home(["messages", "inbox", "--json"], Some(home));

        assert_eq!(json.code, 0, "{}", json.stderr);
        assert!(json.stdout.contains("\"totalAgents\": 2"));
        assert!(json.stdout.contains("\"totalMessages\": 1"));
        assert!(json.stdout.contains("\"agentId\": \"agent.receiver\""));
        assert!(json.stdout.contains("\"messageCount\": 1"));
        assert!(json.stdout.contains("\"newestMessage\": {"));
        assert!(json.stdout.contains("\"fromAgentId\":\"agent.sender\""));
        assert!(json.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!json.stdout.contains("private message contents"));
    }

    #[test]
    fn messages_history_limits_recent_metadata_without_payload() {
        let home = temp_home("message-history-limit");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message one",
        );
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message two",
        );
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message three",
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");

        let output = run_with_home(
            [
                "messages",
                "history",
                "agent.receiver",
                "--limit",
                "2",
                "--json",
            ],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"totalMessages\": 3"));
        assert!(output.stdout.contains("\"returnedMessages\": 2"));
        assert!(output.stdout.contains("\"truncatedBefore\": 1"));
        assert!(output.stdout.contains("\"truncatedAfter\": 0"));
        assert_eq!(output.stdout.matches("\"envelopeId\"").count(), 2);
        assert!(!output.stdout.contains(&inbox[0].envelope_id));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private message"));
    }

    #[test]
    fn messages_history_after_returns_resume_window_without_payload() {
        let home = temp_home("message-history-after");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message one",
        );
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message two",
        );
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message three",
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");

        let output = run_with_home(
            [
                "messages",
                "history",
                "agent.receiver",
                "--after",
                &inbox[0].envelope_id,
                "--limit",
                "1",
                "--json",
            ],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"returnedMessages\": 1"));
        assert!(output.stdout.contains("\"truncatedBefore\": 1"));
        assert!(output.stdout.contains("\"truncatedAfter\": 1"));
        assert!(output.stdout.contains(&format!(
            "\"afterEnvelopeId\": \"{}\"",
            inbox[0].envelope_id
        )));
        assert!(output.stdout.contains(&inbox[1].envelope_id));
        assert!(!output.stdout.contains(&inbox[2].envelope_id));
        assert!(!output.stdout.contains("private message"));
    }

    #[test]
    fn messages_history_text_can_show_newest_first_without_contents() {
        let home = temp_home("message-history-text");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message one",
        );
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message two",
        );

        let output = run_with_home(
            [
                "messages",
                "history",
                "agent.receiver",
                "--limit",
                "2",
                "--newest-first",
            ],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("conU messages history"));
        assert!(output.stdout.contains("order: newest-first"));
        assert!(output.stdout.contains("returnedMessages: 2"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(!output.stdout.contains("private message"));
    }

    #[test]
    fn messages_history_missing_after_does_not_display_paths_or_payload() {
        let home = temp_home("message-history-missing-after");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"private message one",
        );

        let output = run_with_home(
            [
                "messages",
                "history",
                "agent.receiver",
                "--after",
                "env.missing",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(!output.stderr.contains(home.to_str().expect("path utf8")));
        assert!(!output.stderr.contains("private message"));
    }

    #[test]
    fn messages_reply_delivers_to_original_sender_without_original_payload() {
        let home = temp_home("message-reply-delivered");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"original private message",
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");

        let output = run_with_home_and_stdin(
            [
                "messages",
                "reply",
                "agent.receiver",
                &inbox[0].envelope_id,
                "--stdin",
                "--json",
            ],
            Some(home.clone()),
            b"private reply contents".to_vec(),
        );
        let sender_inbox =
            messages::list_agent_inbox(Some(home), "agent.sender").expect("sender inbox reads");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"delivered\""));
        assert!(
            output
                .stdout
                .contains("\"fromAgentId\": \"agent.receiver\"")
        );
        assert!(output.stdout.contains("\"toAgentId\": \"agent.sender\""));
        assert!(output.stdout.contains("\"inReplyToEnvelopeId\""));
        assert!(output.stdout.contains("\"payloadBytes\": 22"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(sender_inbox.iter().any(|entry| {
            entry.from_agent_id == "agent.receiver"
                && entry.to_agent_id == "agent.sender"
                && entry.payload_bytes == 22
        }));
        assert!(!output.stdout.contains("original private message"));
        assert!(!output.stdout.contains("private reply contents"));
    }

    #[test]
    fn messages_reply_round_trip_delivers_to_original_sender_after_processing() {
        let home = temp_home("message-reply-round-trip");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"original private message",
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");

        let output = run_with_home_and_stdin(
            [
                "messages",
                "reply",
                "agent.receiver",
                &inbox[0].envelope_id,
                "--stdin",
            ],
            Some(home.clone()),
            b"useful reply bytes".to_vec(),
        );
        messages::process_message_requests(Some(home.clone())).expect("reply processes");
        let sender_inbox =
            messages::list_agent_inbox(Some(home), "agent.sender").expect("sender inbox reads");

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("conU messages reply"));
        assert!(output.stdout.contains("from: agent.receiver"));
        assert!(output.stdout.contains("to: agent.sender"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(!output.stdout.contains("original private message"));
        assert!(!output.stdout.contains("useful reply bytes"));
        assert_eq!(sender_inbox.len(), 1);
        assert_eq!(sender_inbox[0].from_agent_id, "agent.receiver");
        assert_eq!(sender_inbox[0].to_agent_id, "agent.sender");
        assert_eq!(sender_inbox[0].payload_bytes, 18);
    }

    #[test]
    fn messages_reply_missing_target_does_not_display_paths_or_payload() {
        let home = temp_home("message-reply-missing-target");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        deliver_test_message(
            &home,
            "agent.sender",
            "agent.receiver",
            b"original private message",
        );

        let output = run_with_home_and_stdin(
            [
                "messages",
                "reply",
                "agent.receiver",
                "env.missing",
                "--stdin",
            ],
            Some(home.clone()),
            b"private reply contents".to_vec(),
        );

        assert_eq!(output.code, 1);
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(!output.stderr.contains(home.to_str().expect("path utf8")));
        assert!(!output.stderr.contains("original private message"));
        assert!(!output.stderr.contains("private reply contents"));
    }

    #[test]
    fn messages_receive_writes_payload_to_new_output_without_displaying_contents() {
        let home = temp_home("message-receive-output");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let output_path = home.join("received.bin");

        let output = run_with_home(
            [
                "messages",
                "receive",
                "agent.receiver",
                &inbox[0].envelope_id,
                "--output",
                output_path.to_str().expect("path utf8"),
                "--json",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(
            fs::read(&output_path).expect("received output reads"),
            b"private message contents"
        );
        assert!(output.stdout.contains("\"status\": \"written\""));
        assert!(output.stdout.contains("\"payloadBytes\": 24"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            !output
                .stdout
                .contains(output_path.to_str().expect("path utf8"))
        );
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn messages_receive_text_output_keeps_path_and_contents_hidden() {
        let home = temp_home("message-receive-text-output");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let output_path = home.join("received.bin");

        let output = run_with_home(
            [
                "messages",
                "receive",
                "agent.receiver",
                &inbox[0].envelope_id,
                "--output",
                output_path.to_str().expect("path utf8"),
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(
            fs::read(&output_path).expect("received output reads"),
            b"private message contents"
        );
        assert!(output.stdout.contains("status: written"));
        assert!(output.stdout.contains("pathDisplayed=false"));
        assert!(output.stdout.contains("contentsDisplayed=false"));
        assert!(
            !output
                .stdout
                .contains(output_path.to_str().expect("path utf8"))
        );
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn receive_latest_processes_queue_and_writes_payload_without_displaying_contents() {
        let home = temp_home("message-receive-latest");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private latest contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        let output_path = home.join("latest.bin");

        let output = run_with_home(
            [
                "receive",
                "agent.receiver",
                "--latest",
                "--output",
                output_path.to_str().expect("path utf8"),
                "--process-ipc",
                "--timeout-ms",
                "1000",
                "--json",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(
            fs::read(&output_path).expect("latest output reads"),
            b"private latest contents"
        );
        assert!(output.stdout.contains("\"status\": \"written\""));
        assert!(output.stdout.contains("\"mode\": \"latest\""));
        assert!(output.stdout.contains("\"fromAgentId\": \"agent.sender\""));
        assert!(output.stdout.contains("\"payloadBytes\": 23"));
        assert!(output.stdout.contains("\"processIpc\": true"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            !output
                .stdout
                .contains(output_path.to_str().expect("path utf8"))
        );
        assert!(!output.stdout.contains("private latest contents"));
    }

    #[test]
    fn receive_latest_timeout_does_not_create_output_or_display_path() {
        let home = temp_home("message-receive-latest-timeout");
        register_test_agent(&home, "agent.receiver");
        let output_path = home.join("timeout.bin");

        let output = run_with_home(
            [
                "receive",
                "agent.receiver",
                "--latest",
                "--output",
                output_path.to_str().expect("path utf8"),
                "--timeout-ms",
                "0",
                "--json",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(!output_path.exists());
        assert!(output.stdout.contains("\"status\": \"timeout\""));
        assert!(output.stdout.contains("\"outputWritten\": false"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            !output
                .stdout
                .contains(output_path.to_str().expect("path utf8"))
        );
        assert!(!output.stdout.contains(home.to_str().expect("path utf8")));
    }

    #[test]
    fn receive_latest_requires_latest_for_wait_options() {
        let output = run_with_home(
            [
                "receive",
                "agent.receiver",
                "env.one",
                "--output",
                "received.bin",
                "--process-ipc",
            ],
            Some(temp_home("message-receive-latest-usage")),
        );

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("conu receive <agent-id> --latest"));
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn pull_processes_queue_and_writes_named_payload_without_displaying_contents() {
        let home = temp_home("message-pull-output");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private pull contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        let output_dir = home.join("pulled");

        let output = run_with_home(
            [
                "pull",
                "agent.receiver",
                "--dir",
                output_dir.to_str().expect("path utf8"),
                "--process-ipc",
                "--timeout-ms",
                "1000",
                "--json",
            ],
            Some(home.clone()),
        );
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let file_name = pull_output_file_name(&inbox[0]);
        let output_path = output_dir.join(&file_name);

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(
            fs::read(&output_path).expect("pulled output reads"),
            b"private pull contents"
        );
        assert!(output.stdout.contains("\"status\": \"written\""));
        assert!(output.stdout.contains("\"mode\": \"pull\""));
        assert!(output.stdout.contains("\"fromAgentId\": \"agent.sender\""));
        assert!(
            output
                .stdout
                .contains(&format!("\"fileName\": \"{file_name}\""))
        );
        assert!(output.stdout.contains("\"payloadBytes\": 21"));
        assert!(output.stdout.contains("\"processIpc\": true"));
        assert!(output.stdout.contains("\"outputDirDisplayed\": false"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            !output
                .stdout
                .contains(output_dir.to_str().expect("path utf8"))
        );
        assert!(
            !output
                .stdout
                .contains(output_path.to_str().expect("path utf8"))
        );
        assert!(!output.stdout.contains("private pull contents"));
    }

    #[test]
    fn pull_timeout_does_not_create_output_dir_or_display_path() {
        let home = temp_home("message-pull-timeout");
        register_test_agent(&home, "agent.receiver");
        let output_dir = home.join("pull-timeout");

        let output = run_with_home(
            [
                "messages",
                "pull",
                "agent.receiver",
                "--dir",
                output_dir.to_str().expect("path utf8"),
                "--timeout-ms",
                "0",
                "--json",
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(!output_dir.exists());
        assert!(output.stdout.contains("\"status\": \"timeout\""));
        assert!(output.stdout.contains("\"mode\": \"pull\""));
        assert!(output.stdout.contains("\"outputWritten\": false"));
        assert!(output.stdout.contains("\"outputDirDisplayed\": false"));
        assert!(output.stdout.contains("\"pathDisplayed\": false"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(
            !output
                .stdout
                .contains(output_dir.to_str().expect("path utf8"))
        );
        assert!(!output.stdout.contains(home.to_str().expect("path utf8")));
    }

    #[test]
    fn pull_rejects_existing_named_output_without_payload_or_path() {
        let home = temp_home("message-pull-existing-output");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private pull contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let output_dir = home.join("pulled");
        fs::create_dir_all(&output_dir).expect("output dir creates");
        let output_path = output_dir.join(pull_output_file_name(&inbox[0]));
        fs::write(&output_path, b"existing").expect("existing output writes");

        let output = run_with_home(
            [
                "pull",
                "agent.receiver",
                "--dir",
                output_dir.to_str().expect("path utf8"),
                "--json",
            ],
            Some(home),
        );

        assert_eq!(output.code, 1);
        assert_eq!(
            fs::read(&output_path).expect("existing output reads"),
            b"existing"
        );
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(
            !output
                .stderr
                .contains(output_dir.to_str().expect("path utf8"))
        );
        assert!(
            !output
                .stderr
                .contains(output_path.to_str().expect("path utf8"))
        );
        assert!(!output.stderr.contains("private pull contents"));
    }

    #[test]
    fn messages_receive_rejects_existing_output_without_payload_or_path() {
        let home = temp_home("message-receive-existing-output");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");
        let inbox =
            messages::list_agent_inbox(Some(home.clone()), "agent.receiver").expect("inbox reads");
        let output_path = home.join("received.bin");
        fs::write(&output_path, b"existing").expect("existing output writes");

        let output = run_with_home(
            [
                "messages",
                "receive",
                "agent.receiver",
                &inbox[0].envelope_id,
                "--output",
                output_path.to_str().expect("path utf8"),
            ],
            Some(home),
        );

        assert_eq!(output.code, 1);
        assert_eq!(
            fs::read(&output_path).expect("existing output reads"),
            b"existing"
        );
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(
            !output
                .stderr
                .contains(output_path.to_str().expect("path utf8"))
        );
        assert!(!output.stderr.contains("private message contents"));
    }

    #[test]
    fn messages_receive_missing_envelope_does_not_display_inbox_path() {
        let home = temp_home("message-receive-missing-envelope");
        register_test_agent(&home, "agent.receiver");
        let output_path = home.join("received.bin");

        let output = run_with_home(
            [
                "messages",
                "receive",
                "agent.receiver",
                "env.missing",
                "--output",
                output_path.to_str().expect("path utf8"),
            ],
            Some(home.clone()),
        );

        assert_eq!(output.code, 1);
        assert!(!output_path.exists());
        assert!(output.stderr.contains("pathDisplayed=false"));
        assert!(output.stderr.contains("contentsDisplayed=false"));
        assert!(!output.stderr.contains(home.to_str().expect("path utf8")));
        assert!(
            !output
                .stderr
                .contains(output_path.to_str().expect("path utf8"))
        );
    }

    #[test]
    fn messages_wait_returns_existing_metadata_without_payload() {
        let home = temp_home("message-wait-existing");
        register_test_agent(&home, "agent.sender");
        register_test_agent(&home, "agent.receiver");
        let message = LocalMessage::new(
            "agent.sender",
            "agent.receiver",
            OpaquePayload::from_bytes(b"private message contents".to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.clone()), message).expect("message submits");
        messages::process_message_requests(Some(home.clone())).expect("message processes");

        let output = run_with_home(
            [
                "messages",
                "wait",
                "agent.receiver",
                "--timeout-ms",
                "0",
                "--json",
            ],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"delivered\""));
        assert!(output.stdout.contains("\"fromAgentId\": \"agent.sender\""));
        assert!(output.stdout.contains("\"payloadBytes\": 24"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn messages_send_processes_pending_agents_before_local_delivery() {
        let home = temp_home("message-send-processes-agents");
        let sender = run_with_home(
            [
                "agents",
                "register",
                "agent.sender",
                "Sender",
                "--kind",
                "test-agent",
            ],
            Some(home.clone()),
        );
        let receiver = run_with_home(
            [
                "agents",
                "register",
                "agent.receiver",
                "Receiver",
                "--kind",
                "test-agent",
            ],
            Some(home.clone()),
        );
        let sent = run_with_home_and_stdin(
            [
                "messages",
                "send",
                "agent.sender",
                "agent.receiver",
                "--stdin",
                "--json",
            ],
            Some(home.clone()),
            b"private message contents".to_vec(),
        );

        assert_eq!(sender.code, 0, "{}", sender.stderr);
        assert_eq!(receiver.code, 0, "{}", receiver.stderr);
        let waited = run_with_home(
            [
                "messages",
                "wait",
                "agent.receiver",
                "--process-ipc",
                "--timeout-ms",
                "1000",
                "--interval-ms",
                "1",
                "--json",
            ],
            Some(home),
        );

        assert_eq!(sent.code, 0, "{}", sent.stderr);
        assert!(sent.stdout.contains("\"status\": \"delivered\""));
        assert_eq!(waited.code, 0, "{}", waited.stderr);
        assert!(waited.stdout.contains("\"status\": \"delivered\""));
        assert!(waited.stdout.contains("\"processIpc\": true"));
        assert!(waited.stdout.contains("\"payloadBytes\": 24"));
        assert!(!waited.stdout.contains("private message contents"));
    }

    #[test]
    fn messages_wait_timeout_is_payload_safe() {
        let home = temp_home("message-wait-timeout");

        let output = run_with_home(
            [
                "messages",
                "wait",
                "agent.receiver",
                "--timeout-ms",
                "0",
                "--json",
            ],
            Some(home),
        );

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert!(output.stdout.contains("\"status\": \"timeout\""));
        assert!(output.stdout.contains("\"message\": null"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
    }

    #[test]
    fn messages_send_requires_stdin_flag() {
        let output = run(["messages", "send", "agent.sender", "agent.receiver"]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("conu messages send"));
    }

    #[test]
    fn init_creates_state_and_status_reads_it() {
        let home = temp_home("init-status");

        let init = run_with_home(["init"], Some(home.clone()));
        let status = run_with_home(["status"], Some(home));

        assert_eq!(init.code, 0, "{}", init.stderr);
        assert!(init.stdout.contains("status: created"));
        assert!(init.stdout.contains("node_"));
        assert_eq!(status.code, 0, "{}", status.stderr);
        assert!(status.stdout.contains("state         initialized"));
        assert!(status.stdout.contains("trust store   ready"));
    }

    #[test]
    fn status_detects_runtime_heartbeat() {
        let home = temp_home("status-runtime");
        let _lease = runtime::acquire_runtime(Some(home.clone())).expect("runtime starts");

        let status = run_with_home(["status"], Some(home));

        assert_eq!(status.code, 0, "{}", status.stderr);
        assert!(status.stdout.contains("conUD         running"));
        assert!(status.stdout.contains("health        file heartbeat ok"));
    }

    #[test]
    fn start_reports_already_running_without_spawning() {
        let home = temp_home("start-running");
        let _lease = runtime::acquire_runtime(Some(home.clone())).expect("runtime starts");

        let start = run_with_home(["start"], Some(home));

        assert_eq!(start.code, 0, "{}", start.stderr);
        assert!(start.stdout.contains("status: already running"));
    }

    #[test]
    fn runtime_start_retries_only_transient_control_file_races() {
        assert!(runtime_start_read_error_is_retryable(
            "read runtime status at status.toml: runtime control path changed while reading"
        ));
        assert!(runtime_start_read_error_is_retryable(
            "inspect runtime status at status.toml: runtime control path changed while opening"
        ));
        assert!(!runtime_start_read_error_is_retryable(
            "read runtime status at status.toml: runtime control file exceeds 1048576 bytes"
        ));
        assert!(!runtime_start_read_error_is_retryable(
            "read runtime status at status.toml: runtime control path is missing"
        ));
    }

    #[test]
    fn stop_requests_running_runtime() {
        let home = temp_home("stop-running");
        let _lease = runtime::acquire_runtime(Some(home.clone())).expect("runtime starts");
        let stop_path = state::StatePaths::from_home(home.clone()).runtime_stop_request;

        let stop = run_with_home(["stop"], Some(home));

        assert_eq!(stop.code, 0, "{}", stop.stderr);
        assert!(stop.stdout.contains("status: stop requested"));
        assert!(stop_path.exists());
    }

    #[test]
    fn init_is_idempotent() {
        let home = temp_home("init-idempotent");

        let first = run_with_home(["init"], Some(home.clone()));
        let second = run_with_home(["init"], Some(home));

        assert_eq!(first.code, 0, "{}", first.stderr);
        assert_eq!(second.code, 0, "{}", second.stderr);
        assert!(first.stdout.contains("status: created"));
        assert!(second.stdout.contains("status: already initialized"));
        assert!(second.stdout.contains("node identity  kept"));
    }

    #[test]
    fn status_json_is_machine_readable_shape() {
        let home = temp_home("status-json");
        let init = run_with_home(["init"], Some(home.clone()));
        assert_eq!(init.code, 0, "{}", init.stderr);

        let output = run_with_home(["status", "--json"], Some(home));

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("\"conud\": \"offline\""));
        assert!(output.stdout.contains("\"localIpc\": \"file_gateway\""));
        assert!(output.stdout.contains("\"state\": \"initialized\""));
        assert!(output.stdout.contains("\"node\": \"node_"));
        assert!(output.stdout.contains("\"remote\": 0"));
        assert!(output.stdout.contains("\"trustedPeers\": 0"));
        assert!(output.stdout.contains("\"sessions\": 0"));
        assert!(output.stdout.contains("\"streams\": 0"));
        assert!(output.stdout.contains("\"contentsDisplayed\": false"));
    }

    #[test]
    fn join_requires_a_code() {
        let output = run(["join"]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("usage: conu join <code>"));
    }

    #[test]
    fn watch_never_prints_message_contents() {
        let output = run(["watch"]);

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("contents      not displayed"));
        assert!(!output.stdout.contains("Review this code"));
        assert!(!output.stdout.contains("private message contents"));
    }

    #[test]
    fn unknown_command_fails_with_help() {
        let output = run(["unknown"]);

        assert_eq!(output.code, 2);
        assert!(output.stderr.contains("unknown command"));
        assert!(output.stderr.contains("Usage:"));
    }

    #[test]
    fn unknown_cli_arguments_do_not_echo_secret_like_values() {
        let secret_command = "secret-relay-token";
        let secret_option = "--secret-relay-token";
        let secret_argument = "secret-extra-argument";

        let command = run([secret_command]);
        let option = run(["agents", "export", secret_option]);
        let argument = run(["dashboard", secret_argument]);

        for output in [command, option, argument] {
            assert_eq!(output.code, 2);
            assert!(output.stderr.contains("contentsDisplayed=false"));
            assert!(!output.stderr.contains(secret_command));
            assert!(!output.stderr.contains(secret_option));
            assert!(!output.stderr.contains(secret_argument));
        }
    }

    fn temp_home(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        std::env::temp_dir().join(format!("conu-cli-test-{label}-{}-{nonce}", process::id()))
    }

    fn write_update_policy_fixture(directory: &Path, auto_apply: bool) -> PathBuf {
        write_update_policy_fixture_with_asset_sha(directory, auto_apply, &"0".repeat(64))
    }

    fn write_update_policy_fixture_with_asset_sha(
        directory: &Path,
        auto_apply: bool,
        asset_sha: &str,
    ) -> PathBuf {
        write_update_policy_fixture_for_asset(
            directory,
            auto_apply,
            asset_sha,
            "linux-x64",
            "conu-0.1.0-linux-x64.tar.gz",
        )
    }

    fn write_update_policy_fixture_for_asset(
        directory: &Path,
        auto_apply: bool,
        asset_sha: &str,
        target: &str,
        filename: &str,
    ) -> PathBuf {
        fs::create_dir_all(directory).expect("fixture dir creates");
        let policy = directory.join("conu-0.1.0-update-policy.json");
        let release_base = "https://github.com/imthegoodboy/conU/releases/download/v0.1.0";
        let policy_text = format!(
            r#"{{
  "apply": {{
    "autoApply": {auto_apply},
    "downgradeAllowed": false,
    "manualVerificationRequired": true,
    "operatorConsentRequired": true
  }},
  "channel": "stable",
  "ciphertextDisplayed": false,
  "contentsDisplayed": false,
  "keyMaterialDisplayed": false,
  "linuxPackageAssets": [
    {{
      "filename": "conu_0.1.0_amd64.deb",
      "kind": "debian-package",
      "sha256": "{asset_sha}",
      "sha256Url": "{release_base}/conu_0.1.0_amd64.deb.sha256",
      "signatureUrl": "{release_base}/conu_0.1.0_amd64.deb.asc",
      "target": "linux-x64",
      "url": "{release_base}/conu_0.1.0_amd64.deb"
    }}
  ],
  "npm": {{
    "packages": [
      {{
        "name": "@imthegoodboy/conu",
        "version": "0.1.0"
      }}
    ],
    "registry": "https://registry.npmjs.org"
  }},
  "packageManagerAssets": [
    {{
      "filename": "conu.rb",
      "kind": "package-manager",
      "packageManager": "homebrew-formula",
      "sha256": "{asset_sha}",
      "url": "{release_base}/conu.rb"
    }}
  ],
  "payloadDisplayed": false,
  "platformArchives": [
    {{
      "filename": "{filename}",
      "kind": "platform-archive",
      "sha256": "{asset_sha}",
      "sha256Url": "{release_base}/{filename}.sha256",
      "signatureUrl": "{release_base}/{filename}.asc",
      "target": "{target}",
      "url": "{release_base}/{filename}"
    }}
  ],
  "policyAsset": {{
    "cacheControl": "no-cache",
    "filename": "conu-0.1.0-update-policy.json",
    "sha256Url": "{release_base}/conu-0.1.0-update-policy.json.sha256",
    "signatureUrl": "{release_base}/conu-0.1.0-update-policy.json.asc",
    "url": "{release_base}/conu-0.1.0-update-policy.json"
  }},
  "product": "conU",
  "releaseBaseUrl": "{release_base}",
  "releaseTag": "v0.1.0",
  "repositoryAssets": [
    {{
      "filename": "conu-linux-gpg-key.asc",
      "kind": "linux-gpg-public-key",
      "sha256": "{asset_sha}",
      "sha256Url": "{release_base}/conu-linux-gpg-key.asc.sha256",
      "url": "{release_base}/conu-linux-gpg-key.asc"
    }}
  ],
  "schema": "conu.releaseUpdatePolicy.v1",
  "sourceRepository": "https://github.com/imthegoodboy/conU",
  "tokenDisplayed": false,
  "verification": {{
    "githubArtifactAttestationsExpectedForPlatformArchives": true,
    "linuxDetachedSignaturesRequired": true,
    "policyDetachedSignatureRequired": true,
    "strictSha256SidecarsRequired": true
  }},
  "version": "0.1.0"
}}
"#,
            asset_sha = asset_sha,
            filename = filename,
            target = target
        );
        fs::write(&policy, policy_text).expect("policy writes");
        let digest = sha256_hex(&fs::read(&policy).expect("policy reads"));
        fs::write(
            policy.with_file_name("conu-0.1.0-update-policy.json.sha256"),
            format!("{digest}  conu-0.1.0-update-policy.json\n"),
        )
        .expect("sidecar writes");
        fs::write(
            policy.with_file_name("conu-0.1.0-update-policy.json.asc"),
            "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n",
        )
        .expect("signature writes");
        policy
    }

    fn update_apply_test_target() -> String {
        default_update_target()
            .expect("test runner has supported update target")
            .to_string()
    }

    fn update_archive_fixture_name(target: &str) -> String {
        format!("conu-0.1.0-{target}.tar.gz")
    }

    fn update_zip_archive_fixture_name(target: &str) -> String {
        format!("conu-0.1.0-{target}.zip")
    }

    fn update_archive_fixture_bytes(target: &str, unsafe_member: bool) -> Vec<u8> {
        let root = format!("conu-0.1.0-{target}");
        update_archive_fixture_bytes_with_root(target, &root, unsafe_member)
    }

    fn update_archive_fixture_bytes_with_manifest(target: &str, manifest: &str) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let root = format!("conu-0.1.0-{target}");
        append_update_archive_fixture_file(
            &mut builder,
            &format!("{root}/manifest.toml"),
            manifest.as_bytes(),
            0o644,
        );
        for name in UPDATE_BINARY_NAMES {
            append_update_archive_fixture_file(
                &mut builder,
                &format!("{root}/bin/{}", update_binary_filename(name)),
                &update_archive_binary_bytes(name),
                0o755,
            );
        }
        builder.finish().expect("tar builder finishes");
        let encoder = builder.into_inner().expect("tar encoder returns");
        encoder.finish().expect("gzip finishes")
    }

    fn update_archive_fixture_bytes_with_root(
        target: &str,
        root: &str,
        unsafe_member: bool,
    ) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let manifest = format!(
            "version = \"0.1.0\"\ntarget = \"{target}\"\npayload_contents_included = false\n"
        );
        append_update_archive_fixture_file(
            &mut builder,
            &format!("{root}/manifest.toml"),
            manifest.as_bytes(),
            0o644,
        );
        for name in UPDATE_BINARY_NAMES {
            append_update_archive_fixture_file(
                &mut builder,
                &format!("{root}/bin/{}", update_binary_filename(name)),
                &update_archive_binary_bytes(name),
                0o755,
            );
        }
        if unsafe_member {
            append_update_archive_fixture_file(&mut builder, "../bin/conu", b"escape", 0o755);
        }
        builder.finish().expect("tar builder finishes");
        let encoder = builder.into_inner().expect("tar encoder returns");
        encoder.finish().expect("gzip finishes")
    }

    fn update_archive_fixture_bytes_with_extra_file(
        target: &str,
        extra_path: &str,
        extra_bytes: &[u8],
    ) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let root = format!("conu-0.1.0-{target}");
        let manifest = format!(
            "version = \"0.1.0\"\ntarget = \"{target}\"\npayload_contents_included = false\n"
        );
        append_update_archive_fixture_file(
            &mut builder,
            &format!("{root}/manifest.toml"),
            manifest.as_bytes(),
            0o644,
        );
        for name in UPDATE_BINARY_NAMES {
            append_update_archive_fixture_file(
                &mut builder,
                &format!("{root}/bin/{}", update_binary_filename(name)),
                &update_archive_binary_bytes(name),
                0o755,
            );
        }
        append_update_archive_fixture_file(&mut builder, extra_path, extra_bytes, 0o755);
        builder.finish().expect("tar builder finishes");
        let encoder = builder.into_inner().expect("tar encoder returns");
        encoder.finish().expect("gzip finishes")
    }

    fn update_archive_fixture_bytes_with_mixed_root(target: &str) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let root = format!("conu-0.1.0-{target}");
        let manifest = format!(
            "version = \"0.1.0\"\ntarget = \"{target}\"\npayload_contents_included = false\n"
        );
        append_update_archive_fixture_file(
            &mut builder,
            &format!("{root}/manifest.toml"),
            manifest.as_bytes(),
            0o644,
        );
        append_update_archive_fixture_file(
            &mut builder,
            &format!("bin/{}", update_binary_filename("conu")),
            &update_archive_binary_bytes("conu"),
            0o755,
        );
        builder.finish().expect("tar builder finishes");
        let encoder = builder.into_inner().expect("tar encoder returns");
        encoder.finish().expect("gzip finishes")
    }

    fn update_archive_fixture_bytes_with_raw_member_name(raw_name: &[u8], bytes: &[u8]) -> Vec<u8> {
        assert!(
            raw_name.len() <= 100,
            "raw tar fixture member name must fit the ustar name field"
        );
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_mut_bytes()[..raw_name.len()].copy_from_slice(raw_name);
        header.set_cksum();
        builder
            .append(&header, bytes)
            .expect("raw tar fixture member appends");
        builder.finish().expect("tar builder finishes");
        let encoder = builder.into_inner().expect("tar encoder returns");
        encoder.finish().expect("gzip finishes")
    }

    fn update_zip_archive_fixture_bytes(target: &str, unsafe_member: bool) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let root = format!("conu-0.1.0-{target}");
        let manifest = format!(
            "version = \"0.1.0\"\ntarget = \"{target}\"\npayload_contents_included = false\n"
        );
        append_update_zip_archive_fixture_file(
            &mut writer,
            &format!("{root}/manifest.toml"),
            manifest.as_bytes(),
            0o644,
        );
        for name in UPDATE_BINARY_NAMES {
            append_update_zip_archive_fixture_file(
                &mut writer,
                &format!("{root}/bin/{}", update_binary_filename(name)),
                &update_archive_binary_bytes(name),
                0o755,
            );
        }
        if unsafe_member {
            append_update_zip_archive_fixture_file(&mut writer, "../bin/conu", b"escape", 0o755);
        }
        writer.finish().expect("zip finishes").into_inner()
    }

    fn append_update_archive_fixture_file<W: Write>(
        builder: &mut tar::Builder<W>,
        path: &str,
        bytes: &[u8],
        mode: u32,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .expect("tar fixture file appends");
    }

    fn append_update_zip_archive_fixture_file<W: Write + io::Seek>(
        writer: &mut zip::ZipWriter<W>,
        path: &str,
        bytes: &[u8],
        mode: u32,
    ) {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(mode);
        writer
            .start_file(path, options)
            .expect("zip fixture file starts");
        writer.write_all(bytes).expect("zip fixture file writes");
    }

    fn update_archive_binary_bytes(name: &str) -> Vec<u8> {
        format!("fixture binary bytes for {name}\n").into_bytes()
    }

    fn write_update_artifact_fixture(directory: &Path, filename: &str, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(directory).expect("artifact dir creates");
        let artifact = directory.join(filename);
        fs::write(&artifact, bytes).expect("artifact writes");
        let digest = sha256_hex(bytes);
        fs::write(
            sidecar_path(&artifact, ".sha256"),
            format!("{digest}  {filename}\n"),
        )
        .expect("artifact sidecar writes");
        fs::write(
            sidecar_path(&artifact, ".asc"),
            "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n",
        )
        .expect("artifact signature writes");
        artifact
    }

    fn pairing_code_from_output(output: &str) -> String {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix("code: "))
            .expect("pairing code line")
            .to_string()
    }

    fn stream_id_from_output(output: &str) -> String {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix("stream: "))
            .expect("stream id line")
            .to_string()
    }

    fn config_key_suffix_for_test(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn assert_update_archive_member_error_redacted(error: &str, expected: &str, forbidden: &str) {
        assert!(error.contains(expected), "{error}");
        assert!(error.contains("pathDisplayed=false"), "{error}");
        assert!(error.contains("contentsDisplayed=false"), "{error}");
        assert!(!error.contains(forbidden), "{error}");
    }

    fn deliver_test_message(home: &Path, from_agent: &str, to_agent: &str, payload: &[u8]) {
        let message = LocalMessage::new(
            from_agent,
            to_agent,
            OpaquePayload::from_bytes(payload.to_vec()),
        )
        .expect("message valid");
        messages::submit_local_message(Some(home.to_path_buf()), message).expect("message submits");
        messages::process_message_requests(Some(home.to_path_buf())).expect("message processes");
    }

    fn register_test_agent(home: &std::path::Path, agent_id: &str) {
        let mut registration =
            AgentRegistration::new(agent_id, agent_id, "test-agent").expect("valid registration");
        registration.capabilities.streams = true;
        registration.capabilities.rooms = true;
        agents::submit_registration(Some(home.to_path_buf()), registration)
            .expect("request submits");
        agents::process_gateway_requests(Some(home.to_path_buf())).expect("request processes");
    }
}
