use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use conu_core::relay::{
    RelayAdminRequest, RelayAdminResult, RelayClientFrame, RelayServerFrame, RelayWebSocketClient,
};
use conu_relay::{
    CredentialManifestUpdate, IssuedRelayCredential, RelayAccountingPolicy, RelayAccountingStorage,
    RelayConfig, RelayCredential, RelayMailboxPolicy, RelayMailboxStorage, RelaySessionPolicy,
    issue_relay_credential, relay_credential_manifest_contains_node, relay_token_sha256_hex,
    revoke_relay_credential_in_file, upsert_issued_relay_credential_in_file,
    write_issued_relay_token_file,
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--check") => {
            println!("{}", conu_core::scaffold_status("conu-relay"));
            println!("relay: websocket relay ready; ciphertext bodies only; payloads not observed");
            ExitCode::SUCCESS
        }
        Some("--hash-token") => match hash_token_from_stdin() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--issue-credential") => match issue_credential_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--revoke-credential") => match revoke_credential_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--admin-issue-credential") => {
            match admin_issue_credential_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--admin-rotate-credential") => {
            match admin_rotate_credential_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--admin-revoke-credential") => {
            match admin_revoke_credential_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--admin-audit-credentials") => {
            match admin_audit_credentials_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--serve") => {
            let addr = args.next().unwrap_or_else(|| "127.0.0.1:8787".to_string());
            let config = match relay_config_from_env(addr) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    return ExitCode::from(2);
                }
            };
            match conu_relay::run_blocking(config) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("conu-relay {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("unknown option: {unknown}");
            print_help();
            ExitCode::from(2)
        }
        None => {
            println!("conU relay ready. Use `conu-relay --serve 127.0.0.1:8787`.");
            println!("payloads not observed");
            ExitCode::SUCCESS
        }
    }
}

fn print_help() {
    println!(
        r"conu-relay - conU relay and bootstrap scaffold

Usage:
  conu-relay
  conu-relay --serve [addr]
  conu-relay --hash-token
  conu-relay --issue-credential <node-id> --token-out <path> [--credentials-file <path>] [--replace] [--expires-at-unix <seconds>] [--json]
  conu-relay --revoke-credential <node-id> --credentials-file <path> [--json]
  conu-relay --admin-issue-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin --token-out <path> [--expires-at-unix <seconds>] [--json]
  conu-relay --admin-rotate-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin --token-out <path> [--expires-at-unix <seconds>] [--json]
  conu-relay --admin-revoke-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin [--json]
  conu-relay --admin-audit-credentials --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--json]
  conu-relay --check
  conu-relay --help
  conu-relay --version

Environment:
  CONU_RELAY_TOKEN                    shared runtime session token; defaults to local-dev-token for loopback only
  CONU_RELAY_CREDENTIALS              comma-separated node-id:token compatibility credentials
  CONU_RELAY_CREDENTIALS_FILE         preferred live-reloaded scoped credential manifest with token_sha256_hex, status, and expiry metadata
  CONU_RELAY_MAX_CONNECTIONS          active TCP connection cap; defaults to 512
  CONU_RELAY_MAX_CONNECTIONS_PER_IP   per-source-IP connection cap; defaults to 64
  CONU_RELAY_MAX_FRAMES_PER_MINUTE    per-session frame cap; defaults to 600
  CONU_RELAY_IDLE_TIMEOUT_SECONDS     authenticated session idle timeout; defaults to 120
  CONU_RELAY_SESSION_TTL_SECONDS      authenticated session max lifetime; defaults to 3600
  CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE
                                        offline ciphertext envelope cap per node; defaults to 128
  CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS
                                        offline envelope TTL; defaults to 3600
  CONU_RELAY_MAILBOX_DIR              optional durable mailbox directory for peer-encrypted envelopes
  CONU_RELAY_ACCOUNTING_DIR           optional metadata-only accounting directory
  CONU_RELAY_ACCOUNTING_WINDOW_SECONDS
                                        accounting/quota window; defaults to 86400
  CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE
                                        optional per-node sent-envelope quota per accounting window
  CONU_RELAY_MAX_BYTES_SENT_PER_NODE  optional per-node sent-byte quota per accounting window
  CONU_RELAY_ADMIN_TOKEN              optional hosted admin token for online credential lifecycle; requires CONU_RELAY_CREDENTIALS_FILE

CONU_RELAY_CREDENTIALS_FILE overrides CONU_RELAY_CREDENTIALS; CONU_RELAY_CREDENTIALS overrides
CONU_RELAY_TOKEN. Non-loopback binds such as 0.0.0.0 require custom shared or scoped tokens
with at least 24 characters. Use --hash-token with stdin to generate credential-file hash fields,
--issue-credential to generate a scoped token file and optional manifest update, or
--revoke-credential to mark a scoped credential revoked without displaying tokens. Hosted admin
commands authenticate with an admin token read from stdin, send only node-token hash metadata to the
relay, and write the raw node token locally only after the relay confirms the update."
    );
}

fn hash_token_from_stdin() -> Result<(), String> {
    let mut token = String::new();
    io::stdin()
        .read_to_string(&mut token)
        .map_err(|error| format!("read relay token from stdin: {error}"))?;
    let token = token.trim();
    let hash = relay_token_sha256_hex(token).map_err(|error| error.to_string())?;

    println!("token_sha256_hex = \"{hash}\"");
    println!("token_length = {}", token.len());
    println!("token_displayed = false");
    Ok(())
}

fn issue_credential_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_issue_credential_args(args)?;
    if let Some(path) = parsed.credentials_file.as_ref()
        && !parsed.replace
        && relay_credential_manifest_contains_node(path, parsed.node_id.clone())
            .map_err(|error| error.to_string())?
    {
        return Err("relay credential already exists; use --replace to rotate it".to_string());
    }

    let credential = issue_relay_credential(&parsed.node_id, parsed.expires_at_unix)
        .map_err(|error| error.to_string())?;
    write_issued_relay_token_file(&credential, &parsed.token_out)
        .map_err(|error| error.to_string())?;
    let manifest_update = parsed
        .credentials_file
        .as_ref()
        .map(|path| upsert_issued_relay_credential_in_file(path, &credential, parsed.replace))
        .transpose()
        .map_err(|error| error.to_string())?;

    if parsed.json {
        println!(
            "{}",
            render_issued_credential_json(&credential, &parsed.token_out, manifest_update.as_ref())
        );
    } else {
        println!(
            "{}",
            render_issued_credential_text(&credential, &parsed.token_out, manifest_update.as_ref())
        );
    }
    Ok(())
}

struct IssueCredentialArgs {
    node_id: String,
    token_out: PathBuf,
    credentials_file: Option<PathBuf>,
    replace: bool,
    expires_at_unix: Option<u64>,
    json: bool,
}

fn parse_issue_credential_args(args: Vec<String>) -> Result<IssueCredentialArgs, String> {
    let mut positional = Vec::new();
    let mut token_out = None::<PathBuf>;
    let mut credentials_file = None::<PathBuf>;
    let mut replace = false;
    let mut expires_at_unix = None::<u64>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--token-out" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(issue_credential_usage());
                };
                token_out = Some(PathBuf::from(value));
            }
            "--credentials-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(issue_credential_usage());
                };
                credentials_file = Some(PathBuf::from(value));
            }
            "--replace" => replace = true,
            "--expires-at-unix" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(issue_credential_usage());
                };
                expires_at_unix =
                    Some(value.parse::<u64>().map_err(|_| {
                        "--expires-at-unix must be an unsigned integer".to_string()
                    })?);
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(issue_credential_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(issue_credential_usage());
    }
    let Some(token_out) = token_out else {
        return Err(issue_credential_usage());
    };
    if replace && credentials_file.is_none() {
        return Err("--replace requires --credentials-file".to_string());
    }

    Ok(IssueCredentialArgs {
        node_id: positional.remove(0),
        token_out,
        credentials_file,
        replace,
        expires_at_unix,
        json,
    })
}

fn issue_credential_usage() -> String {
    "usage: conu-relay --issue-credential <node-id> --token-out <path> [--credentials-file <path>] [--replace] [--expires-at-unix <seconds>] [--json]".to_string()
}

fn render_issued_credential_text(
    credential: &IssuedRelayCredential,
    token_out: &Path,
    manifest_update: Option<&CredentialManifestUpdate>,
) -> String {
    let mut output = format!(
        r"conU relay credential issued

node: {}
token file: {}
token length: {}
token displayed: no
payload displayed: no
",
        credential.node_id(),
        token_out.display(),
        credential.token_length()
    );
    if let Some(update) = manifest_update {
        output.push_str(&format!(
            r"
credentials file: {}
manifest updated: yes
manifest credentials: {}
replaced: {}
manifest contents displayed: no
",
            update.path.display(),
            update.credentials,
            yes_no(update.replaced)
        ));
    } else {
        output.push_str("\nmanifest entry\n");
        output.push_str(&credential.manifest_entry());
    }
    output
}

fn render_issued_credential_json(
    credential: &IssuedRelayCredential,
    token_out: &Path,
    manifest_update: Option<&CredentialManifestUpdate>,
) -> String {
    let manifest_entry = match manifest_update {
        Some(_) => "null".to_string(),
        None => format!("\"{}\"", json_escape(&credential.manifest_entry())),
    };
    let credentials_file = manifest_update
        .map(|update| format!("\"{}\"", json_escape(&update.path.display().to_string())))
        .unwrap_or_else(|| "null".to_string());
    let manifest_credentials = manifest_update
        .map(|update| update.credentials.to_string())
        .unwrap_or_else(|| "null".to_string());
    let replaced = manifest_update
        .map(|update| bool_json(update.replaced).to_string())
        .unwrap_or_else(|| "null".to_string());
    format!(
        r#"{{
  "status": "issued",
  "nodeId": "{}",
  "tokenPath": "{}",
  "tokenLength": {},
  "expiresAtUnix": {},
  "credentialsFile": {},
  "manifestUpdated": {},
  "manifestCredentials": {},
  "replaced": {},
  "manifestEntry": {},
  "tokenDisplayed": false,
  "contentsDisplayed": false
}}"#,
        json_escape(credential.node_id()),
        json_escape(&token_out.display().to_string()),
        credential.token_length(),
        optional_u64_json(credential.expires_at_unix()),
        credentials_file,
        bool_json(manifest_update.is_some()),
        manifest_credentials,
        replaced,
        manifest_entry
    )
}

fn revoke_credential_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_revoke_credential_args(args)?;
    let update = revoke_relay_credential_in_file(&parsed.credentials_file, &parsed.node_id)
        .map_err(|error| error.to_string())?;

    if parsed.json {
        println!("{}", render_revoke_credential_json(&update));
    } else {
        println!("{}", render_revoke_credential_text(&update));
    }
    Ok(())
}

struct RevokeCredentialArgs {
    node_id: String,
    credentials_file: PathBuf,
    json: bool,
}

fn parse_revoke_credential_args(args: Vec<String>) -> Result<RevokeCredentialArgs, String> {
    let mut positional = Vec::new();
    let mut credentials_file = None::<PathBuf>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--credentials-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(revoke_credential_usage());
                };
                credentials_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(revoke_credential_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(revoke_credential_usage());
    }
    let Some(credentials_file) = credentials_file else {
        return Err(revoke_credential_usage());
    };

    Ok(RevokeCredentialArgs {
        node_id: positional.remove(0),
        credentials_file,
        json,
    })
}

fn revoke_credential_usage() -> String {
    "usage: conu-relay --revoke-credential <node-id> --credentials-file <path> [--json]".to_string()
}

fn render_revoke_credential_text(update: &CredentialManifestUpdate) -> String {
    format!(
        r"conU relay credential revoked

node: {}
credentials file: {}
manifest credentials: {}
token displayed: no
payload displayed: no
manifest contents displayed: no",
        update.node_id,
        update.path.display(),
        update.credentials
    )
}

fn render_revoke_credential_json(update: &CredentialManifestUpdate) -> String {
    format!(
        r#"{{
  "status": "{}",
  "nodeId": "{}",
  "credentialsFile": "{}",
  "manifestCredentials": {},
  "tokenDisplayed": false,
  "contentsDisplayed": false
}}"#,
        update.status.as_str(),
        json_escape(&update.node_id),
        json_escape(&update.path.display().to_string()),
        update.credentials
    )
}

fn admin_issue_credential_from_args(args: Vec<String>) -> Result<(), String> {
    admin_write_credential_from_args(args, AdminCredentialMode::Issue)
}

fn admin_rotate_credential_from_args(args: Vec<String>) -> Result<(), String> {
    admin_write_credential_from_args(args, AdminCredentialMode::Rotate)
}

fn admin_write_credential_from_args(
    args: Vec<String>,
    mode: AdminCredentialMode,
) -> Result<(), String> {
    let parsed = parse_admin_credential_args(args, mode)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    ensure_token_out_available(&parsed.token_out)?;
    let credential = issue_relay_credential(&parsed.node_id, parsed.expires_at_unix)
        .and_then(|credential| credential.with_account_id(parsed.account_id.clone()))
        .map_err(|error| error.to_string())?;
    let request = match mode {
        AdminCredentialMode::Issue => RelayAdminRequest::issue(
            admin_token,
            parsed.account_id.clone(),
            parsed.node_id.clone(),
            credential.token_sha256_hex().to_string(),
            credential.token_length(),
            parsed.expires_at_unix,
        ),
        AdminCredentialMode::Rotate => RelayAdminRequest::rotate(
            admin_token,
            parsed.account_id.clone(),
            parsed.node_id.clone(),
            credential.token_sha256_hex().to_string(),
            credential.token_length(),
            parsed.expires_at_unix,
        ),
    }
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    let expected = mode.success_status();
    if result.status != expected {
        return Err(format!(
            "relay admin {} did not complete: status={}",
            mode.verb(),
            result.status
        ));
    }
    write_issued_relay_token_file(&credential, &parsed.token_out)
        .map_err(|error| error.to_string())?;

    if parsed.json {
        println!(
            "{}",
            render_admin_credential_json(&result, &parsed.relay, &parsed.token_out)
        );
    } else {
        println!(
            "{}",
            render_admin_credential_text(&result, &parsed.relay, &parsed.token_out)
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AdminCredentialMode {
    Issue,
    Rotate,
}

impl AdminCredentialMode {
    fn usage(self) -> String {
        match self {
            Self::Issue => "usage: conu-relay --admin-issue-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin --token-out <path> [--expires-at-unix <seconds>] [--json]".to_string(),
            Self::Rotate => "usage: conu-relay --admin-rotate-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin --token-out <path> [--expires-at-unix <seconds>] [--json]".to_string(),
        }
    }

    fn success_status(self) -> &'static str {
        match self {
            Self::Issue => "issued",
            Self::Rotate => "rotated",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Rotate => "rotate",
        }
    }
}

struct AdminCredentialArgs {
    account_id: String,
    node_id: String,
    relay: String,
    admin_token_stdin: bool,
    token_out: PathBuf,
    expires_at_unix: Option<u64>,
    json: bool,
}

fn parse_admin_credential_args(
    args: Vec<String>,
    mode: AdminCredentialMode,
) -> Result<AdminCredentialArgs, String> {
    let mut positional = Vec::new();
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut token_out = None::<PathBuf>;
    let mut expires_at_unix = None::<u64>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--token-out" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                token_out = Some(PathBuf::from(value));
            }
            "--expires-at-unix" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                expires_at_unix =
                    Some(value.parse::<u64>().map_err(|_| {
                        "--expires-at-unix must be an unsigned integer".to_string()
                    })?);
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(mode.usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(mode.usage());
    }
    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(mode.usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }
    let Some(token_out) = token_out.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(mode.usage());
    };

    Ok(AdminCredentialArgs {
        account_id: positional.remove(0),
        node_id: positional.remove(0),
        relay,
        admin_token_stdin,
        token_out,
        expires_at_unix,
        json,
    })
}

fn admin_revoke_credential_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_revoke_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::revoke(
        admin_token,
        parsed.account_id.clone(),
        parsed.node_id.clone(),
    )
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "revoked" {
        return Err(format!(
            "relay admin revoke did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!("{}", render_admin_result_json(&result, &parsed.relay));
    } else {
        println!("{}", render_admin_result_text(&result, &parsed.relay));
    }
    Ok(())
}

struct AdminRevokeArgs {
    account_id: String,
    node_id: String,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_revoke_args(args: Vec<String>) -> Result<AdminRevokeArgs, String> {
    let mut positional = Vec::new();
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_revoke_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_revoke_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(admin_revoke_usage());
    }
    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_revoke_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminRevokeArgs {
        account_id: positional.remove(0),
        node_id: positional.remove(0),
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_revoke_usage() -> String {
    "usage: conu-relay --admin-revoke-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin [--json]".to_string()
}

fn admin_audit_credentials_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_audit_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::audit(admin_token, parsed.account_id.clone())
        .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "audited" {
        return Err(format!(
            "relay admin audit did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!("{}", render_admin_result_json(&result, &parsed.relay));
    } else {
        println!("{}", render_admin_result_text(&result, &parsed.relay));
    }
    Ok(())
}

struct AdminAuditArgs {
    account_id: Option<String>,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_audit_args(args: Vec<String>) -> Result<AdminAuditArgs, String> {
    let mut account_id = None::<String>;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_audit_usage());
                };
                account_id = Some(value.to_string());
            }
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_audit_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_audit_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(admin_audit_usage()),
        }
        index += 1;
    }

    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_audit_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminAuditArgs {
        account_id,
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_audit_usage() -> String {
    "usage: conu-relay --admin-audit-credentials --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--json]".to_string()
}

fn read_admin_token_from_stdin(required: bool) -> Result<String, String> {
    if !required {
        return Err("--admin-token-stdin is required".to_string());
    }
    let mut token = String::new();
    io::stdin()
        .read_to_string(&mut token)
        .map_err(|error| format!("read relay admin token from stdin: {error}"))?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err("relay admin token cannot be empty".to_string());
    }
    Ok(token)
}

fn ensure_token_out_available(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err("token output file already exists".to_string());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create issued relay token directory: {error}"))?;
    }
    Ok(())
}

fn send_admin_request(relay: &str, request: RelayAdminRequest) -> Result<RelayAdminResult, String> {
    let mut client = RelayWebSocketClient::connect(relay, Duration::from_secs(10))
        .map_err(|error| error.to_string())?;
    client
        .send(&RelayClientFrame::Admin(Box::new(request)))
        .map_err(|error| error.to_string())?;
    match client.read().map_err(|error| error.to_string())? {
        Some(RelayServerFrame::AdminResult(result)) => Ok(result),
        Some(RelayServerFrame::Error { reason }) => {
            Err(format!("relay admin request rejected: {reason}"))
        }
        Some(_) => Err("relay admin request returned an unexpected frame".to_string()),
        None => Err("relay admin request ended without a result".to_string()),
    }
}

fn render_admin_credential_text(
    result: &RelayAdminResult,
    relay: &str,
    token_out: &Path,
) -> String {
    format!(
        r"conU hosted relay credential {}

account: {}
node: {}
relay: {}
token file: {}
token length: {}
expires at unix: {}
credentials: {}
active: {}
revoked: {}
expired: {}
accounts: {}
token displayed: no
payload displayed: no
contents displayed: no",
        result.status,
        result.account_id.as_deref().unwrap_or("unknown"),
        result.node_id.as_deref().unwrap_or("unknown"),
        relay,
        token_out.display(),
        result
            .token_length
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        optional_u64_text(result.expires_at_unix),
        result.credentials,
        result.active,
        result.revoked,
        result.expired,
        result.accounts
    )
}

fn render_admin_credential_json(
    result: &RelayAdminResult,
    relay: &str,
    token_out: &Path,
) -> String {
    format!(
        r#"{{
  "status": "{}",
  "accountId": {},
  "nodeId": {},
  "relay": "{}",
  "tokenPath": "{}",
  "tokenLength": {},
  "expiresAtUnix": {},
  "credentials": {},
  "active": {},
  "revoked": {},
  "expired": {},
  "accounts": {},
  "tokenDisplayed": false,
  "payloadDisplayed": false,
  "contentsDisplayed": false
}}"#,
        json_escape(&result.status),
        optional_string_json(result.account_id.as_deref()),
        optional_string_json(result.node_id.as_deref()),
        json_escape(relay),
        json_escape(&token_out.display().to_string()),
        optional_usize_json(result.token_length),
        optional_u64_json(result.expires_at_unix),
        result.credentials,
        result.active,
        result.revoked,
        result.expired,
        result.accounts
    )
}

fn render_admin_result_text(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r"conU hosted relay admin {}

action: {}
account: {}
node: {}
relay: {}
credentials: {}
active: {}
revoked: {}
expired: {}
accounts: {}
token displayed: no
payload displayed: no
contents displayed: no",
        result.status,
        result.action.as_str(),
        result.account_id.as_deref().unwrap_or("all"),
        result.node_id.as_deref().unwrap_or("none"),
        relay,
        result.credentials,
        result.active,
        result.revoked,
        result.expired,
        result.accounts
    )
}

fn render_admin_result_json(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "accountId": {},
  "nodeId": {},
  "relay": "{}",
  "credentials": {},
  "active": {},
  "revoked": {},
  "expired": {},
  "accounts": {},
  "tokenDisplayed": false,
  "payloadDisplayed": false,
  "contentsDisplayed": false
}}"#,
        json_escape(&result.status),
        result.action.as_str(),
        optional_string_json(result.account_id.as_deref()),
        optional_string_json(result.node_id.as_deref()),
        json_escape(relay),
        result.credentials,
        result.active,
        result.revoked,
        result.expired,
        result.accounts
    )
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn bool_json(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn optional_u64_json(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn optional_usize_json(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn optional_u64_text(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn optional_string_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_string())
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

fn relay_config_from_env(addr: String) -> Result<RelayConfig, String> {
    let limits = relay_limits_from_env()?;
    let session_policy = relay_session_policy_from_env()?;
    let mailbox_policy = relay_mailbox_policy_from_env()?;
    let mailbox_storage = relay_mailbox_storage_from_env()?;
    let accounting_policy = relay_accounting_policy_from_env()?;
    let accounting_storage = relay_accounting_storage_from_env()?;
    let credentials_file = env::var("CONU_RELAY_CREDENTIALS_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let mut config = match credentials_file.clone() {
        Some(path) => RelayConfig::with_scoped_credentials_file(addr, path),
        None => match env::var("CONU_RELAY_CREDENTIALS")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(value) => RelayConfig::with_scoped_credentials(addr, parse_credentials(&value)?),
            None => {
                let token = env::var("CONU_RELAY_TOKEN")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "local-dev-token".to_string());
                RelayConfig::new(addr, token)
            }
        },
    }
    .map_err(|error| error.to_string())?;

    config = config
        .with_limits(limits)
        .with_session_policy(session_policy)
        .with_mailbox_policy(mailbox_policy)
        .with_mailbox_storage(mailbox_storage)
        .with_accounting_policy(accounting_policy)
        .with_accounting_storage(accounting_storage);

    if let Some(admin_token) = env::var("CONU_RELAY_ADMIN_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        let Some(credentials_file) = credentials_file else {
            return Err("CONU_RELAY_ADMIN_TOKEN requires CONU_RELAY_CREDENTIALS_FILE".to_string());
        };
        config = config
            .with_admin_token(admin_token, credentials_file)
            .map_err(|error| error.to_string())?;
    }

    Ok(config)
}

fn relay_limits_from_env() -> Result<conu_relay::RelayLimits, String> {
    conu_relay::RelayLimits::new(
        parse_limit("CONU_RELAY_MAX_CONNECTIONS", 512)?,
        parse_limit("CONU_RELAY_MAX_CONNECTIONS_PER_IP", 64)?,
        parse_limit("CONU_RELAY_MAX_FRAMES_PER_MINUTE", 600)?,
    )
    .map_err(|error| error.to_string())
}

fn relay_session_policy_from_env() -> Result<RelaySessionPolicy, String> {
    RelaySessionPolicy::new(
        Duration::from_secs(parse_duration_seconds(
            "CONU_RELAY_IDLE_TIMEOUT_SECONDS",
            120,
        )?),
        Duration::from_secs(parse_duration_seconds(
            "CONU_RELAY_SESSION_TTL_SECONDS",
            3600,
        )?),
    )
    .map_err(|error| error.to_string())
}

fn relay_mailbox_policy_from_env() -> Result<RelayMailboxPolicy, String> {
    RelayMailboxPolicy::new(
        parse_limit("CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE", 128)?,
        Duration::from_secs(parse_duration_seconds(
            "CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS",
            3600,
        )?),
    )
    .map_err(|error| error.to_string())
}

fn relay_mailbox_storage_from_env() -> Result<RelayMailboxStorage, String> {
    match env::var("CONU_RELAY_MAILBOX_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(path) => RelayMailboxStorage::file_backed(path).map_err(|error| error.to_string()),
        None => Ok(RelayMailboxStorage::memory_only()),
    }
}

fn relay_accounting_policy_from_env() -> Result<RelayAccountingPolicy, String> {
    RelayAccountingPolicy::new(
        Duration::from_secs(parse_duration_seconds(
            "CONU_RELAY_ACCOUNTING_WINDOW_SECONDS",
            86_400,
        )?),
        parse_optional_limit("CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE")?.map(|value| value as u64),
        parse_optional_limit("CONU_RELAY_MAX_BYTES_SENT_PER_NODE")?.map(|value| value as u64),
    )
    .map_err(|error| error.to_string())
}

fn relay_accounting_storage_from_env() -> Result<RelayAccountingStorage, String> {
    match env::var("CONU_RELAY_ACCOUNTING_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(path) => RelayAccountingStorage::file_backed(path).map_err(|error| error.to_string()),
        None => Ok(RelayAccountingStorage::memory_only()),
    }
}

fn parse_limit(name: &str, default: usize) -> Result<usize, String> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| format!("{name} must be an unsigned integer")),
        Err(_) => Ok(default),
    }
}

fn parse_optional_limit(name: &str) -> Result<Option<usize>, String> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| format!("{name} must be an unsigned integer"))?;
            if parsed == 0 {
                Ok(None)
            } else {
                Ok(Some(parsed))
            }
        }
        Err(_) => Ok(None),
    }
}

fn parse_duration_seconds(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(default),
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an unsigned integer")),
        Err(_) => Ok(default),
    }
}

fn parse_credentials(value: &str) -> Result<Vec<RelayCredential>, String> {
    let mut credentials = Vec::new();

    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let (node_id, token) = entry
            .split_once(':')
            .ok_or_else(|| "CONU_RELAY_CREDENTIALS entries must use node-id:token".to_string())?;
        credentials.push(
            RelayCredential::new(node_id.trim(), token.trim())
                .map_err(|error| error.to_string())?,
        );
    }

    if credentials.is_empty() {
        return Err("CONU_RELAY_CREDENTIALS must contain at least one node-id:token pair".into());
    }

    Ok(credentials)
}
