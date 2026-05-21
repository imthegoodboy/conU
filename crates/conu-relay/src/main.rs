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
    CredentialManifestUpdate, HostedCredentialAudit, HostedTenantAudit, HostedTenantManifestUpdate,
    HostedTenantPermissions, IssuedRelayCredential, RelayAbuseAudit, RelayAbusePolicy,
    RelayAbuseStorage, RelayAccountingAudit, RelayAccountingPolicy, RelayAccountingStorage,
    RelayConfig, RelayCredential, RelayMailboxAudit, RelayMailboxMaintenancePolicy,
    RelayMailboxPolicy, RelayMailboxPurgeReport, RelayMailboxStorage, RelaySessionPolicy,
    RelaySessionStorage, audit_hosted_relay_credentials_file, audit_hosted_tenants_file,
    audit_relay_abuse_dir, audit_relay_accounting_dir, audit_relay_mailbox_dir,
    issue_relay_credential, purge_relay_mailbox_dir, relay_credential_manifest_contains_node,
    relay_token_sha256_hex, revoke_hosted_tenant_in_file, revoke_hosted_tenant_node_in_file,
    revoke_relay_credential_in_file, upsert_hosted_tenant_in_file,
    upsert_hosted_tenant_node_in_file, upsert_issued_relay_credential_in_file,
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
        Some("--admin-hosted-dashboard") => {
            match admin_hosted_dashboard_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--admin-mailbox-audit") => match admin_mailbox_audit_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--admin-mailbox-purge") => match admin_mailbox_purge_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--tenant-upsert") => match tenant_upsert_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--tenant-revoke") => match tenant_revoke_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--tenant-node-upsert") => match tenant_node_upsert_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--tenant-node-revoke") => match tenant_node_revoke_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--tenant-audit") => match tenant_audit_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--abuse-audit") => match abuse_audit_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--mailbox-audit") => match mailbox_audit_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--mailbox-purge") => match mailbox_purge_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--hosted-dashboard") => match hosted_dashboard_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
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
  conu-relay --admin-hosted-dashboard --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--node <node-id>] [--json]
  conu-relay --admin-mailbox-audit --relay <ws://host:port/path> --admin-token-stdin [--node <node-id>] [--ttl-seconds <seconds>] [--json]
  conu-relay --admin-mailbox-purge --relay <ws://host:port/path> --admin-token-stdin --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]
  conu-relay --tenant-upsert <account-id> --tenants-file <path> [--json]
  conu-relay --tenant-revoke <account-id> --tenants-file <path> [--json]
  conu-relay --tenant-node-upsert <account-id> <node-id> --tenants-file <path> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] [--signing-key-id <id>] [--exchange-key-id <id>] [--json]
  conu-relay --tenant-node-revoke <account-id> <node-id> --tenants-file <path> [--json]
  conu-relay --tenant-audit --tenants-file <path> [--account <account-id>] [--json]
  conu-relay --abuse-audit --abuse-dir <path> [--node <node-id>] [--json]
  conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--json]
  conu-relay --mailbox-purge --mailbox-dir <path> --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]
  conu-relay --hosted-dashboard [--credentials-file <path>] [--tenants-file <path>] [--accounting-dir <path>] [--abuse-dir <path>] [--account <account-id>] [--node <node-id>] [--json]
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
  CONU_RELAY_SESSION_STATE_DIR        optional metadata-only session state directory
  CONU_RELAY_MAX_OFFLINE_ENVELOPES_PER_NODE
                                        offline ciphertext envelope cap per node; defaults to 128
  CONU_RELAY_OFFLINE_ENVELOPE_TTL_SECONDS
                                        offline envelope TTL; defaults to 3600
  CONU_RELAY_MAILBOX_DIR              optional durable mailbox directory for peer-encrypted envelopes
  CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS
                                        optional relay-local expired mailbox purge interval; 0/empty disables
  CONU_RELAY_ACCOUNTING_DIR           optional metadata-only accounting directory
  CONU_RELAY_ACCOUNTING_WINDOW_SECONDS
                                        accounting/quota window; defaults to 86400
  CONU_RELAY_MAX_ENVELOPES_SENT_PER_NODE
                                        optional per-node sent-envelope quota per accounting window
  CONU_RELAY_MAX_BYTES_SENT_PER_NODE  optional per-node sent-byte quota per accounting window
  CONU_RELAY_ABUSE_DIR                optional metadata-only abuse/dashboard counter directory
  CONU_RELAY_ABUSE_WINDOW_SECONDS     abuse counter window; defaults to 86400
  CONU_RELAY_ADMIN_TOKEN              optional hosted admin token for online credential lifecycle; requires CONU_RELAY_CREDENTIALS_FILE
  CONU_RELAY_TENANTS_FILE             optional hosted tenant metadata registry; requires CONU_RELAY_ADMIN_TOKEN and CONU_RELAY_CREDENTIALS_FILE

CONU_RELAY_CREDENTIALS_FILE overrides CONU_RELAY_CREDENTIALS; CONU_RELAY_CREDENTIALS overrides
CONU_RELAY_TOKEN. Non-loopback binds such as 0.0.0.0 require custom shared or scoped tokens
with at least 24 characters. Use --hash-token with stdin to generate credential-file hash fields,
--issue-credential to generate a scoped token file and optional manifest update, or
--revoke-credential to mark a scoped credential revoked without displaying tokens. Hosted admin
commands authenticate with an admin token read from stdin, send only node-token hash metadata to the
relay, and write the raw node token locally only after the relay confirms the update. Tenant
commands manage account, node, public key-id, and hosted permission metadata only; they never grant
local peer policy or display private keys, tokens, hashes, payloads, or ciphertext bodies. Admin
hosted dashboard snapshots require the admin token over the relay control plane and return
metadata-only credential, tenant, accounting, and abuse counters. Admin mailbox audits and purges
require the admin token over the relay control plane and inspect or clean durable mailbox retention
metadata from the running relay only. Abuse audit reads aggregate enforcement counters only, mailbox
audit reads durable mailbox timestamps and file sizes only, manual and admin mailbox purge require
dry-run or explicit confirmation, and scheduled mailbox purge requires an explicit local interval
plus CONU_RELAY_MAILBOX_DIR before deleting expired durable mailbox files. Hosted dashboard
snapshots combine configured credential, tenant, accounting, and abuse summaries without displaying
tokens, token hashes, payloads, ciphertext bodies, frame contents, private keys, or relay session ids."
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

fn admin_hosted_dashboard_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_dashboard_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::dashboard(
        admin_token,
        parsed.account_id.clone(),
        parsed.node_id.clone(),
    )
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "snapshotted" {
        return Err(format!(
            "relay admin hosted dashboard did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!("{}", render_admin_dashboard_json(&result, &parsed.relay));
    } else {
        println!("{}", render_admin_dashboard_text(&result, &parsed.relay));
    }
    Ok(())
}

#[derive(Debug)]
struct AdminDashboardArgs {
    account_id: Option<String>,
    node_id: Option<String>,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_dashboard_args(args: Vec<String>) -> Result<AdminDashboardArgs, String> {
    let mut account_id = None::<String>;
    let mut node_id = None::<String>;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_dashboard_usage());
                };
                account_id = Some(value.to_string());
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_dashboard_usage());
                };
                node_id = Some(value.to_string());
            }
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_dashboard_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_dashboard_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(admin_dashboard_usage()),
        }
        index += 1;
    }

    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_dashboard_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminDashboardArgs {
        account_id,
        node_id,
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_dashboard_usage() -> String {
    "usage: conu-relay --admin-hosted-dashboard --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--node <node-id>] [--json]".to_string()
}

fn admin_mailbox_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_mailbox_audit_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::mailbox_audit(
        admin_token,
        parsed.node_id.clone(),
        parsed.ttl.map(|ttl| ttl.as_secs()),
    )
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "audited" {
        return Err(format!(
            "relay admin mailbox audit did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!(
            "{}",
            render_admin_mailbox_audit_json(&result, &parsed.relay)
        );
    } else {
        println!(
            "{}",
            render_admin_mailbox_audit_text(&result, &parsed.relay)
        );
    }
    Ok(())
}

#[derive(Debug)]
struct AdminMailboxAuditArgs {
    node_id: Option<String>,
    ttl: Option<Duration>,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_mailbox_audit_args(args: Vec<String>) -> Result<AdminMailboxAuditArgs, String> {
    let mut node_id = None::<String>;
    let mut ttl = None::<Duration>;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_audit_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--ttl-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_audit_usage());
                };
                ttl = Some(parse_positive_cli_duration(value, "--ttl-seconds")?);
            }
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_audit_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_mailbox_audit_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(admin_mailbox_audit_usage()),
        }
        index += 1;
    }

    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_mailbox_audit_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminMailboxAuditArgs {
        node_id,
        ttl,
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_mailbox_audit_usage() -> String {
    "usage: conu-relay --admin-mailbox-audit --relay <ws://host:port/path> --admin-token-stdin [--node <node-id>] [--ttl-seconds <seconds>] [--json]".to_string()
}

fn admin_mailbox_purge_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_mailbox_purge_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::mailbox_purge(
        admin_token,
        parsed.node_id.clone(),
        parsed.ttl.as_secs(),
        parsed.dry_run,
    )
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if !matches!(result.status.as_str(), "dry_run" | "purged") {
        return Err(format!(
            "relay admin mailbox purge did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!(
            "{}",
            render_admin_mailbox_purge_json(&result, &parsed.relay)
        );
    } else {
        println!(
            "{}",
            render_admin_mailbox_purge_text(&result, &parsed.relay)
        );
    }
    Ok(())
}

#[derive(Debug)]
struct AdminMailboxPurgeArgs {
    node_id: Option<String>,
    ttl: Duration,
    dry_run: bool,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_mailbox_purge_args(args: Vec<String>) -> Result<AdminMailboxPurgeArgs, String> {
    let mut node_id = None::<String>;
    let mut ttl = None::<Duration>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_purge_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--ttl-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_purge_usage());
                };
                ttl = Some(parse_positive_cli_duration(value, "--ttl-seconds")?);
            }
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_purge_usage());
                };
                relay = Some(value.to_string());
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_mailbox_purge_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(admin_mailbox_purge_usage()),
        }
        index += 1;
    }

    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_mailbox_purge_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }
    let Some(ttl) = ttl else {
        return Err(admin_mailbox_purge_usage());
    };
    match (dry_run, confirm) {
        (true, false) | (false, true) => {}
        _ => {
            return Err(
                "--admin-mailbox-purge requires exactly one of --dry-run or --confirm".to_string(),
            );
        }
    }

    Ok(AdminMailboxPurgeArgs {
        node_id,
        ttl,
        dry_run,
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_mailbox_purge_usage() -> String {
    "usage: conu-relay --admin-mailbox-purge --relay <ws://host:port/path> --admin-token-stdin --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]".to_string()
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
        Some(RelayServerFrame::AdminResult(result)) => Ok(*result),
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

fn render_admin_dashboard_text(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r"conU hosted relay admin dashboard snapshot

account: {}
node: {}
relay: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
credential accounts: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
hosted policies: {}
accounting records: {}
accounting window started unix: {}
sessions authenticated: {}
sessions resumed: {}
envelopes sent: {}
bytes sent: {}
envelopes received: {}
bytes received: {}
envelopes mailboxed: {}
bytes mailboxed: {}
abuse records: {}
abuse window started unix: {}
admin unauthorized: {}
admin failed: {}
unauthorized sessions: {}
credential denied sessions: {}
tenant denied sessions: {}
rate limited sessions: {}
session expired: {}
quota denied forwards: {}
undelivered forwards: {}
mailbox rejected forwards: {}
malformed client frames: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        result.account_id.as_deref().unwrap_or("all"),
        result.node_id.as_deref().unwrap_or("all"),
        relay,
        result.credentials,
        result.active,
        result.revoked,
        result.expired,
        result.accounts,
        result.tenants,
        result.active_tenants,
        result.revoked_tenants,
        result.nodes,
        result.active_nodes,
        result.revoked_nodes,
        result.tenant_policies,
        result.accounting_records,
        optional_u64_text(result.accounting_window_started_unix),
        result.sessions_authenticated,
        result.sessions_resumed,
        result.envelopes_sent,
        result.bytes_sent,
        result.envelopes_received,
        result.bytes_received,
        result.envelopes_mailboxed,
        result.bytes_mailboxed,
        result.abuse_records,
        optional_u64_text(result.abuse_window_started_unix),
        result.admin_unauthorized,
        result.admin_failed,
        result.unauthorized_sessions,
        result.credential_denied_sessions,
        result.tenant_denied_sessions,
        result.rate_limited_sessions,
        result.session_expired,
        result.quota_denied_forwards,
        result.undelivered_forwards,
        result.mailbox_rejected_forwards,
        result.malformed_client_frames,
        yes_no(result.payload_displayed),
        yes_no(result.token_displayed),
        yes_no(result.token_hash_displayed),
        yes_no(result.key_material_displayed),
        yes_no(result.session_id_displayed),
        yes_no(result.ciphertext_displayed),
        yes_no(result.contents_displayed)
    )
}

fn render_admin_dashboard_json(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "accountId": {},
  "nodeId": {},
  "relay": "{}",
  "credentials": {{
    "credentials": {},
    "active": {},
    "revoked": {},
    "expired": {},
    "accounts": {}
  }},
  "tenants": {{
    "tenants": {},
    "activeTenants": {},
    "revokedTenants": {},
    "nodes": {},
    "activeNodes": {},
    "revokedNodes": {},
    "policies": {}
  }},
  "accounting": {{
    "records": {},
    "windowStartedUnix": {},
    "sessionsAuthenticated": {},
    "sessionsResumed": {},
    "envelopesSent": {},
    "bytesSent": {},
    "envelopesReceived": {},
    "bytesReceived": {},
    "envelopesMailboxed": {},
    "bytesMailboxed": {}
  }},
  "abuse": {{
    "records": {},
    "windowStartedUnix": {},
    "adminUnauthorized": {},
    "adminFailed": {},
    "unauthorizedSessions": {},
    "credentialDeniedSessions": {},
    "tenantDeniedSessions": {},
    "rateLimitedSessions": {},
    "sessionExpired": {},
    "quotaDeniedForwards": {},
    "undeliveredForwards": {},
    "mailboxRejectedForwards": {},
    "malformedClientFrames": {}
  }},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
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
        result.accounts,
        result.tenants,
        result.active_tenants,
        result.revoked_tenants,
        result.nodes,
        result.active_nodes,
        result.revoked_nodes,
        result.tenant_policies,
        result.accounting_records,
        optional_u64_json(result.accounting_window_started_unix),
        result.sessions_authenticated,
        result.sessions_resumed,
        result.envelopes_sent,
        result.bytes_sent,
        result.envelopes_received,
        result.bytes_received,
        result.envelopes_mailboxed,
        result.bytes_mailboxed,
        result.abuse_records,
        optional_u64_json(result.abuse_window_started_unix),
        result.admin_unauthorized,
        result.admin_failed,
        result.unauthorized_sessions,
        result.credential_denied_sessions,
        result.tenant_denied_sessions,
        result.rate_limited_sessions,
        result.session_expired,
        result.quota_denied_forwards,
        result.undelivered_forwards,
        result.mailbox_rejected_forwards,
        result.malformed_client_frames,
        bool_json(result.payload_displayed),
        bool_json(result.token_displayed),
        bool_json(result.token_hash_displayed),
        bool_json(result.key_material_displayed),
        bool_json(result.session_id_displayed),
        bool_json(result.ciphertext_displayed),
        bool_json(result.contents_displayed)
    )
}

fn render_admin_mailbox_audit_text(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r"conU hosted relay admin mailbox audit

node: {}
relay: {}
retention ttl seconds: {}
nodes: {}
records: {}
invalid records: {}
bytes: {}
oldest queued unix millis: {}
newest queued unix millis: {}
expired records: {}
expired bytes: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        result.node_id.as_deref().unwrap_or("all"),
        relay,
        optional_u64_text(result.retention_ttl_seconds),
        result.mailbox_nodes,
        result.mailbox_records,
        result.mailbox_invalid_records,
        result.mailbox_bytes,
        optional_u64_text(result.mailbox_oldest_queued_unix_millis),
        optional_u64_text(result.mailbox_newest_queued_unix_millis),
        optional_u64_text(result.mailbox_expired_records),
        optional_u64_text(result.mailbox_expired_bytes),
        yes_no(result.payload_displayed),
        yes_no(result.token_displayed),
        yes_no(result.token_hash_displayed),
        yes_no(result.key_material_displayed),
        yes_no(result.session_id_displayed),
        yes_no(result.ciphertext_displayed),
        yes_no(result.contents_displayed)
    )
}

fn render_admin_mailbox_audit_json(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "nodeId": {},
  "relay": "{}",
  "retentionTtlSeconds": {},
  "nodes": {},
  "records": {},
  "invalidRecords": {},
  "bytes": {},
  "oldestQueuedUnixMillis": {},
  "newestQueuedUnixMillis": {},
  "expiredRecords": {},
  "expiredBytes": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        json_escape(&result.status),
        result.action.as_str(),
        optional_string_json(result.node_id.as_deref()),
        json_escape(relay),
        optional_u64_json(result.retention_ttl_seconds),
        result.mailbox_nodes,
        result.mailbox_records,
        result.mailbox_invalid_records,
        result.mailbox_bytes,
        optional_u64_json(result.mailbox_oldest_queued_unix_millis),
        optional_u64_json(result.mailbox_newest_queued_unix_millis),
        optional_u64_json(result.mailbox_expired_records),
        optional_u64_json(result.mailbox_expired_bytes),
        bool_json(result.payload_displayed),
        bool_json(result.token_displayed),
        bool_json(result.token_hash_displayed),
        bool_json(result.key_material_displayed),
        bool_json(result.session_id_displayed),
        bool_json(result.ciphertext_displayed),
        bool_json(result.contents_displayed)
    )
}

fn render_admin_mailbox_purge_text(result: &RelayAdminResult, relay: &str) -> String {
    let dry_run = result.mailbox_dry_run.unwrap_or(false);
    let confirmed = result.mailbox_confirmed.unwrap_or(!dry_run);
    format!(
        r"conU hosted relay admin mailbox purge

mode: {}
node: {}
relay: {}
retention ttl seconds: {}
dry run: {}
confirmed: {}
nodes: {}
records: {}
invalid records: {}
bytes: {}
expired records: {}
expired bytes: {}
purged records: {}
purged bytes: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        if dry_run { "dry-run" } else { "confirmed" },
        result.node_id.as_deref().unwrap_or("all"),
        relay,
        optional_u64_text(result.retention_ttl_seconds),
        yes_no(dry_run),
        yes_no(confirmed),
        result.mailbox_nodes,
        result.mailbox_records,
        result.mailbox_invalid_records,
        result.mailbox_bytes,
        optional_u64_text(result.mailbox_expired_records),
        optional_u64_text(result.mailbox_expired_bytes),
        optional_u64_text(result.mailbox_purged_records),
        optional_u64_text(result.mailbox_purged_bytes),
        yes_no(result.payload_displayed),
        yes_no(result.token_displayed),
        yes_no(result.token_hash_displayed),
        yes_no(result.key_material_displayed),
        yes_no(result.session_id_displayed),
        yes_no(result.ciphertext_displayed),
        yes_no(result.contents_displayed)
    )
}

fn render_admin_mailbox_purge_json(result: &RelayAdminResult, relay: &str) -> String {
    let dry_run = result.mailbox_dry_run.unwrap_or(false);
    let confirmed = result.mailbox_confirmed.unwrap_or(!dry_run);
    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "mode": "{}",
  "nodeId": {},
  "relay": "{}",
  "retentionTtlSeconds": {},
  "dryRun": {},
  "confirmed": {},
  "nodes": {},
  "records": {},
  "invalidRecords": {},
  "bytes": {},
  "expiredRecords": {},
  "expiredBytes": {},
  "purgedRecords": {},
  "purgedBytes": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        json_escape(&result.status),
        result.action.as_str(),
        if dry_run { "dry-run" } else { "confirmed" },
        optional_string_json(result.node_id.as_deref()),
        json_escape(relay),
        optional_u64_json(result.retention_ttl_seconds),
        bool_json(dry_run),
        bool_json(confirmed),
        result.mailbox_nodes,
        result.mailbox_records,
        result.mailbox_invalid_records,
        result.mailbox_bytes,
        optional_u64_json(result.mailbox_expired_records),
        optional_u64_json(result.mailbox_expired_bytes),
        optional_u64_json(result.mailbox_purged_records),
        optional_u64_json(result.mailbox_purged_bytes),
        bool_json(result.payload_displayed),
        bool_json(result.token_displayed),
        bool_json(result.token_hash_displayed),
        bool_json(result.key_material_displayed),
        bool_json(result.session_id_displayed),
        bool_json(result.ciphertext_displayed),
        bool_json(result.contents_displayed)
    )
}

fn tenant_upsert_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_tenant_account_args(args, "--tenant-upsert")?;
    let update = upsert_hosted_tenant_in_file(&parsed.tenants_file, parsed.account_id)
        .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_tenant_update_json(&update));
    } else {
        println!("{}", render_tenant_update_text(&update));
    }
    Ok(())
}

fn tenant_revoke_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_tenant_account_args(args, "--tenant-revoke")?;
    let update = revoke_hosted_tenant_in_file(&parsed.tenants_file, parsed.account_id)
        .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_tenant_update_json(&update));
    } else {
        println!("{}", render_tenant_update_text(&update));
    }
    Ok(())
}

struct TenantAccountArgs {
    account_id: String,
    tenants_file: PathBuf,
    json: bool,
}

fn parse_tenant_account_args(
    args: Vec<String>,
    command: &'static str,
) -> Result<TenantAccountArgs, String> {
    let mut positional = Vec::new();
    let mut tenants_file = None::<PathBuf>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tenants-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_account_usage(command));
                };
                tenants_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(tenant_account_usage(command)),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(tenant_account_usage(command));
    }
    let Some(tenants_file) = tenants_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(tenant_account_usage(command));
    };

    Ok(TenantAccountArgs {
        account_id: positional.remove(0),
        tenants_file,
        json,
    })
}

fn tenant_account_usage(command: &str) -> String {
    format!("usage: conu-relay {command} <account-id> --tenants-file <path> [--json]")
}

fn tenant_node_upsert_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_tenant_node_upsert_args(args)?;
    let update = upsert_hosted_tenant_node_in_file(
        &parsed.tenants_file,
        parsed.account_id,
        parsed.node_id,
        parsed.permissions,
        parsed.signing_key_id,
        parsed.exchange_key_id,
    )
    .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_tenant_update_json(&update));
    } else {
        println!("{}", render_tenant_update_text(&update));
    }
    Ok(())
}

#[derive(Debug)]
struct TenantNodeUpsertArgs {
    account_id: String,
    node_id: String,
    tenants_file: PathBuf,
    permissions: HostedTenantPermissions,
    signing_key_id: Option<String>,
    exchange_key_id: Option<String>,
    json: bool,
}

fn parse_tenant_node_upsert_args(args: Vec<String>) -> Result<TenantNodeUpsertArgs, String> {
    let mut positional = Vec::new();
    let mut tenants_file = None::<PathBuf>;
    let mut permissions = HostedTenantPermissions::default();
    let mut signing_key_id = None::<String>;
    let mut exchange_key_id = None::<String>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tenants-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                tenants_file = Some(PathBuf::from(value));
            }
            "--messages" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                permissions.messages = parse_cli_bool(value, "--messages")?;
            }
            "--streams" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                permissions.streams = parse_cli_bool(value, "--streams")?;
            }
            "--rooms" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                permissions.rooms = parse_cli_bool(value, "--rooms")?;
            }
            "--files" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                permissions.files = parse_cli_bool(value, "--files")?;
            }
            "--mailbox" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                permissions.mailbox = parse_cli_bool(value, "--mailbox")?;
            }
            "--signing-key-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                signing_key_id = Some(value.to_string());
            }
            "--exchange-key-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_upsert_usage());
                };
                exchange_key_id = Some(value.to_string());
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(tenant_node_upsert_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(tenant_node_upsert_usage());
    }
    let Some(tenants_file) = tenants_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(tenant_node_upsert_usage());
    };

    Ok(TenantNodeUpsertArgs {
        account_id: positional.remove(0),
        node_id: positional.remove(0),
        tenants_file,
        permissions,
        signing_key_id,
        exchange_key_id,
        json,
    })
}

fn tenant_node_upsert_usage() -> String {
    "usage: conu-relay --tenant-node-upsert <account-id> <node-id> --tenants-file <path> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] [--signing-key-id <id>] [--exchange-key-id <id>] [--json]".to_string()
}

fn tenant_node_revoke_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_tenant_node_revoke_args(args)?;
    let update =
        revoke_hosted_tenant_node_in_file(&parsed.tenants_file, parsed.account_id, parsed.node_id)
            .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_tenant_update_json(&update));
    } else {
        println!("{}", render_tenant_update_text(&update));
    }
    Ok(())
}

struct TenantNodeRevokeArgs {
    account_id: String,
    node_id: String,
    tenants_file: PathBuf,
    json: bool,
}

fn parse_tenant_node_revoke_args(args: Vec<String>) -> Result<TenantNodeRevokeArgs, String> {
    let mut positional = Vec::new();
    let mut tenants_file = None::<PathBuf>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tenants-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_node_revoke_usage());
                };
                tenants_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(tenant_node_revoke_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(tenant_node_revoke_usage());
    }
    let Some(tenants_file) = tenants_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(tenant_node_revoke_usage());
    };

    Ok(TenantNodeRevokeArgs {
        account_id: positional.remove(0),
        node_id: positional.remove(0),
        tenants_file,
        json,
    })
}

fn tenant_node_revoke_usage() -> String {
    "usage: conu-relay --tenant-node-revoke <account-id> <node-id> --tenants-file <path> [--json]"
        .to_string()
}

fn tenant_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_tenant_audit_args(args)?;
    let audit = audit_hosted_tenants_file(&parsed.tenants_file, parsed.account_id.as_deref())
        .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_tenant_audit_json(&audit, &parsed.tenants_file));
    } else {
        println!("{}", render_tenant_audit_text(&audit, &parsed.tenants_file));
    }
    Ok(())
}

struct TenantAuditArgs {
    account_id: Option<String>,
    tenants_file: PathBuf,
    json: bool,
}

fn parse_tenant_audit_args(args: Vec<String>) -> Result<TenantAuditArgs, String> {
    let mut account_id = None::<String>;
    let mut tenants_file = None::<PathBuf>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_audit_usage());
                };
                account_id = Some(value.to_string());
            }
            "--tenants-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(tenant_audit_usage());
                };
                tenants_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(tenant_audit_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(tenant_audit_usage()),
        }
        index += 1;
    }

    let Some(tenants_file) = tenants_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(tenant_audit_usage());
    };

    Ok(TenantAuditArgs {
        account_id,
        tenants_file,
        json,
    })
}

fn tenant_audit_usage() -> String {
    "usage: conu-relay --tenant-audit --tenants-file <path> [--account <account-id>] [--json]"
        .to_string()
}

#[derive(Debug, Clone)]
struct AbuseAuditArgs {
    abuse_dir: PathBuf,
    node_id: Option<String>,
    json: bool,
}

fn abuse_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_abuse_audit_args(args)?;
    let audit = audit_relay_abuse_dir(&parsed.abuse_dir, parsed.node_id.as_deref())
        .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_abuse_audit_json(&audit, &parsed.abuse_dir));
    } else {
        println!("{}", render_abuse_audit_text(&audit, &parsed.abuse_dir));
    }
    Ok(())
}

fn parse_abuse_audit_args(args: Vec<String>) -> Result<AbuseAuditArgs, String> {
    let mut abuse_dir = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--abuse-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(abuse_audit_usage());
                };
                abuse_dir = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(abuse_audit_usage());
                };
                node_id = Some(value.to_string());
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(abuse_audit_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(abuse_audit_usage()),
        }
        index += 1;
    }

    let Some(abuse_dir) = abuse_dir.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(abuse_audit_usage());
    };

    Ok(AbuseAuditArgs {
        abuse_dir,
        node_id,
        json,
    })
}

fn abuse_audit_usage() -> String {
    "usage: conu-relay --abuse-audit --abuse-dir <path> [--node <node-id>] [--json]".to_string()
}

#[derive(Debug, Clone)]
struct MailboxAuditArgs {
    mailbox_dir: PathBuf,
    node_id: Option<String>,
    ttl: Option<Duration>,
    json: bool,
}

fn mailbox_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_mailbox_audit_args(args)?;
    let audit = audit_relay_mailbox_dir(&parsed.mailbox_dir, parsed.node_id.as_deref(), parsed.ttl)
        .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_mailbox_audit_json(&audit, &parsed.mailbox_dir));
    } else {
        println!("{}", render_mailbox_audit_text(&audit, &parsed.mailbox_dir));
    }
    Ok(())
}

fn parse_mailbox_audit_args(args: Vec<String>) -> Result<MailboxAuditArgs, String> {
    let mut mailbox_dir = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut ttl = None::<Duration>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--mailbox-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_audit_usage());
                };
                mailbox_dir = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_audit_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--ttl-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_audit_usage());
                };
                ttl = Some(parse_positive_cli_duration(value, "--ttl-seconds")?);
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(mailbox_audit_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(mailbox_audit_usage()),
        }
        index += 1;
    }

    let Some(mailbox_dir) = mailbox_dir.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(mailbox_audit_usage());
    };

    Ok(MailboxAuditArgs {
        mailbox_dir,
        node_id,
        ttl,
        json,
    })
}

fn parse_positive_cli_duration(value: &str, flag: &str) -> Result<Duration, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be an unsigned integer"))?;
    if seconds == 0 {
        return Err(format!("{flag} must be greater than zero"));
    }
    Ok(Duration::from_secs(seconds))
}

fn mailbox_audit_usage() -> String {
    "usage: conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--json]".to_string()
}

#[derive(Debug, Clone)]
struct MailboxPurgeArgs {
    mailbox_dir: PathBuf,
    node_id: Option<String>,
    ttl: Duration,
    dry_run: bool,
    json: bool,
}

fn mailbox_purge_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_mailbox_purge_args(args)?;
    let report = purge_relay_mailbox_dir(
        &parsed.mailbox_dir,
        parsed.node_id.as_deref(),
        parsed.ttl,
        parsed.dry_run,
    )
    .map_err(|error| error.to_string())?;
    if parsed.json {
        println!(
            "{}",
            render_mailbox_purge_json(&report, &parsed.mailbox_dir)
        );
    } else {
        println!(
            "{}",
            render_mailbox_purge_text(&report, &parsed.mailbox_dir)
        );
    }
    Ok(())
}

fn parse_mailbox_purge_args(args: Vec<String>) -> Result<MailboxPurgeArgs, String> {
    let mut mailbox_dir = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut ttl = None::<Duration>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--mailbox-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_purge_usage());
                };
                mailbox_dir = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_purge_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--ttl-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_purge_usage());
                };
                ttl = Some(parse_positive_cli_duration(value, "--ttl-seconds")?);
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(mailbox_purge_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(mailbox_purge_usage()),
        }
        index += 1;
    }

    let Some(mailbox_dir) = mailbox_dir.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(mailbox_purge_usage());
    };
    let Some(ttl) = ttl else {
        return Err(mailbox_purge_usage());
    };
    match (dry_run, confirm) {
        (true, false) | (false, true) => {}
        _ => {
            return Err(
                "--mailbox-purge requires exactly one of --dry-run or --confirm".to_string(),
            );
        }
    }

    Ok(MailboxPurgeArgs {
        mailbox_dir,
        node_id,
        ttl,
        dry_run,
        json,
    })
}

fn mailbox_purge_usage() -> String {
    "usage: conu-relay --mailbox-purge --mailbox-dir <path> --ttl-seconds <seconds> [--node <node-id>] (--dry-run|--confirm) [--json]".to_string()
}

#[derive(Debug, Clone)]
struct HostedDashboardArgs {
    credentials_file: Option<PathBuf>,
    tenants_file: Option<PathBuf>,
    accounting_dir: Option<PathBuf>,
    abuse_dir: Option<PathBuf>,
    account_id: Option<String>,
    node_id: Option<String>,
    json: bool,
}

#[derive(Debug, Clone)]
struct HostedDashboardSnapshot {
    credentials_file: Option<PathBuf>,
    tenants_file: Option<PathBuf>,
    accounting_dir: Option<PathBuf>,
    abuse_dir: Option<PathBuf>,
    account_id: Option<String>,
    node_id: Option<String>,
    credentials: Option<HostedCredentialAudit>,
    tenants: Option<HostedTenantAudit>,
    accounting: Option<RelayAccountingAudit>,
    abuse: Option<RelayAbuseAudit>,
}

fn hosted_dashboard_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_hosted_dashboard_args(args)?;
    let snapshot = hosted_dashboard_snapshot(&parsed)?;
    if parsed.json {
        println!("{}", render_hosted_dashboard_json(&snapshot));
    } else {
        println!("{}", render_hosted_dashboard_text(&snapshot));
    }
    Ok(())
}

fn parse_hosted_dashboard_args(args: Vec<String>) -> Result<HostedDashboardArgs, String> {
    let mut credentials_file = None::<PathBuf>;
    let mut tenants_file = None::<PathBuf>;
    let mut accounting_dir = None::<PathBuf>;
    let mut abuse_dir = None::<PathBuf>;
    let mut account_id = None::<String>;
    let mut node_id = None::<String>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--credentials-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_dashboard_usage());
                };
                credentials_file = Some(PathBuf::from(value));
            }
            "--tenants-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_dashboard_usage());
                };
                tenants_file = Some(PathBuf::from(value));
            }
            "--accounting-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_dashboard_usage());
                };
                accounting_dir = Some(PathBuf::from(value));
            }
            "--abuse-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_dashboard_usage());
                };
                abuse_dir = Some(PathBuf::from(value));
            }
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_dashboard_usage());
                };
                account_id = Some(value.to_string());
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_dashboard_usage());
                };
                node_id = Some(value.to_string());
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(hosted_dashboard_usage()),
            value if value.starts_with("--") => return Err(format!("unknown option: {value}")),
            _ => return Err(hosted_dashboard_usage()),
        }
        index += 1;
    }

    credentials_file = credentials_file.filter(|path| !path.as_os_str().is_empty());
    tenants_file = tenants_file.filter(|path| !path.as_os_str().is_empty());
    accounting_dir = accounting_dir.filter(|path| !path.as_os_str().is_empty());
    abuse_dir = abuse_dir.filter(|path| !path.as_os_str().is_empty());
    let account_id = account_id
        .map(|value| validate_dashboard_filter_id(value, "account id"))
        .transpose()?;
    let node_id = node_id
        .map(|value| validate_dashboard_filter_id(value, "node id"))
        .transpose()?;

    if credentials_file.is_none()
        && tenants_file.is_none()
        && accounting_dir.is_none()
        && abuse_dir.is_none()
    {
        return Err(hosted_dashboard_usage());
    }

    Ok(HostedDashboardArgs {
        credentials_file,
        tenants_file,
        accounting_dir,
        abuse_dir,
        account_id,
        node_id,
        json,
    })
}

fn hosted_dashboard_usage() -> String {
    "usage: conu-relay --hosted-dashboard [--credentials-file <path>] [--tenants-file <path>] [--accounting-dir <path>] [--abuse-dir <path>] [--account <account-id>] [--node <node-id>] [--json]".to_string()
}

fn validate_dashboard_filter_id(value: String, label: &'static str) -> Result<String, String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(format!("relay dashboard {label} cannot be empty"));
    }
    if value.len() > 120 {
        return Err(format!("relay dashboard {label} is too long"));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(format!(
            "relay dashboard {label} must use ASCII letters, numbers, dash, underscore, or dot"
        ));
    }
    Ok(value)
}

fn hosted_dashboard_snapshot(
    args: &HostedDashboardArgs,
) -> Result<HostedDashboardSnapshot, String> {
    let credentials = args
        .credentials_file
        .as_ref()
        .map(|path| audit_hosted_relay_credentials_file(path, args.account_id.as_deref()))
        .transpose()
        .map_err(|error| error.to_string())?;
    let tenants = args
        .tenants_file
        .as_ref()
        .map(|path| audit_hosted_tenants_file(path, args.account_id.as_deref()))
        .transpose()
        .map_err(|error| error.to_string())?;
    let accounting = args
        .accounting_dir
        .as_ref()
        .map(|path| audit_relay_accounting_dir(path, args.node_id.as_deref()))
        .transpose()
        .map_err(|error| error.to_string())?;
    let abuse = args
        .abuse_dir
        .as_ref()
        .map(|path| audit_relay_abuse_dir(path, args.node_id.as_deref()))
        .transpose()
        .map_err(|error| error.to_string())?;

    Ok(HostedDashboardSnapshot {
        credentials_file: args.credentials_file.clone(),
        tenants_file: args.tenants_file.clone(),
        accounting_dir: args.accounting_dir.clone(),
        abuse_dir: args.abuse_dir.clone(),
        account_id: args.account_id.clone(),
        node_id: args.node_id.clone(),
        credentials,
        tenants,
        accounting,
        abuse,
    })
}

fn parse_cli_bool(value: &str, flag: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{flag} must be true or false")),
    }
}

fn render_tenant_update_text(update: &HostedTenantManifestUpdate) -> String {
    format!(
        r"conU hosted tenant metadata {}

account: {}
node: {}
tenants file: {}
tenants: {}
nodes: {}
token displayed: {}
key material displayed: {}
payload displayed: no
contents displayed: {}",
        update.status.as_str(),
        update.account_id,
        update.node_id.as_deref().unwrap_or("none"),
        update.path.display(),
        update.tenants,
        update.nodes,
        yes_no(update.token_displayed),
        yes_no(update.key_material_displayed),
        yes_no(update.contents_displayed)
    )
}

fn render_tenant_update_json(update: &HostedTenantManifestUpdate) -> String {
    format!(
        r#"{{
  "status": "{}",
  "accountId": "{}",
  "nodeId": {},
  "tenantsFile": "{}",
  "tenants": {},
  "nodes": {},
  "tokenDisplayed": {},
  "keyMaterialDisplayed": {},
  "payloadDisplayed": false,
  "contentsDisplayed": {}
}}"#,
        update.status.as_str(),
        json_escape(&update.account_id),
        optional_string_json(update.node_id.as_deref()),
        json_escape(&update.path.display().to_string()),
        update.tenants,
        update.nodes,
        bool_json(update.token_displayed),
        bool_json(update.key_material_displayed),
        bool_json(update.contents_displayed)
    )
}

fn render_tenant_audit_text(audit: &HostedTenantAudit, tenants_file: &Path) -> String {
    format!(
        r"conU hosted tenant audit

account: {}
tenants file: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
policies: {}
token displayed: {}
key material displayed: {}
payload displayed: no
contents displayed: {}",
        audit.account_id.as_deref().unwrap_or("all"),
        tenants_file.display(),
        audit.tenants,
        audit.active_tenants,
        audit.revoked_tenants,
        audit.nodes,
        audit.active_nodes,
        audit.revoked_nodes,
        audit.policies,
        yes_no(audit.token_displayed),
        yes_no(audit.key_material_displayed),
        yes_no(audit.contents_displayed)
    )
}

fn render_tenant_audit_json(audit: &HostedTenantAudit, tenants_file: &Path) -> String {
    format!(
        r#"{{
  "status": "audited",
  "accountId": {},
  "tenantsFile": "{}",
  "tenants": {},
  "activeTenants": {},
  "revokedTenants": {},
  "nodes": {},
  "activeNodes": {},
  "revokedNodes": {},
  "policies": {},
  "tokenDisplayed": {},
  "keyMaterialDisplayed": {},
  "payloadDisplayed": false,
  "contentsDisplayed": {}
}}"#,
        optional_string_json(audit.account_id.as_deref()),
        json_escape(&tenants_file.display().to_string()),
        audit.tenants,
        audit.active_tenants,
        audit.revoked_tenants,
        audit.nodes,
        audit.active_nodes,
        audit.revoked_nodes,
        audit.policies,
        bool_json(audit.token_displayed),
        bool_json(audit.key_material_displayed),
        bool_json(audit.contents_displayed)
    )
}

fn render_abuse_audit_text(audit: &RelayAbuseAudit, abuse_dir: &Path) -> String {
    format!(
        r"conU relay abuse audit

scope: {}
abuse dir: {}
records: {}
window started unix: {}
admin unauthorized: {}
admin failed: {}
unauthorized sessions: {}
credential denied sessions: {}
tenant denied sessions: {}
rate limited sessions: {}
session expired: {}
quota denied forwards: {}
undelivered forwards: {}
mailbox rejected forwards: {}
malformed client frames: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        audit.node_id.as_deref().unwrap_or("all"),
        abuse_dir.display(),
        audit.records,
        optional_u64_text(audit.window_started_unix),
        audit.admin_unauthorized,
        audit.admin_failed,
        audit.unauthorized_sessions,
        audit.credential_denied_sessions,
        audit.tenant_denied_sessions,
        audit.rate_limited_sessions,
        audit.session_expired,
        audit.quota_denied_forwards,
        audit.undelivered_forwards,
        audit.mailbox_rejected_forwards,
        audit.malformed_client_frames,
        yes_no(audit.payload_displayed),
        yes_no(audit.token_displayed),
        yes_no(audit.token_hash_displayed),
        yes_no(audit.key_material_displayed),
        yes_no(audit.session_id_displayed),
        yes_no(audit.ciphertext_displayed),
        yes_no(audit.contents_displayed)
    )
}

fn render_abuse_audit_json(audit: &RelayAbuseAudit, abuse_dir: &Path) -> String {
    format!(
        r#"{{
  "status": "audited",
  "nodeId": {},
  "abuseDir": "{}",
  "records": {},
  "windowStartedUnix": {},
  "adminUnauthorized": {},
  "adminFailed": {},
  "unauthorizedSessions": {},
  "credentialDeniedSessions": {},
  "tenantDeniedSessions": {},
  "rateLimitedSessions": {},
  "sessionExpired": {},
  "quotaDeniedForwards": {},
  "undeliveredForwards": {},
  "mailboxRejectedForwards": {},
  "malformedClientFrames": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        optional_string_json(audit.node_id.as_deref()),
        json_escape(&abuse_dir.display().to_string()),
        audit.records,
        optional_u64_json(audit.window_started_unix),
        audit.admin_unauthorized,
        audit.admin_failed,
        audit.unauthorized_sessions,
        audit.credential_denied_sessions,
        audit.tenant_denied_sessions,
        audit.rate_limited_sessions,
        audit.session_expired,
        audit.quota_denied_forwards,
        audit.undelivered_forwards,
        audit.mailbox_rejected_forwards,
        audit.malformed_client_frames,
        bool_json(audit.payload_displayed),
        bool_json(audit.token_displayed),
        bool_json(audit.token_hash_displayed),
        bool_json(audit.key_material_displayed),
        bool_json(audit.session_id_displayed),
        bool_json(audit.ciphertext_displayed),
        bool_json(audit.contents_displayed)
    )
}

fn render_mailbox_audit_text(audit: &RelayMailboxAudit, mailbox_dir: &Path) -> String {
    format!(
        r"conU relay mailbox audit

scope: {}
mailbox dir: {}
retention ttl seconds: {}
nodes: {}
records: {}
invalid records: {}
bytes: {}
oldest queued unix millis: {}
newest queued unix millis: {}
expired records: {}
expired bytes: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        audit.node_id.as_deref().unwrap_or("all"),
        mailbox_dir.display(),
        optional_u64_text(audit.retention_ttl_seconds),
        audit.nodes,
        audit.records,
        audit.invalid_records,
        audit.bytes,
        optional_u64_text(audit.oldest_queued_unix_millis),
        optional_u64_text(audit.newest_queued_unix_millis),
        optional_u64_text(audit.expired_records),
        optional_u64_text(audit.expired_bytes),
        yes_no(audit.payload_displayed),
        yes_no(audit.token_displayed),
        yes_no(audit.token_hash_displayed),
        yes_no(audit.key_material_displayed),
        yes_no(audit.session_id_displayed),
        yes_no(audit.ciphertext_displayed),
        yes_no(audit.contents_displayed)
    )
}

fn render_mailbox_audit_json(audit: &RelayMailboxAudit, mailbox_dir: &Path) -> String {
    format!(
        r#"{{
  "status": "audited",
  "nodeId": {},
  "mailboxDir": "{}",
  "retentionTtlSeconds": {},
  "nodes": {},
  "records": {},
  "invalidRecords": {},
  "bytes": {},
  "oldestQueuedUnixMillis": {},
  "newestQueuedUnixMillis": {},
  "expiredRecords": {},
  "expiredBytes": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        optional_string_json(audit.node_id.as_deref()),
        json_escape(&mailbox_dir.display().to_string()),
        optional_u64_json(audit.retention_ttl_seconds),
        audit.nodes,
        audit.records,
        audit.invalid_records,
        audit.bytes,
        optional_u64_json(audit.oldest_queued_unix_millis),
        optional_u64_json(audit.newest_queued_unix_millis),
        optional_u64_json(audit.expired_records),
        optional_u64_json(audit.expired_bytes),
        bool_json(audit.payload_displayed),
        bool_json(audit.token_displayed),
        bool_json(audit.token_hash_displayed),
        bool_json(audit.key_material_displayed),
        bool_json(audit.session_id_displayed),
        bool_json(audit.ciphertext_displayed),
        bool_json(audit.contents_displayed)
    )
}

fn render_mailbox_purge_text(report: &RelayMailboxPurgeReport, mailbox_dir: &Path) -> String {
    format!(
        r"conU relay mailbox purge

mode: {}
scope: {}
mailbox dir: {}
retention ttl seconds: {}
nodes: {}
records: {}
invalid records: {}
bytes: {}
expired records: {}
expired bytes: {}
purged records: {}
purged bytes: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        if report.dry_run {
            "dry-run"
        } else {
            "confirmed"
        },
        report.node_id.as_deref().unwrap_or("all"),
        mailbox_dir.display(),
        report.retention_ttl_seconds,
        report.nodes,
        report.records,
        report.invalid_records,
        report.bytes,
        report.expired_records,
        report.expired_bytes,
        report.purged_records,
        report.purged_bytes,
        yes_no(report.payload_displayed),
        yes_no(report.token_displayed),
        yes_no(report.token_hash_displayed),
        yes_no(report.key_material_displayed),
        yes_no(report.session_id_displayed),
        yes_no(report.ciphertext_displayed),
        yes_no(report.contents_displayed)
    )
}

fn render_mailbox_purge_json(report: &RelayMailboxPurgeReport, mailbox_dir: &Path) -> String {
    let status = if report.dry_run { "dry_run" } else { "purged" };
    format!(
        r#"{{
  "status": "{}",
  "mode": "{}",
  "nodeId": {},
  "mailboxDir": "{}",
  "retentionTtlSeconds": {},
  "dryRun": {},
  "confirmed": {},
  "nodes": {},
  "records": {},
  "invalidRecords": {},
  "bytes": {},
  "expiredRecords": {},
  "expiredBytes": {},
  "purgedRecords": {},
  "purgedBytes": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        status,
        if report.dry_run {
            "dry-run"
        } else {
            "confirmed"
        },
        optional_string_json(report.node_id.as_deref()),
        json_escape(&mailbox_dir.display().to_string()),
        report.retention_ttl_seconds,
        bool_json(report.dry_run),
        bool_json(report.confirmed),
        report.nodes,
        report.records,
        report.invalid_records,
        report.bytes,
        report.expired_records,
        report.expired_bytes,
        report.purged_records,
        report.purged_bytes,
        bool_json(report.payload_displayed),
        bool_json(report.token_displayed),
        bool_json(report.token_hash_displayed),
        bool_json(report.key_material_displayed),
        bool_json(report.session_id_displayed),
        bool_json(report.ciphertext_displayed),
        bool_json(report.contents_displayed)
    )
}

fn render_hosted_dashboard_text(snapshot: &HostedDashboardSnapshot) -> String {
    let credentials = snapshot.credentials.as_ref();
    let tenants = snapshot.tenants.as_ref();
    let accounting = snapshot.accounting.as_ref();
    let abuse = snapshot.abuse.as_ref();

    format!(
        r"conU hosted relay dashboard snapshot

account: {}
node: {}
credentials file: {}
credentials configured: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
credential accounts: {}
tenants file: {}
tenants configured: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
hosted policies: {}
accounting dir: {}
accounting configured: {}
accounting records: {}
accounting window started unix: {}
sessions authenticated: {}
sessions resumed: {}
envelopes sent: {}
bytes sent: {}
envelopes received: {}
bytes received: {}
envelopes mailboxed: {}
bytes mailboxed: {}
abuse dir: {}
abuse configured: {}
abuse records: {}
abuse window started unix: {}
admin unauthorized: {}
admin failed: {}
unauthorized sessions: {}
credential denied sessions: {}
tenant denied sessions: {}
rate limited sessions: {}
session expired: {}
quota denied forwards: {}
undelivered forwards: {}
mailbox rejected forwards: {}
malformed client frames: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        snapshot.account_id.as_deref().unwrap_or("all"),
        snapshot.node_id.as_deref().unwrap_or("all"),
        optional_path_text(snapshot.credentials_file.as_deref()),
        yes_no(credentials.is_some()),
        credentials.map(|audit| audit.credentials).unwrap_or(0),
        credentials.map(|audit| audit.active).unwrap_or(0),
        credentials.map(|audit| audit.revoked).unwrap_or(0),
        credentials.map(|audit| audit.expired).unwrap_or(0),
        credentials.map(|audit| audit.accounts).unwrap_or(0),
        optional_path_text(snapshot.tenants_file.as_deref()),
        yes_no(tenants.is_some()),
        tenants.map(|audit| audit.tenants).unwrap_or(0),
        tenants.map(|audit| audit.active_tenants).unwrap_or(0),
        tenants.map(|audit| audit.revoked_tenants).unwrap_or(0),
        tenants.map(|audit| audit.nodes).unwrap_or(0),
        tenants.map(|audit| audit.active_nodes).unwrap_or(0),
        tenants.map(|audit| audit.revoked_nodes).unwrap_or(0),
        tenants.map(|audit| audit.policies).unwrap_or(0),
        optional_path_text(snapshot.accounting_dir.as_deref()),
        yes_no(accounting.is_some()),
        accounting.map(|audit| audit.records).unwrap_or(0),
        optional_u64_text(accounting.and_then(|audit| audit.window_started_unix)),
        accounting
            .map(|audit| audit.sessions_authenticated)
            .unwrap_or(0),
        accounting.map(|audit| audit.sessions_resumed).unwrap_or(0),
        accounting.map(|audit| audit.envelopes_sent).unwrap_or(0),
        accounting.map(|audit| audit.bytes_sent).unwrap_or(0),
        accounting
            .map(|audit| audit.envelopes_received)
            .unwrap_or(0),
        accounting.map(|audit| audit.bytes_received).unwrap_or(0),
        accounting
            .map(|audit| audit.envelopes_mailboxed)
            .unwrap_or(0),
        accounting.map(|audit| audit.bytes_mailboxed).unwrap_or(0),
        optional_path_text(snapshot.abuse_dir.as_deref()),
        yes_no(abuse.is_some()),
        abuse.map(|audit| audit.records).unwrap_or(0),
        optional_u64_text(abuse.and_then(|audit| audit.window_started_unix)),
        abuse.map(|audit| audit.admin_unauthorized).unwrap_or(0),
        abuse.map(|audit| audit.admin_failed).unwrap_or(0),
        abuse.map(|audit| audit.unauthorized_sessions).unwrap_or(0),
        abuse
            .map(|audit| audit.credential_denied_sessions)
            .unwrap_or(0),
        abuse.map(|audit| audit.tenant_denied_sessions).unwrap_or(0),
        abuse.map(|audit| audit.rate_limited_sessions).unwrap_or(0),
        abuse.map(|audit| audit.session_expired).unwrap_or(0),
        abuse.map(|audit| audit.quota_denied_forwards).unwrap_or(0),
        abuse.map(|audit| audit.undelivered_forwards).unwrap_or(0),
        abuse
            .map(|audit| audit.mailbox_rejected_forwards)
            .unwrap_or(0),
        abuse
            .map(|audit| audit.malformed_client_frames)
            .unwrap_or(0),
        yes_no(snapshot_payload_displayed(snapshot)),
        yes_no(snapshot_token_displayed(snapshot)),
        yes_no(snapshot_token_hash_displayed(snapshot)),
        yes_no(snapshot_key_material_displayed(snapshot)),
        yes_no(snapshot_session_id_displayed(snapshot)),
        yes_no(snapshot_ciphertext_displayed(snapshot)),
        yes_no(snapshot_contents_displayed(snapshot))
    )
}

fn render_hosted_dashboard_json(snapshot: &HostedDashboardSnapshot) -> String {
    format!(
        r#"{{
  "status": "snapshotted",
  "accountId": {},
  "nodeId": {},
  "sources": {{
    "credentialsFile": {},
    "tenantsFile": {},
    "accountingDir": {},
    "abuseDir": {}
  }},
  "credentials": {},
  "tenants": {},
  "accounting": {},
  "abuse": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        optional_string_json(snapshot.account_id.as_deref()),
        optional_string_json(snapshot.node_id.as_deref()),
        optional_path_json(snapshot.credentials_file.as_deref()),
        optional_path_json(snapshot.tenants_file.as_deref()),
        optional_path_json(snapshot.accounting_dir.as_deref()),
        optional_path_json(snapshot.abuse_dir.as_deref()),
        render_dashboard_credentials_json(snapshot.credentials.as_ref()),
        render_dashboard_tenants_json(snapshot.tenants.as_ref()),
        render_dashboard_accounting_json(snapshot.accounting.as_ref()),
        render_dashboard_abuse_json(snapshot.abuse.as_ref()),
        bool_json(snapshot_payload_displayed(snapshot)),
        bool_json(snapshot_token_displayed(snapshot)),
        bool_json(snapshot_token_hash_displayed(snapshot)),
        bool_json(snapshot_key_material_displayed(snapshot)),
        bool_json(snapshot_session_id_displayed(snapshot)),
        bool_json(snapshot_ciphertext_displayed(snapshot)),
        bool_json(snapshot_contents_displayed(snapshot))
    )
}

fn render_dashboard_credentials_json(audit: Option<&HostedCredentialAudit>) -> String {
    match audit {
        Some(audit) => format!(
            r#"{{
    "configured": true,
    "credentials": {},
    "active": {},
    "revoked": {},
    "expired": {},
    "accounts": {},
    "tokenDisplayed": {},
    "contentsDisplayed": {}
  }}"#,
            audit.credentials,
            audit.active,
            audit.revoked,
            audit.expired,
            audit.accounts,
            bool_json(audit.token_displayed),
            bool_json(audit.contents_displayed)
        ),
        None => "null".to_string(),
    }
}

fn render_dashboard_tenants_json(audit: Option<&HostedTenantAudit>) -> String {
    match audit {
        Some(audit) => format!(
            r#"{{
    "configured": true,
    "tenants": {},
    "activeTenants": {},
    "revokedTenants": {},
    "nodes": {},
    "activeNodes": {},
    "revokedNodes": {},
    "policies": {},
    "tokenDisplayed": {},
    "keyMaterialDisplayed": {},
    "contentsDisplayed": {}
  }}"#,
            audit.tenants,
            audit.active_tenants,
            audit.revoked_tenants,
            audit.nodes,
            audit.active_nodes,
            audit.revoked_nodes,
            audit.policies,
            bool_json(audit.token_displayed),
            bool_json(audit.key_material_displayed),
            bool_json(audit.contents_displayed)
        ),
        None => "null".to_string(),
    }
}

fn render_dashboard_accounting_json(audit: Option<&RelayAccountingAudit>) -> String {
    match audit {
        Some(audit) => format!(
            r#"{{
    "configured": true,
    "records": {},
    "windowStartedUnix": {},
    "sessionsAuthenticated": {},
    "sessionsResumed": {},
    "envelopesSent": {},
    "bytesSent": {},
    "envelopesReceived": {},
    "bytesReceived": {},
    "envelopesMailboxed": {},
    "bytesMailboxed": {},
    "payloadDisplayed": {},
    "tokenDisplayed": {},
    "tokenHashDisplayed": {},
    "keyMaterialDisplayed": {},
    "sessionIdDisplayed": {},
    "ciphertextDisplayed": {},
    "contentsDisplayed": {}
  }}"#,
            audit.records,
            optional_u64_json(audit.window_started_unix),
            audit.sessions_authenticated,
            audit.sessions_resumed,
            audit.envelopes_sent,
            audit.bytes_sent,
            audit.envelopes_received,
            audit.bytes_received,
            audit.envelopes_mailboxed,
            audit.bytes_mailboxed,
            bool_json(audit.payload_displayed),
            bool_json(audit.token_displayed),
            bool_json(audit.token_hash_displayed),
            bool_json(audit.key_material_displayed),
            bool_json(audit.session_id_displayed),
            bool_json(audit.ciphertext_displayed),
            bool_json(audit.contents_displayed)
        ),
        None => "null".to_string(),
    }
}

fn render_dashboard_abuse_json(audit: Option<&RelayAbuseAudit>) -> String {
    match audit {
        Some(audit) => format!(
            r#"{{
    "configured": true,
    "records": {},
    "windowStartedUnix": {},
    "adminUnauthorized": {},
    "adminFailed": {},
    "unauthorizedSessions": {},
    "credentialDeniedSessions": {},
    "tenantDeniedSessions": {},
    "rateLimitedSessions": {},
    "sessionExpired": {},
    "quotaDeniedForwards": {},
    "undeliveredForwards": {},
    "mailboxRejectedForwards": {},
    "malformedClientFrames": {},
    "payloadDisplayed": {},
    "tokenDisplayed": {},
    "tokenHashDisplayed": {},
    "keyMaterialDisplayed": {},
    "sessionIdDisplayed": {},
    "ciphertextDisplayed": {},
    "contentsDisplayed": {}
  }}"#,
            audit.records,
            optional_u64_json(audit.window_started_unix),
            audit.admin_unauthorized,
            audit.admin_failed,
            audit.unauthorized_sessions,
            audit.credential_denied_sessions,
            audit.tenant_denied_sessions,
            audit.rate_limited_sessions,
            audit.session_expired,
            audit.quota_denied_forwards,
            audit.undelivered_forwards,
            audit.mailbox_rejected_forwards,
            audit.malformed_client_frames,
            bool_json(audit.payload_displayed),
            bool_json(audit.token_displayed),
            bool_json(audit.token_hash_displayed),
            bool_json(audit.key_material_displayed),
            bool_json(audit.session_id_displayed),
            bool_json(audit.ciphertext_displayed),
            bool_json(audit.contents_displayed)
        ),
        None => "null".to_string(),
    }
}

fn snapshot_payload_displayed(snapshot: &HostedDashboardSnapshot) -> bool {
    snapshot
        .accounting
        .as_ref()
        .is_some_and(|audit| audit.payload_displayed)
        || snapshot
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
}

fn snapshot_token_displayed(snapshot: &HostedDashboardSnapshot) -> bool {
    snapshot
        .credentials
        .as_ref()
        .is_some_and(|audit| audit.token_displayed)
        || snapshot
            .tenants
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || snapshot
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || snapshot
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
}

fn snapshot_token_hash_displayed(snapshot: &HostedDashboardSnapshot) -> bool {
    snapshot
        .accounting
        .as_ref()
        .is_some_and(|audit| audit.token_hash_displayed)
        || snapshot
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
}

fn snapshot_key_material_displayed(snapshot: &HostedDashboardSnapshot) -> bool {
    snapshot
        .tenants
        .as_ref()
        .is_some_and(|audit| audit.key_material_displayed)
        || snapshot
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || snapshot
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
}

fn snapshot_session_id_displayed(snapshot: &HostedDashboardSnapshot) -> bool {
    snapshot
        .accounting
        .as_ref()
        .is_some_and(|audit| audit.session_id_displayed)
        || snapshot
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
}

fn snapshot_ciphertext_displayed(snapshot: &HostedDashboardSnapshot) -> bool {
    snapshot
        .accounting
        .as_ref()
        .is_some_and(|audit| audit.ciphertext_displayed)
        || snapshot
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
}

fn snapshot_contents_displayed(snapshot: &HostedDashboardSnapshot) -> bool {
    snapshot
        .credentials
        .as_ref()
        .is_some_and(|audit| audit.contents_displayed)
        || snapshot
            .tenants
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || snapshot
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || snapshot
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
}

fn optional_path_text(value: Option<&Path>) -> String {
    value
        .map(|value| value.display().to_string())
        .unwrap_or_else(|| "not configured".to_string())
}

fn optional_path_json(value: Option<&Path>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(&value.display().to_string())))
        .unwrap_or_else(|| "null".to_string())
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
    let session_storage = relay_session_storage_from_env()?;
    let mailbox_policy = relay_mailbox_policy_from_env()?;
    let mailbox_storage = relay_mailbox_storage_from_env()?;
    let mailbox_maintenance = relay_mailbox_maintenance_from_env(&mailbox_storage)?;
    let accounting_policy = relay_accounting_policy_from_env()?;
    let accounting_storage = relay_accounting_storage_from_env()?;
    let abuse_policy = relay_abuse_policy_from_env()?;
    let abuse_storage = relay_abuse_storage_from_env()?;
    let credentials_file = env::var("CONU_RELAY_CREDENTIALS_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let tenants_file = env::var("CONU_RELAY_TENANTS_FILE")
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
        .with_session_storage(session_storage)
        .with_mailbox_policy(mailbox_policy)
        .with_mailbox_storage(mailbox_storage)
        .with_mailbox_maintenance(mailbox_maintenance)
        .with_accounting_policy(accounting_policy)
        .with_accounting_storage(accounting_storage)
        .with_abuse_policy(abuse_policy)
        .with_abuse_storage(abuse_storage);

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
        if let Some(tenants_file) = tenants_file {
            config = config
                .with_admin_tenants_file(tenants_file)
                .map_err(|error| error.to_string())?;
        }
    } else if tenants_file.is_some() {
        return Err(
            "CONU_RELAY_TENANTS_FILE requires CONU_RELAY_ADMIN_TOKEN and CONU_RELAY_CREDENTIALS_FILE"
                .to_string(),
        );
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

fn relay_session_storage_from_env() -> Result<RelaySessionStorage, String> {
    match env::var("CONU_RELAY_SESSION_STATE_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(path) => RelaySessionStorage::file_backed(path).map_err(|error| error.to_string()),
        None => Ok(RelaySessionStorage::memory_only()),
    }
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

fn relay_mailbox_maintenance_from_env(
    mailbox_storage: &RelayMailboxStorage,
) -> Result<RelayMailboxMaintenancePolicy, String> {
    let Some(seconds) =
        parse_optional_duration_seconds("CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS")?
    else {
        return Ok(RelayMailboxMaintenancePolicy::disabled());
    };
    if matches!(mailbox_storage, RelayMailboxStorage::MemoryOnly) {
        return Err(
            "CONU_RELAY_MAILBOX_PURGE_INTERVAL_SECONDS requires CONU_RELAY_MAILBOX_DIR".to_string(),
        );
    }
    RelayMailboxMaintenancePolicy::every(Duration::from_secs(seconds))
        .map_err(|error| error.to_string())
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

fn relay_abuse_policy_from_env() -> Result<RelayAbusePolicy, String> {
    RelayAbusePolicy::new(Duration::from_secs(parse_duration_seconds(
        "CONU_RELAY_ABUSE_WINDOW_SECONDS",
        86_400,
    )?))
    .map_err(|error| error.to_string())
}

fn relay_abuse_storage_from_env() -> Result<RelayAbuseStorage, String> {
    match env::var("CONU_RELAY_ABUSE_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(path) => RelayAbuseStorage::file_backed(path).map_err(|error| error.to_string()),
        None => Ok(RelayAbuseStorage::memory_only()),
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

fn parse_optional_duration_seconds(name: &str) -> Result<Option<u64>, String> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => {
            let parsed = value
                .parse::<u64>()
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

#[cfg(test)]
mod tests {
    use super::*;
    use conu_relay::HostedTenantStatus;

    #[test]
    fn tenant_node_upsert_parser_defaults_permissions_to_false() {
        let parsed = parse_tenant_node_upsert_args(vec![
            "account.prod".to_string(),
            "node.hosted".to_string(),
            "--tenants-file".to_string(),
            "tenants.toml".to_string(),
            "--messages".to_string(),
            "true".to_string(),
            "--mailbox".to_string(),
            "false".to_string(),
        ])
        .expect("tenant node args parse");

        assert_eq!(parsed.account_id, "account.prod");
        assert_eq!(parsed.node_id, "node.hosted");
        assert!(parsed.permissions.messages);
        assert!(!parsed.permissions.streams);
        assert!(!parsed.permissions.rooms);
        assert!(!parsed.permissions.files);
        assert!(!parsed.permissions.mailbox);

        let error = parse_tenant_node_upsert_args(vec![
            "account.prod".to_string(),
            "node.hosted".to_string(),
            "--tenants-file".to_string(),
            "tenants.toml".to_string(),
            "--messages".to_string(),
            "yes".to_string(),
        ])
        .expect_err("invalid bool should fail");
        assert!(error.contains("must be true or false"));
    }

    #[test]
    fn tenant_admin_renderers_are_metadata_only() {
        let update = HostedTenantManifestUpdate {
            path: PathBuf::from("tenants.toml"),
            account_id: "account.prod".to_string(),
            node_id: Some("node.hosted".to_string()),
            status: HostedTenantStatus::Active,
            tenants: 1,
            nodes: 1,
            token_displayed: false,
            key_material_displayed: false,
            contents_displayed: false,
        };
        let audit = HostedTenantAudit {
            account_id: Some("account.prod".to_string()),
            tenants: 1,
            active_tenants: 1,
            revoked_tenants: 0,
            nodes: 1,
            active_nodes: 1,
            revoked_nodes: 0,
            policies: 1,
            token_displayed: false,
            key_material_displayed: false,
            contents_displayed: false,
        };
        let secret_token = "tenant-node-token-secret";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let outputs = [
            render_tenant_update_text(&update),
            render_tenant_update_json(&update),
            render_tenant_audit_text(&audit, Path::new("tenants.toml")),
            render_tenant_audit_json(&audit, Path::new("tenants.toml")),
        ];

        for output in outputs {
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }
    }

    #[test]
    fn abuse_audit_parser_and_renderers_are_metadata_only() {
        let parsed = parse_abuse_audit_args(vec![
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--json".to_string(),
        ])
        .expect("abuse audit args parse");
        assert_eq!(parsed.abuse_dir, PathBuf::from("abuse"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert!(parsed.json);

        let audit = RelayAbuseAudit {
            node_id: Some("node.hosted".to_string()),
            records: 1,
            window_started_unix: Some(1_763_596_800),
            admin_unauthorized: 1,
            admin_failed: 1,
            unauthorized_sessions: 2,
            credential_denied_sessions: 1,
            tenant_denied_sessions: 1,
            rate_limited_sessions: 1,
            session_expired: 1,
            quota_denied_forwards: 1,
            undelivered_forwards: 1,
            mailbox_rejected_forwards: 1,
            malformed_client_frames: 1,
            payload_displayed: false,
            token_displayed: false,
            token_hash_displayed: false,
            key_material_displayed: false,
            session_id_displayed: false,
            ciphertext_displayed: false,
            contents_displayed: false,
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_abuse_audit_text(&audit, Path::new("abuse")),
            render_abuse_audit_json(&audit, Path::new("abuse")),
        ];

        for output in outputs {
            assert!(output.contains("credential"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }
    }

    #[test]
    fn mailbox_audit_parser_and_renderers_are_metadata_only() {
        let parsed = parse_mailbox_audit_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--ttl-seconds".to_string(),
            "3600".to_string(),
            "--json".to_string(),
        ])
        .expect("mailbox audit args parse");
        assert_eq!(parsed.mailbox_dir, PathBuf::from("mailbox"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.ttl, Some(Duration::from_secs(3600)));
        assert!(parsed.json);

        let invalid_filter = parse_mailbox_audit_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
        ])
        .expect_err("invalid node filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));
        assert!(
            parse_mailbox_audit_args(vec![
                "--mailbox-dir".to_string(),
                "mailbox".to_string(),
                "--ttl-seconds".to_string(),
                "0".to_string(),
            ])
            .is_err()
        );

        let audit = RelayMailboxAudit {
            node_id: Some("node.hosted".to_string()),
            retention_ttl_seconds: Some(3600),
            nodes: 1,
            records: 2,
            invalid_records: 0,
            bytes: 512,
            oldest_queued_unix_millis: Some(1_763_596_800_000),
            newest_queued_unix_millis: Some(1_763_596_900_000),
            expired_records: Some(1),
            expired_bytes: Some(256),
            payload_displayed: false,
            token_displayed: false,
            token_hash_displayed: false,
            key_material_displayed: false,
            session_id_displayed: false,
            ciphertext_displayed: false,
            contents_displayed: false,
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_mailbox_audit_text(&audit, Path::new("mailbox")),
            render_mailbox_audit_json(&audit, Path::new("mailbox")),
        ];

        for output in outputs {
            assert!(output.contains("mailbox"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
            assert!(!output.contains("ENVELOPE from=node.a"));
        }
    }

    #[test]
    fn mailbox_purge_parser_and_renderers_are_metadata_only() {
        let parsed = parse_mailbox_purge_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--ttl-seconds".to_string(),
            "3600".to_string(),
            "--dry-run".to_string(),
            "--json".to_string(),
        ])
        .expect("mailbox purge args parse");
        assert_eq!(parsed.mailbox_dir, PathBuf::from("mailbox"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.ttl, Duration::from_secs(3600));
        assert!(parsed.dry_run);
        assert!(parsed.json);

        let invalid_filter = parse_mailbox_purge_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
            "--ttl-seconds".to_string(),
            "3600".to_string(),
            "--dry-run".to_string(),
        ])
        .expect_err("invalid node filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));
        assert!(
            parse_mailbox_purge_args(vec![
                "--mailbox-dir".to_string(),
                "mailbox".to_string(),
                "--ttl-seconds".to_string(),
                "3600".to_string(),
            ])
            .is_err()
        );
        assert!(
            parse_mailbox_purge_args(vec![
                "--mailbox-dir".to_string(),
                "mailbox".to_string(),
                "--ttl-seconds".to_string(),
                "3600".to_string(),
                "--dry-run".to_string(),
                "--confirm".to_string(),
            ])
            .is_err()
        );

        let report = RelayMailboxPurgeReport {
            node_id: Some("node.hosted".to_string()),
            retention_ttl_seconds: 3600,
            dry_run: false,
            confirmed: true,
            nodes: 1,
            records: 3,
            invalid_records: 1,
            bytes: 768,
            expired_records: 2,
            expired_bytes: 512,
            purged_records: 2,
            purged_bytes: 512,
            payload_displayed: false,
            token_displayed: false,
            token_hash_displayed: false,
            key_material_displayed: false,
            session_id_displayed: false,
            ciphertext_displayed: false,
            contents_displayed: false,
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_mailbox_purge_text(&report, Path::new("mailbox")),
            render_mailbox_purge_json(&report, Path::new("mailbox")),
        ];

        for output in outputs {
            assert!(output.contains("mailbox"));
            assert!(output.contains("purge") || output.contains("purged"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
            assert!(!output.contains("ENVELOPE from=node.a"));
        }
    }

    #[test]
    fn admin_hosted_dashboard_parser_and_renderers_are_metadata_only() {
        let parsed = parse_admin_dashboard_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--account".to_string(),
            "account.prod".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--json".to_string(),
        ])
        .expect("admin dashboard args parse");
        assert_eq!(parsed.relay, "ws://127.0.0.1:8787");
        assert!(parsed.admin_token_stdin);
        assert_eq!(parsed.account_id.as_deref(), Some("account.prod"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert!(parsed.json);
        assert!(parse_admin_dashboard_args(Vec::new()).is_err());
        assert!(
            parse_admin_dashboard_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
            ])
            .expect_err("admin token stdin required")
            .contains("--admin-token-stdin")
        );

        let result = RelayAdminResult {
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            credentials: 3,
            active: 1,
            revoked: 1,
            expired: 1,
            accounts: 1,
            tenants: 1,
            active_tenants: 1,
            revoked_tenants: 0,
            nodes: 2,
            active_nodes: 1,
            revoked_nodes: 1,
            tenant_policies: 1,
            accounting_records: 1,
            accounting_window_started_unix: Some(1_763_596_800),
            sessions_authenticated: 2,
            sessions_resumed: 1,
            envelopes_sent: 3,
            bytes_sent: 33,
            envelopes_received: 4,
            bytes_received: 44,
            envelopes_mailboxed: 1,
            bytes_mailboxed: 11,
            abuse_records: 1,
            abuse_window_started_unix: Some(1_763_596_800),
            admin_unauthorized: 1,
            admin_failed: 1,
            unauthorized_sessions: 2,
            credential_denied_sessions: 1,
            tenant_denied_sessions: 1,
            rate_limited_sessions: 1,
            session_expired: 1,
            quota_denied_forwards: 1,
            undelivered_forwards: 1,
            mailbox_rejected_forwards: 1,
            malformed_client_frames: 1,
            ..RelayAdminResult::new(conu_core::relay::RelayAdminAction::Dashboard, "snapshotted")
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_admin_dashboard_text(&result, "ws://127.0.0.1:8787"),
            render_admin_dashboard_json(&result, "ws://127.0.0.1:8787"),
        ];

        for output in outputs {
            assert!(output.contains("dashboard") || output.contains("snapshotted"));
            assert!(output.contains("credentials"));
            assert!(output.contains("accounting"));
            assert!(output.contains("abuse"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }
    }

    #[test]
    fn admin_mailbox_audit_parser_and_renderers_are_metadata_only() {
        let parsed = parse_admin_mailbox_audit_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--ttl-seconds".to_string(),
            "3600".to_string(),
            "--json".to_string(),
        ])
        .expect("admin mailbox audit args parse");
        assert_eq!(parsed.relay, "ws://127.0.0.1:8787");
        assert!(parsed.admin_token_stdin);
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.ttl, Some(Duration::from_secs(3600)));
        assert!(parsed.json);
        assert!(parse_admin_mailbox_audit_args(Vec::new()).is_err());
        assert!(
            parse_admin_mailbox_audit_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
            ])
            .expect_err("admin token stdin required")
            .contains("--admin-token-stdin")
        );
        assert!(
            parse_admin_mailbox_audit_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--ttl-seconds".to_string(),
                "0".to_string(),
            ])
            .is_err()
        );

        let result = RelayAdminResult {
            node_id: Some("node.hosted".to_string()),
            retention_ttl_seconds: Some(3600),
            mailbox_nodes: 1,
            mailbox_records: 2,
            mailbox_invalid_records: 1,
            mailbox_bytes: 512,
            mailbox_oldest_queued_unix_millis: Some(1_763_596_800_000),
            mailbox_newest_queued_unix_millis: Some(1_763_596_900_000),
            mailbox_expired_records: Some(1),
            mailbox_expired_bytes: Some(256),
            ..RelayAdminResult::new(conu_core::relay::RelayAdminAction::MailboxAudit, "audited")
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_admin_mailbox_audit_text(&result, "ws://127.0.0.1:8787"),
            render_admin_mailbox_audit_json(&result, "ws://127.0.0.1:8787"),
        ];

        for output in outputs {
            assert!(output.contains("mailbox"));
            assert!(output.contains("audit") || output.contains("audited"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
            assert!(!output.contains("ENVELOPE from=node.a"));
        }
    }

    #[test]
    fn admin_mailbox_purge_parser_and_renderers_are_metadata_only() {
        let parsed = parse_admin_mailbox_purge_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--ttl-seconds".to_string(),
            "3600".to_string(),
            "--dry-run".to_string(),
            "--json".to_string(),
        ])
        .expect("admin mailbox purge args parse");
        assert_eq!(parsed.relay, "ws://127.0.0.1:8787");
        assert!(parsed.admin_token_stdin);
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.ttl, Duration::from_secs(3600));
        assert!(parsed.dry_run);
        assert!(parsed.json);
        assert!(parse_admin_mailbox_purge_args(Vec::new()).is_err());
        assert!(
            parse_admin_mailbox_purge_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--ttl-seconds".to_string(),
                "3600".to_string(),
                "--dry-run".to_string(),
            ])
            .expect_err("admin token stdin required")
            .contains("--admin-token-stdin")
        );
        assert!(
            parse_admin_mailbox_purge_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--ttl-seconds".to_string(),
                "0".to_string(),
                "--dry-run".to_string(),
            ])
            .is_err()
        );
        assert!(
            parse_admin_mailbox_purge_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--ttl-seconds".to_string(),
                "3600".to_string(),
            ])
            .expect_err("purge mode required")
            .contains("exactly one")
        );
        assert!(
            parse_admin_mailbox_purge_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--ttl-seconds".to_string(),
                "3600".to_string(),
                "--dry-run".to_string(),
                "--confirm".to_string(),
            ])
            .expect_err("one purge mode required")
            .contains("exactly one")
        );

        let result = RelayAdminResult {
            node_id: Some("node.hosted".to_string()),
            retention_ttl_seconds: Some(3600),
            mailbox_nodes: 1,
            mailbox_records: 2,
            mailbox_invalid_records: 1,
            mailbox_bytes: 512,
            mailbox_expired_records: Some(1),
            mailbox_expired_bytes: Some(256),
            mailbox_dry_run: Some(false),
            mailbox_confirmed: Some(true),
            mailbox_purged_records: Some(1),
            mailbox_purged_bytes: Some(256),
            ..RelayAdminResult::new(conu_core::relay::RelayAdminAction::MailboxPurge, "purged")
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_admin_mailbox_purge_text(&result, "ws://127.0.0.1:8787"),
            render_admin_mailbox_purge_json(&result, "ws://127.0.0.1:8787"),
        ];

        for output in outputs {
            assert!(output.contains("mailbox"));
            assert!(output.contains("purge") || output.contains("purged"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
            assert!(!output.contains("ENVELOPE from=node.a"));
        }
    }

    #[test]
    fn hosted_dashboard_parser_and_renderers_are_metadata_only() {
        let parsed = parse_hosted_dashboard_args(vec![
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--tenants-file".to_string(),
            "tenants.toml".to_string(),
            "--accounting-dir".to_string(),
            "accounting".to_string(),
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--account".to_string(),
            "account.prod".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--json".to_string(),
        ])
        .expect("hosted dashboard args parse");
        assert_eq!(
            parsed.credentials_file.as_deref(),
            Some(Path::new("credentials.toml"))
        );
        assert_eq!(
            parsed.tenants_file.as_deref(),
            Some(Path::new("tenants.toml"))
        );
        assert_eq!(
            parsed.accounting_dir.as_deref(),
            Some(Path::new("accounting"))
        );
        assert_eq!(parsed.abuse_dir.as_deref(), Some(Path::new("abuse")));
        assert_eq!(parsed.account_id.as_deref(), Some("account.prod"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert!(parsed.json);
        assert!(parse_hosted_dashboard_args(Vec::new()).is_err());
        let invalid_filter = parse_hosted_dashboard_args(vec![
            "--accounting-dir".to_string(),
            "accounting".to_string(),
            "--account".to_string(),
            "bad secret value".to_string(),
        ])
        .expect_err("invalid account filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));

        let snapshot = HostedDashboardSnapshot {
            credentials_file: Some(PathBuf::from("credentials.toml")),
            tenants_file: Some(PathBuf::from("tenants.toml")),
            accounting_dir: Some(PathBuf::from("accounting")),
            abuse_dir: Some(PathBuf::from("abuse")),
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            credentials: Some(HostedCredentialAudit {
                account_id: Some("account.prod".to_string()),
                credentials: 3,
                active: 1,
                revoked: 1,
                expired: 1,
                accounts: 1,
                token_displayed: false,
                contents_displayed: false,
            }),
            tenants: Some(HostedTenantAudit {
                account_id: Some("account.prod".to_string()),
                tenants: 1,
                active_tenants: 1,
                revoked_tenants: 0,
                nodes: 2,
                active_nodes: 1,
                revoked_nodes: 1,
                policies: 1,
                token_displayed: false,
                key_material_displayed: false,
                contents_displayed: false,
            }),
            accounting: Some(RelayAccountingAudit {
                node_id: Some("node.hosted".to_string()),
                records: 1,
                window_started_unix: Some(1_763_596_800),
                sessions_authenticated: 2,
                sessions_resumed: 1,
                envelopes_sent: 3,
                bytes_sent: 33,
                envelopes_received: 4,
                bytes_received: 44,
                envelopes_mailboxed: 1,
                bytes_mailboxed: 11,
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            }),
            abuse: Some(RelayAbuseAudit {
                node_id: Some("node.hosted".to_string()),
                records: 1,
                window_started_unix: Some(1_763_596_800),
                admin_unauthorized: 1,
                admin_failed: 1,
                unauthorized_sessions: 2,
                credential_denied_sessions: 1,
                tenant_denied_sessions: 1,
                rate_limited_sessions: 1,
                session_expired: 1,
                quota_denied_forwards: 1,
                undelivered_forwards: 1,
                mailbox_rejected_forwards: 1,
                malformed_client_frames: 1,
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            }),
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_hosted_dashboard_text(&snapshot),
            render_hosted_dashboard_json(&snapshot),
        ];

        for output in outputs {
            assert!(output.contains("dashboard") || output.contains("snapshotted"));
            assert!(output.contains("credentials"));
            assert!(output.contains("accounting"));
            assert!(output.contains("abuse"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }
    }
}
