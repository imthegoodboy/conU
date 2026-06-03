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
    CredentialManifestUpdate, HostedAccountNodeSuspension, HostedAccountSuspension,
    HostedAdminTokenAudit, HostedCredentialAudit, HostedTenantAudit, HostedTenantManifestUpdate,
    HostedTenantPermissions, IssuedRelayCredential, RelayAbuseAudit, RelayAbusePolicy,
    RelayAbuseStorage, RelayAccountingAudit, RelayAccountingPolicy, RelayAccountingStorage,
    RelayConfig, RelayCredential, RelayMailboxAudit, RelayMailboxMaintenancePolicy,
    RelayMailboxPolicy, RelayMailboxPurgeReport, RelayMailboxStorage, RelaySessionAudit,
    RelaySessionPolicy, RelaySessionStorage, audit_hosted_admin_tokens_file,
    audit_hosted_relay_credentials_file, audit_hosted_relay_credentials_file_with_node,
    audit_hosted_tenants_file, audit_hosted_tenants_file_with_node, audit_relay_abuse_dir,
    audit_relay_accounting_dir, audit_relay_mailbox_dir, audit_relay_session_state_dir,
    issue_relay_credential, purge_relay_mailbox_dir, relay_credential_manifest_contains_node,
    relay_token_sha256_hex, revoke_hosted_relay_credentials_for_account_node_in_file,
    revoke_hosted_tenant_in_file, revoke_hosted_tenant_node_in_file,
    revoke_relay_credential_in_file, suspend_hosted_account_in_files,
    suspend_hosted_account_node_in_files, upsert_hosted_tenant_in_file,
    upsert_hosted_tenant_node_in_file, upsert_issued_relay_credential_in_file,
    write_issued_relay_token_file,
};

const ABUSE_THRESHOLD_POLICY_FILE_VERSION: &str = "1";
const MAILBOX_RETENTION_POLICY_FILE_VERSION: &str = "1";
const HOSTED_FLEET_DASHBOARD_FILE_VERSION: &str = "1";
const MAX_RELAY_CLI_FILE_BYTES: u64 = 1024 * 1024;
const MAX_RELAY_STDIN_TOKEN_BYTES: u64 = 4096;

fn read_required_regular_cli_file(path: &Path, label: &'static str) -> Result<String, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label} file: {error}"))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        return Err(format!("inspect {label} file: path is not a regular file"));
    }
    if metadata.len() > MAX_RELAY_CLI_FILE_BYTES {
        return Err(format!(
            "inspect {label} file: file exceeds {MAX_RELAY_CLI_FILE_BYTES} bytes"
        ));
    }

    let mut file = fs::File::open(path).map_err(|error| format!("read {label} file: {error}"))?;
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label} file: {error}"))?;
    let path_file_type = path_metadata.file_type();
    if path_file_type.is_symlink()
        || !path_file_type.is_file()
        || !relay_cli_file_metadata_matches(&metadata, &path_metadata)
    {
        return Err(format!("inspect {label} file: path changed while reading"));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("inspect {label} file: {error}"))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > MAX_RELAY_CLI_FILE_BYTES
        || !relay_cli_file_metadata_matches(&metadata, &opened_metadata)
    {
        return Err(format!("read {label} file: path changed while reading"));
    }

    let mut contents = String::new();
    let limit = MAX_RELAY_CLI_FILE_BYTES.saturating_add(1);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_string(&mut contents)
        .map_err(|error| format!("read {label} file: {error}"))?;
    if contents.len() as u64 > MAX_RELAY_CLI_FILE_BYTES {
        return Err(format!(
            "read {label} file: file exceeds {MAX_RELAY_CLI_FILE_BYTES} bytes"
        ));
    }
    Ok(contents)
}

fn relay_cli_file_metadata_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.len() == current.len() && relay_cli_file_identity_matches(expected, current)
}

#[cfg(unix)]
fn relay_cli_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == current.dev() && expected.ino() == current.ino()
}

#[cfg(windows)]
fn relay_cli_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    expected.file_attributes() == current.file_attributes()
        && expected.creation_time() == current.creation_time()
        && expected.last_write_time() == current.last_write_time()
        && expected.file_size() == current.file_size()
}

#[cfg(not(any(unix, windows)))]
fn relay_cli_file_identity_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.modified().ok() == current.modified().ok()
}

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
        Some("--admin-token-audit") => match admin_token_audit_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--hosted-readiness") => match hosted_readiness_from_args(args.collect()) {
            Ok(status) => status.exit_code(),
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
        Some("--admin-session-audit") => match admin_session_audit_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--admin-abuse-threshold-report") => {
            match admin_abuse_threshold_report_from_args(args.collect()) {
                Ok(status) => status.exit_code(),
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--admin-tenant-upsert") => match admin_tenant_upsert_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--admin-tenant-revoke") => match admin_tenant_revoke_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--admin-tenant-node-upsert") => {
            match admin_tenant_node_upsert_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--admin-tenant-node-revoke") => {
            match admin_tenant_node_revoke_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--admin-tenant-audit") => match admin_tenant_audit_from_args(args.collect()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("conU relay failed: {error}");
                ExitCode::from(2)
            }
        },
        Some("--admin-hosted-account-suspend") => {
            match admin_hosted_account_suspend_from_args(args.collect()) {
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
        Some("--hosted-account-suspend") => {
            match hosted_account_suspend_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-account-audit") => {
            match hosted_fleet_account_audit_from_args(args.collect()) {
                Ok(status) => status.exit_code(),
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-account-suspend") => {
            match hosted_fleet_account_suspend_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-credential-revoke") => {
            match hosted_fleet_credential_revoke_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-tenant-upsert") => {
            match hosted_fleet_tenant_account_upsert_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-tenant-revoke") => {
            match hosted_fleet_tenant_account_revoke_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-tenant-node-upsert") => {
            match hosted_fleet_tenant_node_upsert_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-tenant-node-revoke") => {
            match hosted_fleet_tenant_node_revoke_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--session-audit") => match session_audit_from_args(args.collect()) {
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
        Some("--abuse-threshold-report") => {
            match abuse_threshold_report_from_args(args.collect()) {
                Ok(status) => status.exit_code(),
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
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
        Some("--hosted-fleet-mailbox-purge") => {
            match hosted_fleet_mailbox_purge_from_args(args.collect()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-abuse-response-plan") => {
            match hosted_fleet_abuse_response_plan_from_args(args.collect()) {
                Ok(status) => status.exit_code(),
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Some("--hosted-fleet-dashboard") => {
            match hosted_fleet_dashboard_from_args(args.collect()) {
                Ok(status) => status.exit_code(),
                Err(error) => {
                    eprintln!("conU relay failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
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
        Some(_unknown) => {
            eprintln!("{}", unknown_option_error());
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

fn unknown_option_error() -> String {
    "unknown option; contentsDisplayed=false".to_string()
}

fn print_help() {
    println!(
        r"conu-relay - conU relay and bootstrap scaffold

Usage:
  conu-relay
  conu-relay --serve [addr]
  conu-relay --hash-token
  conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <account-id>] [--json]
  conu-relay --hosted-readiness [--bind-addr <addr>] [--credentials-file <path>] [--tenants-file <path>] [--admin-tokens-file <path>] [--session-state-dir <path>] [--mailbox-dir <path>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--accounting-dir <path>] [--abuse-dir <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--account <account-id>] [--node <node-id>] [--json] [--fail-on-warning]
  conu-relay --issue-credential <node-id> --token-out <path> [--credentials-file <path>] [--replace] [--expires-at-unix <seconds>] [--json]
  conu-relay --revoke-credential <node-id> --credentials-file <path> [--json]
  conu-relay --admin-issue-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin --token-out <path> [--expires-at-unix <seconds>] [--json]
  conu-relay --admin-rotate-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin --token-out <path> [--expires-at-unix <seconds>] [--json]
  conu-relay --admin-revoke-credential <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin [--json]
  conu-relay --admin-audit-credentials --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--json]
  conu-relay --admin-hosted-dashboard --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--node <node-id>] [--json]
  conu-relay --admin-session-audit --relay <ws://host:port/path> --admin-token-stdin [--node <node-id>] [--json]
  conu-relay --admin-abuse-threshold-report --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--node <node-id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold]
  conu-relay --admin-tenant-upsert <account-id> --relay <ws://host:port/path> --admin-token-stdin [--json]
  conu-relay --admin-tenant-revoke <account-id> --relay <ws://host:port/path> --admin-token-stdin [--json]
  conu-relay --admin-tenant-node-upsert <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] [--signing-key-id <id>] [--exchange-key-id <id>] [--json]
  conu-relay --admin-tenant-node-revoke <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin [--json]
  conu-relay --admin-tenant-audit --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--json]
  conu-relay --admin-hosted-account-suspend <account-id> --relay <ws://host:port/path> --admin-token-stdin [--json]
  conu-relay --admin-mailbox-audit --relay <ws://host:port/path> --admin-token-stdin [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]
  conu-relay --admin-mailbox-purge --relay <ws://host:port/path> --admin-token-stdin [--ttl-seconds <seconds>] [--node <node-id>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]
  conu-relay --tenant-upsert <account-id> --tenants-file <path> [--json]
  conu-relay --tenant-revoke <account-id> --tenants-file <path> [--json]
  conu-relay --tenant-node-upsert <account-id> <node-id> --tenants-file <path> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] [--signing-key-id <id>] [--exchange-key-id <id>] [--json]
  conu-relay --tenant-node-revoke <account-id> <node-id> --tenants-file <path> [--json]
  conu-relay --tenant-audit --tenants-file <path> [--account <account-id>] [--json]
  conu-relay --hosted-account-suspend <account-id> --credentials-file <path> --tenants-file <path> [--json]
  conu-relay --hosted-fleet-account-audit <account-id> --fleet-file <path> [--node <node-id>] [--json] [--fail-on-warning]
  conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file <path> [--node <node-id>] (--dry-run|--confirm) [--json]
  conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file <path> (--dry-run|--confirm) [--json]
  conu-relay --hosted-fleet-tenant-upsert <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]
  conu-relay --hosted-fleet-tenant-revoke <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]
  conu-relay --hosted-fleet-tenant-node-upsert <account-id> <node-id> --fleet-file <path> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] [--signing-key-id <id>] [--exchange-key-id <id>] (--dry-run|--confirm) [--json]
  conu-relay --hosted-fleet-tenant-node-revoke <account-id> <node-id> --fleet-file <path> (--dry-run|--confirm) [--json]
  conu-relay --session-audit --session-state-dir <path> [--node <node-id>] [--json]
  conu-relay --abuse-audit --abuse-dir <path> [--node <node-id>] [--json]
  conu-relay --abuse-threshold-report --abuse-dir <path> [--node <node-id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold]
  conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]
  conu-relay --mailbox-purge --mailbox-dir <path> [--ttl-seconds <seconds>] [--node <node-id>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]
  conu-relay --hosted-fleet-mailbox-purge --fleet-file <path> [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]
  conu-relay --hosted-fleet-abuse-response-plan --fleet-file <path> [--node <node-id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-action]
  conu-relay --hosted-fleet-dashboard --fleet-file <path> [--account <account-id>] [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold] [--fail-on-retention]
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
  CONU_RELAY_ADMIN_TOKENS_FILE        optional hashed scoped hosted admin token manifest
  CONU_RELAY_TENANTS_FILE             optional hosted tenant metadata registry; requires hosted admin config and CONU_RELAY_CREDENTIALS_FILE

CONU_RELAY_CREDENTIALS_FILE overrides CONU_RELAY_CREDENTIALS; CONU_RELAY_CREDENTIALS overrides
CONU_RELAY_TOKEN. Non-loopback binds such as 0.0.0.0 require custom shared or scoped tokens
with at least 24 characters. Use --hash-token with stdin to generate credential-file hash fields,
--issue-credential to generate a scoped token file and optional manifest update, or
--revoke-credential to mark a scoped credential revoked without displaying tokens. Hosted admin
commands authenticate with an admin token read from stdin, send only node-token hash metadata to the
relay, and write the raw node token locally only after the relay confirms the update. CONU_RELAY_ADMIN_TOKEN
remains a full-admin compatibility path; CONU_RELAY_ADMIN_TOKENS_FILE can grant hashed tokens narrower
credentials, tenants, dashboard, sessions, mailbox-audit, and mailbox-purge scopes. Local and admin
tenant commands manage account, node, public key-id, and hosted permission metadata only; hosted
account suspension revokes the tenant and all account credential records together. These commands never
grant local peer policy or display private keys, tokens, hashes, payloads, or ciphertext bodies.
Admin hosted dashboard, tenant, and session-state snapshots require the admin token over the relay
control plane and return metadata-only credential, tenant, accounting, abuse, or session-state
counters. Admin mailbox audits and purges require the admin token over the relay control plane and
inspect or clean durable mailbox retention metadata from the running relay only. Session audit reads
session-state counts and timestamp bounds only, abuse audit reads aggregate enforcement counters only,
mailbox audit reads durable mailbox timestamps and file sizes only, manual and admin mailbox purge require
dry-run or explicit confirmation, and scheduled mailbox purge requires an explicit local interval plus
CONU_RELAY_MAILBOX_DIR before deleting expired durable mailbox files. Hosted dashboard
snapshots combine configured credential, tenant, accounting, and abuse summaries without displaying
tokens, token hashes, payloads, ciphertext bodies, frame contents, private keys, or relay session ids.
Hosted fleet dashboard snapshots read a versioned manifest of multiple relay-local metadata stores
and aggregate only credential, tenant, session-state, mailbox, accounting, and abuse counters. They
can apply guarded --retention-policy-file mailbox TTL/node defaults and guarded --thresholds-file
or --max-* abuse limits to aggregate fleet counters, preserving stdout and returning exit code 3
only with --fail-on-retention or --fail-on-threshold. Per-relay mailbox_ttl_seconds entries remain
source-specific retention overrides unless a CLI --ttl-seconds override is supplied. The same
manifest can drive --hosted-fleet-abuse-response-plan for deterministic operator action categories
over aggregate abuse thresholds, --hosted-fleet-account-audit for read-only account or account/node
credential/tenant consistency warnings, --hosted-fleet-account-suspend for dry-run or explicitly confirmed
tenant-first account or account/node suspension across complete local credential/tenant source pairs,
--hosted-fleet-credential-revoke for guarded dry-run or confirmed account/node credential revocation
across configured local credential manifests,
--hosted-fleet-tenant-upsert or --hosted-fleet-tenant-revoke for guarded dry-run or confirmed
tenant account lifecycle across configured local tenant registries,
--hosted-fleet-tenant-node-upsert or --hosted-fleet-tenant-node-revoke for guarded dry-run or
confirmed tenant-node metadata workflows across configured local tenant registries, and
--hosted-fleet-mailbox-purge for dry-run or explicitly confirmed expired durable mailbox cleanup
across configured local mailbox stores. The manifest must include explicit false display guards and
does not make conU a managed billing, remote purge, remote tenant control, or adaptive abuse service.
Mailbox audit and purge commands accept reusable --retention-policy-file policy files with
version set to 1, optional ttl_seconds and node_id keys, and explicit false display guards;
CLI --ttl-seconds and --node values override file values. Purge commands still require a
retention TTL from the policy file or CLI plus exactly one of --dry-run or --confirm. Abuse
threshold reports accept reusable --thresholds-file policy files with version set to 1, max_*
threshold keys, and explicit false display guards; CLI --max-* values override file values.
At least one threshold must be supplied by file or CLI. Abuse threshold reports preserve stdout
report output and return exit code 3 only when --fail-on-threshold is set and one or more configured
thresholds are exceeded. Use --admin-token-audit to inspect scoped admin-token manifest counts,
account boundaries, expiry metadata, and granted scopes without printing raw admin tokens or hashes.
Use --hosted-readiness before startup or release smoke to combine the same local credential,
tenant, admin-token, session-state, mailbox, accounting, abuse, retention-policy, and threshold
checks into one metadata-only preflight; --fail-on-warning preserves stdout and returns exit code 3
when attention is needed."
    );
}

#[derive(Debug, Clone)]
struct AdminTokenAuditArgs {
    admin_tokens_file: PathBuf,
    bind_addr: String,
    account_id: Option<String>,
    json: bool,
}

fn admin_token_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_token_audit_args(args)?;
    let audit = audit_hosted_admin_tokens_file(
        &parsed.admin_tokens_file,
        parsed.account_id.as_deref(),
        &parsed.bind_addr,
    )
    .map_err(|error| error.to_string())?;

    if parsed.json {
        println!(
            "{}",
            render_admin_token_audit_json(&audit, &parsed.admin_tokens_file, &parsed.bind_addr)
        );
    } else {
        println!(
            "{}",
            render_admin_token_audit_text(&audit, &parsed.admin_tokens_file, &parsed.bind_addr)
        );
    }
    Ok(())
}

fn parse_admin_token_audit_args(args: Vec<String>) -> Result<AdminTokenAuditArgs, String> {
    let mut admin_tokens_file = None::<PathBuf>;
    let mut bind_addr = "127.0.0.1:0".to_string();
    let mut account_id = None::<String>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--admin-tokens-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_token_audit_usage());
                };
                admin_tokens_file = Some(PathBuf::from(value));
            }
            "--bind-addr" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_token_audit_usage());
                };
                bind_addr = value.to_string();
            }
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_token_audit_usage());
                };
                account_id = Some(value.to_string());
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_token_audit_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(admin_token_audit_usage()),
        }
        index += 1;
    }

    let admin_tokens_file = admin_tokens_file
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(admin_token_audit_usage)?;
    let bind_addr = validate_relay_bind_addr(bind_addr)?;
    let account_id = account_id
        .map(|value| validate_admin_token_audit_filter_id(value, "account id"))
        .transpose()?;

    Ok(AdminTokenAuditArgs {
        admin_tokens_file,
        bind_addr,
        account_id,
        json,
    })
}

fn admin_token_audit_usage() -> String {
    "usage: conu-relay --admin-token-audit --admin-tokens-file <path> [--bind-addr <addr>] [--account <account-id>] [--json]".to_string()
}

fn validate_relay_bind_addr(value: String) -> Result<String, String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err("relay bind addr cannot be empty".to_string());
    }
    if value.len() > 256 {
        return Err("relay bind addr is too long".to_string());
    }
    if value.chars().any(char::is_whitespace) {
        return Err("relay bind addr cannot contain whitespace".to_string());
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(character, '.' | ':' | '-' | '_' | '[' | ']' | '*')
    }) {
        return Err(
            "relay bind addr must use host:port characters only and cannot contain secrets"
                .to_string(),
        );
    }
    Ok(value)
}

fn validate_admin_token_audit_filter_id(
    value: String,
    label: &'static str,
) -> Result<String, String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(format!("relay admin-token audit {label} cannot be empty"));
    }
    if value.len() > 120 {
        return Err(format!("relay admin-token audit {label} is too long"));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(format!(
            "relay admin-token audit {label} must use ASCII letters, numbers, dash, underscore, or dot"
        ));
    }
    Ok(value)
}

fn render_admin_token_audit_text(
    audit: &HostedAdminTokenAudit,
    admin_tokens_file: &Path,
    bind_addr: &str,
) -> String {
    format!(
        r"conU hosted relay admin-token audit

account: {}
admin tokens file: {}
bind addr: {}
records: {}
active: {}
revoked: {}
expired: {}
account scoped records: {}
global records: {}
accounts: {}
expiring records: {}
next expires at unix: {}
last expires at unix: {}
scope credentials: {}
scope tenants: {}
scope dashboard: {}
scope sessions: {}
scope mailbox audit: {}
scope mailbox purge: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        audit.account_id.as_deref().unwrap_or("all"),
        admin_tokens_file.display(),
        bind_addr,
        audit.records,
        audit.active,
        audit.revoked,
        audit.expired,
        audit.account_scoped_records,
        audit.global_records,
        audit.accounts,
        audit.expiring_records,
        optional_u64_text(audit.next_expires_at_unix),
        optional_u64_text(audit.last_expires_at_unix),
        audit.scope_credentials,
        audit.scope_tenants,
        audit.scope_dashboard,
        audit.scope_sessions,
        audit.scope_mailbox_audit,
        audit.scope_mailbox_purge,
        yes_no(audit.payload_displayed),
        yes_no(audit.token_displayed),
        yes_no(audit.token_hash_displayed),
        yes_no(audit.key_material_displayed),
        yes_no(audit.session_id_displayed),
        yes_no(audit.ciphertext_displayed),
        yes_no(audit.contents_displayed)
    )
}

fn render_admin_token_audit_json(
    audit: &HostedAdminTokenAudit,
    admin_tokens_file: &Path,
    bind_addr: &str,
) -> String {
    format!(
        r#"{{
  "status": "audited",
  "accountId": {},
  "adminTokensFile": "{}",
  "bindAddr": "{}",
  "records": {},
  "active": {},
  "revoked": {},
  "expired": {},
  "accountScopedRecords": {},
  "globalRecords": {},
  "accounts": {},
  "expiringRecords": {},
  "nextExpiresAtUnix": {},
  "lastExpiresAtUnix": {},
  "scopeCredentials": {},
  "scopeTenants": {},
  "scopeDashboard": {},
  "scopeSessions": {},
  "scopeMailboxAudit": {},
  "scopeMailboxPurge": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        optional_string_json(audit.account_id.as_deref()),
        json_escape(&admin_tokens_file.display().to_string()),
        json_escape(bind_addr),
        audit.records,
        audit.active,
        audit.revoked,
        audit.expired,
        audit.account_scoped_records,
        audit.global_records,
        audit.accounts,
        audit.expiring_records,
        optional_u64_json(audit.next_expires_at_unix),
        optional_u64_json(audit.last_expires_at_unix),
        audit.scope_credentials,
        audit.scope_tenants,
        audit.scope_dashboard,
        audit.scope_sessions,
        audit.scope_mailbox_audit,
        audit.scope_mailbox_purge,
        bool_json(audit.payload_displayed),
        bool_json(audit.token_displayed),
        bool_json(audit.token_hash_displayed),
        bool_json(audit.key_material_displayed),
        bool_json(audit.session_id_displayed),
        bool_json(audit.ciphertext_displayed),
        bool_json(audit.contents_displayed)
    )
}

#[derive(Debug, Clone)]
struct HostedReadinessArgs {
    bind_addr: String,
    credentials_file: Option<PathBuf>,
    tenants_file: Option<PathBuf>,
    admin_tokens_file: Option<PathBuf>,
    session_state_dir: Option<PathBuf>,
    mailbox_dir: Option<PathBuf>,
    retention_policy_file: Option<PathBuf>,
    mailbox_node_id: Option<String>,
    mailbox_ttl: Option<Duration>,
    accounting_dir: Option<PathBuf>,
    abuse_dir: Option<PathBuf>,
    thresholds_file: Option<PathBuf>,
    abuse_thresholds: AbuseThresholds,
    account_id: Option<String>,
    node_id: Option<String>,
    json: bool,
    fail_on_warning: bool,
}

#[derive(Debug, Clone)]
struct HostedReadinessReport {
    bind_addr: String,
    public_bind: bool,
    credentials_file: Option<PathBuf>,
    tenants_file: Option<PathBuf>,
    admin_tokens_file: Option<PathBuf>,
    session_state_dir: Option<PathBuf>,
    mailbox_dir: Option<PathBuf>,
    retention_policy_file: Option<PathBuf>,
    mailbox_ttl: Option<Duration>,
    accounting_dir: Option<PathBuf>,
    abuse_dir: Option<PathBuf>,
    thresholds_file: Option<PathBuf>,
    account_id: Option<String>,
    node_id: Option<String>,
    credentials: Option<HostedCredentialAudit>,
    tenants: Option<HostedTenantAudit>,
    admin_tokens: Option<HostedAdminTokenAudit>,
    session_state: Option<RelaySessionAudit>,
    mailbox: Option<RelayMailboxAudit>,
    accounting: Option<RelayAccountingAudit>,
    abuse: Option<RelayAbuseAudit>,
    abuse_threshold_report: Option<AbuseThresholdReport>,
}

#[derive(Debug, Clone, Copy)]
struct HostedReadinessExit {
    warnings: usize,
    fail_on_warning: bool,
}

impl HostedReadinessExit {
    fn exit_code(self) -> ExitCode {
        if self.fail_on_warning && self.warnings > 0 {
            ExitCode::from(3)
        } else {
            ExitCode::SUCCESS
        }
    }
}

fn hosted_readiness_from_args(args: Vec<String>) -> Result<HostedReadinessExit, String> {
    let parsed = parse_hosted_readiness_args(args)?;
    let report = hosted_readiness_report(&parsed)?;
    let warnings = report.warning_count();
    if parsed.json {
        println!("{}", render_hosted_readiness_json(&report));
    } else {
        println!("{}", render_hosted_readiness_text(&report));
    }
    Ok(HostedReadinessExit {
        warnings,
        fail_on_warning: parsed.fail_on_warning,
    })
}

fn parse_hosted_readiness_args(args: Vec<String>) -> Result<HostedReadinessArgs, String> {
    let mut bind_addr = "127.0.0.1:0".to_string();
    let mut credentials_file = None::<PathBuf>;
    let mut tenants_file = None::<PathBuf>;
    let mut admin_tokens_file = None::<PathBuf>;
    let mut session_state_dir = None::<PathBuf>;
    let mut mailbox_dir = None::<PathBuf>;
    let mut retention_policy_file = None::<PathBuf>;
    let mut mailbox_ttl = None::<Duration>;
    let mut accounting_dir = None::<PathBuf>;
    let mut abuse_dir = None::<PathBuf>;
    let mut thresholds_file = None::<PathBuf>;
    let mut cli_thresholds = AbuseThresholds::default();
    let mut account_id = None::<String>;
    let mut node_id = None::<String>;
    let mut json = false;
    let mut fail_on_warning = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--bind-addr" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                bind_addr = value.to_string();
            }
            "--credentials-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                credentials_file = Some(PathBuf::from(value));
            }
            "--tenants-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                tenants_file = Some(PathBuf::from(value));
            }
            "--admin-tokens-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                admin_tokens_file = Some(PathBuf::from(value));
            }
            "--session-state-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                session_state_dir = Some(PathBuf::from(value));
            }
            "--mailbox-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                mailbox_dir = Some(PathBuf::from(value));
            }
            "--retention-policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                if value.trim().is_empty() {
                    return Err(hosted_readiness_usage());
                }
                retention_policy_file = Some(PathBuf::from(value));
            }
            "--ttl-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                mailbox_ttl = Some(parse_positive_cli_duration(value, "--ttl-seconds")?);
            }
            "--accounting-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                accounting_dir = Some(PathBuf::from(value));
            }
            "--abuse-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                abuse_dir = Some(PathBuf::from(value));
            }
            "--thresholds-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                if value.trim().is_empty() {
                    return Err(hosted_readiness_usage());
                }
                thresholds_file = Some(PathBuf::from(value));
            }
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                account_id = Some(value.to_string());
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                node_id = Some(value.to_string());
            }
            "--json" => json = true,
            "--fail-on-warning" => fail_on_warning = true,
            "--help" | "-h" => return Err(hosted_readiness_usage()),
            value if value.starts_with("--max-") => {
                index += 1;
                let Some(limit) = args.get(index) else {
                    return Err(hosted_readiness_usage());
                };
                parse_abuse_threshold_option(&mut cli_thresholds, value, limit)?;
            }
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(hosted_readiness_usage()),
        }
        index += 1;
    }

    let bind_addr = validate_relay_bind_addr(bind_addr)?;
    credentials_file = credentials_file.filter(|path| !path.as_os_str().is_empty());
    tenants_file = tenants_file.filter(|path| !path.as_os_str().is_empty());
    admin_tokens_file = admin_tokens_file.filter(|path| !path.as_os_str().is_empty());
    session_state_dir = session_state_dir.filter(|path| !path.as_os_str().is_empty());
    mailbox_dir = mailbox_dir.filter(|path| !path.as_os_str().is_empty());
    retention_policy_file = retention_policy_file.filter(|path| !path.as_os_str().is_empty());
    accounting_dir = accounting_dir.filter(|path| !path.as_os_str().is_empty());
    abuse_dir = abuse_dir.filter(|path| !path.as_os_str().is_empty());
    thresholds_file = thresholds_file.filter(|path| !path.as_os_str().is_empty());
    let account_id = account_id
        .map(|value| validate_dashboard_filter_id(value, "account id"))
        .transpose()?;
    let node_id = node_id
        .map(|value| validate_dashboard_filter_id(value, "node id"))
        .transpose()?;
    let threshold_source_configured = thresholds_file.is_some() || cli_thresholds.has_any();
    if retention_policy_file.is_some() && mailbox_dir.is_none() {
        return Err("--retention-policy-file requires --mailbox-dir".to_string());
    }
    if threshold_source_configured && abuse_dir.is_none() {
        return Err("--thresholds-file and --max-* require --abuse-dir".to_string());
    }
    let mailbox_retention = merged_mailbox_retention_policy(
        retention_policy_file.as_deref(),
        node_id.clone(),
        mailbox_ttl,
    )?;
    let abuse_thresholds = merged_abuse_thresholds(thresholds_file.as_deref(), cli_thresholds)?;

    if credentials_file.is_none()
        && tenants_file.is_none()
        && admin_tokens_file.is_none()
        && session_state_dir.is_none()
        && mailbox_dir.is_none()
        && accounting_dir.is_none()
        && abuse_dir.is_none()
    {
        return Err(hosted_readiness_usage());
    }
    if threshold_source_configured && !abuse_thresholds.has_any() {
        return Err(hosted_readiness_usage());
    }

    Ok(HostedReadinessArgs {
        bind_addr,
        credentials_file,
        tenants_file,
        admin_tokens_file,
        session_state_dir,
        mailbox_dir,
        retention_policy_file,
        mailbox_node_id: mailbox_retention.node_id,
        mailbox_ttl: mailbox_retention.ttl,
        accounting_dir,
        abuse_dir,
        thresholds_file,
        abuse_thresholds,
        account_id,
        node_id,
        json,
        fail_on_warning,
    })
}

fn hosted_readiness_usage() -> String {
    "usage: conu-relay --hosted-readiness [--bind-addr <addr>] [--credentials-file <path>] [--tenants-file <path>] [--admin-tokens-file <path>] [--session-state-dir <path>] [--mailbox-dir <path>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--accounting-dir <path>] [--abuse-dir <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--account <account-id>] [--node <node-id>] [--json] [--fail-on-warning]".to_string()
}

fn hosted_readiness_report(args: &HostedReadinessArgs) -> Result<HostedReadinessReport, String> {
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
    let admin_tokens = args
        .admin_tokens_file
        .as_ref()
        .map(|path| {
            audit_hosted_admin_tokens_file(path, args.account_id.as_deref(), &args.bind_addr)
        })
        .transpose()
        .map_err(|error| error.to_string())?;
    let session_state = args
        .session_state_dir
        .as_ref()
        .map(|path| audit_relay_session_state_dir(path, args.node_id.as_deref()))
        .transpose()
        .map_err(|error| error.to_string())?;
    let mailbox = args
        .mailbox_dir
        .as_ref()
        .map(|path| {
            audit_relay_mailbox_dir(path, args.mailbox_node_id.as_deref(), args.mailbox_ttl)
        })
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
    let abuse_threshold_report = match (&abuse, args.abuse_thresholds.has_any()) {
        (Some(audit), true) => args.abuse_dir.as_ref().map(|path| {
            abuse_threshold_report_from_audit(audit, args.abuse_thresholds, path.clone())
        }),
        _ => None,
    };

    Ok(HostedReadinessReport {
        bind_addr: args.bind_addr.clone(),
        public_bind: readiness_bind_addr_is_public(&args.bind_addr),
        credentials_file: args.credentials_file.clone(),
        tenants_file: args.tenants_file.clone(),
        admin_tokens_file: args.admin_tokens_file.clone(),
        session_state_dir: args.session_state_dir.clone(),
        mailbox_dir: args.mailbox_dir.clone(),
        retention_policy_file: args.retention_policy_file.clone(),
        mailbox_ttl: args.mailbox_ttl,
        accounting_dir: args.accounting_dir.clone(),
        abuse_dir: args.abuse_dir.clone(),
        thresholds_file: args.thresholds_file.clone(),
        account_id: args.account_id.clone(),
        node_id: args.node_id.clone(),
        credentials,
        tenants,
        admin_tokens,
        session_state,
        mailbox,
        accounting,
        abuse,
        abuse_threshold_report,
    })
}

impl HostedReadinessReport {
    fn status(&self) -> &'static str {
        if self.warning_count() == 0 {
            "ready"
        } else {
            "needs_attention"
        }
    }

    fn checked_surfaces(&self) -> usize {
        [
            self.credentials.is_some(),
            self.tenants.is_some(),
            self.admin_tokens.is_some(),
            self.session_state.is_some(),
            self.mailbox.is_some(),
            self.accounting.is_some(),
            self.abuse.is_some(),
        ]
        .into_iter()
        .filter(|configured| *configured)
        .count()
    }

    fn warning_count(&self) -> usize {
        [
            self.public_bind && self.credentials.is_none(),
            self.credentials.is_none(),
            self.credentials
                .as_ref()
                .is_some_and(|audit| audit.active == 0),
            self.admin_tokens.is_none(),
            self.admin_tokens
                .as_ref()
                .is_some_and(|audit| audit.active == 0),
            self.tenants
                .as_ref()
                .is_some_and(|audit| audit.active_tenants == 0 || audit.active_nodes == 0),
            self.session_state
                .as_ref()
                .is_some_and(|audit| audit.invalid_records > 0),
            self.mailbox
                .as_ref()
                .is_some_and(|audit| audit.invalid_records > 0),
            self.accounting.is_none(),
            self.abuse.is_none(),
            self.abuse_threshold_report
                .as_ref()
                .is_some_and(|report| report.threshold_exceeded > 0),
            !self.display_guards_clean(),
        ]
        .into_iter()
        .filter(|warning| *warning)
        .count()
    }

    fn public_bind_has_credentials(&self) -> bool {
        !self.public_bind || self.credentials.is_some()
    }

    fn display_guards_clean(&self) -> bool {
        !readiness_payload_displayed(self)
            && !readiness_token_displayed(self)
            && !readiness_token_hash_displayed(self)
            && !readiness_key_material_displayed(self)
            && !readiness_session_id_displayed(self)
            && !readiness_ciphertext_displayed(self)
            && !readiness_contents_displayed(self)
    }
}

fn readiness_bind_addr_is_public(bind_addr: &str) -> bool {
    let host = readiness_bind_host(bind_addr);
    if host == "localhost" || host.eq_ignore_ascii_case("localhost.localdomain") {
        return false;
    }
    if host == "*" {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| !ip.is_loopback())
        .unwrap_or(true)
}

fn readiness_bind_host(bind_addr: &str) -> String {
    let bind_addr = bind_addr.trim();
    if let Some(rest) = bind_addr.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(host, _)| host)
            .unwrap_or(rest)
            .to_string();
    }
    bind_addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(bind_addr)
        .to_string()
}

fn render_hosted_readiness_text(report: &HostedReadinessReport) -> String {
    format!(
        r"conU hosted relay readiness

status: {}
warnings: {}
checked surfaces: {}
bind addr: {}
public bind: {}
public bind has credential manifest: {}
account: {}
node: {}
credentials file: {}
credentials active: {}
admin tokens file: {}
admin tokens active: {}
tenants file: {}
tenant active nodes: {}
session state dir: {}
session invalid records: {}
mailbox dir: {}
retention policy file: {}
mailbox node: {}
mailbox ttl seconds: {}
mailbox invalid records: {}
accounting dir: {}
accounting records: {}
abuse dir: {}
abuse records: {}
thresholds file: {}
abuse threshold checks: {}
abuse threshold exceeded: {}
display guards clean: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        report.status(),
        report.warning_count(),
        report.checked_surfaces(),
        report.bind_addr,
        yes_no(report.public_bind),
        yes_no(report.public_bind_has_credentials()),
        report.account_id.as_deref().unwrap_or("all"),
        report.node_id.as_deref().unwrap_or("all"),
        optional_path_text(report.credentials_file.as_deref()),
        report
            .credentials
            .as_ref()
            .map(|audit| audit.active)
            .unwrap_or(0),
        optional_path_text(report.admin_tokens_file.as_deref()),
        report
            .admin_tokens
            .as_ref()
            .map(|audit| audit.active)
            .unwrap_or(0),
        optional_path_text(report.tenants_file.as_deref()),
        report
            .tenants
            .as_ref()
            .map(|audit| audit.active_nodes)
            .unwrap_or(0),
        optional_path_text(report.session_state_dir.as_deref()),
        report
            .session_state
            .as_ref()
            .map(|audit| audit.invalid_records)
            .unwrap_or(0),
        optional_path_text(report.mailbox_dir.as_deref()),
        optional_path_text(report.retention_policy_file.as_deref()),
        report
            .mailbox
            .as_ref()
            .and_then(|audit| audit.node_id.as_deref())
            .unwrap_or("all"),
        optional_u64_text(report.mailbox_ttl.map(|ttl| ttl.as_secs())),
        report
            .mailbox
            .as_ref()
            .map(|audit| audit.invalid_records)
            .unwrap_or(0),
        optional_path_text(report.accounting_dir.as_deref()),
        report
            .accounting
            .as_ref()
            .map(|audit| audit.records)
            .unwrap_or(0),
        optional_path_text(report.abuse_dir.as_deref()),
        report
            .abuse
            .as_ref()
            .map(|audit| audit.records)
            .unwrap_or(0),
        optional_path_text(report.thresholds_file.as_deref()),
        report
            .abuse_threshold_report
            .as_ref()
            .map(|threshold_report| threshold_report.threshold_checks)
            .unwrap_or(0),
        report
            .abuse_threshold_report
            .as_ref()
            .map(|threshold_report| threshold_report.threshold_exceeded)
            .unwrap_or(0),
        yes_no(report.display_guards_clean()),
        yes_no(readiness_payload_displayed(report)),
        yes_no(readiness_token_displayed(report)),
        yes_no(readiness_token_hash_displayed(report)),
        yes_no(readiness_key_material_displayed(report)),
        yes_no(readiness_session_id_displayed(report)),
        yes_no(readiness_ciphertext_displayed(report)),
        yes_no(readiness_contents_displayed(report))
    )
}

fn render_hosted_readiness_json(report: &HostedReadinessReport) -> String {
    format!(
        r#"{{
  "status": "{}",
  "warningCount": {},
  "checkedSurfaces": {},
  "bindAddr": "{}",
  "publicBind": {},
  "accountId": {},
  "nodeId": {},
  "sources": {{
    "credentialsFile": {},
    "tenantsFile": {},
    "adminTokensFile": {},
    "sessionStateDir": {},
    "mailboxDir": {},
    "retentionPolicyFile": {},
    "accountingDir": {},
    "abuseDir": {},
    "thresholdsFile": {}
  }},
  "checks": {{
    "publicBindHasCredentialManifest": {},
    "credentialsConfigured": {},
    "adminTokensConfigured": {},
    "tenantRegistryConfigured": {},
    "sessionStateConfigured": {},
    "mailboxConfigured": {},
    "accountingConfigured": {},
    "abuseConfigured": {},
    "abuseThresholdsConfigured": {},
    "abuseThresholdsExceeded": {},
    "displayGuardsClean": {}
  }},
  "credentials": {},
  "adminTokens": {},
  "tenants": {},
  "sessionState": {},
  "mailbox": {},
  "accounting": {},
  "abuse": {},
  "abuseThresholds": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        report.status(),
        report.warning_count(),
        report.checked_surfaces(),
        json_escape(&report.bind_addr),
        bool_json(report.public_bind),
        optional_string_json(report.account_id.as_deref()),
        optional_string_json(report.node_id.as_deref()),
        optional_path_json(report.credentials_file.as_deref()),
        optional_path_json(report.tenants_file.as_deref()),
        optional_path_json(report.admin_tokens_file.as_deref()),
        optional_path_json(report.session_state_dir.as_deref()),
        optional_path_json(report.mailbox_dir.as_deref()),
        optional_path_json(report.retention_policy_file.as_deref()),
        optional_path_json(report.accounting_dir.as_deref()),
        optional_path_json(report.abuse_dir.as_deref()),
        optional_path_json(report.thresholds_file.as_deref()),
        bool_json(report.public_bind_has_credentials()),
        bool_json(report.credentials.is_some()),
        bool_json(report.admin_tokens.is_some()),
        bool_json(report.tenants.is_some()),
        bool_json(report.session_state.is_some()),
        bool_json(report.mailbox.is_some()),
        bool_json(report.accounting.is_some()),
        bool_json(report.abuse.is_some()),
        bool_json(report.abuse_threshold_report.is_some()),
        bool_json(
            report
                .abuse_threshold_report
                .as_ref()
                .is_some_and(|threshold_report| threshold_report.threshold_exceeded > 0)
        ),
        bool_json(report.display_guards_clean()),
        render_dashboard_credentials_json(report.credentials.as_ref()),
        render_readiness_admin_tokens_json(report.admin_tokens.as_ref()),
        render_dashboard_tenants_json(report.tenants.as_ref()),
        render_readiness_session_state_json(report.session_state.as_ref()),
        render_readiness_mailbox_json(report.mailbox.as_ref()),
        render_dashboard_accounting_json(report.accounting.as_ref()),
        render_dashboard_abuse_json(report.abuse.as_ref()),
        render_readiness_abuse_thresholds_json(report.abuse_threshold_report.as_ref()),
        bool_json(readiness_payload_displayed(report)),
        bool_json(readiness_token_displayed(report)),
        bool_json(readiness_token_hash_displayed(report)),
        bool_json(readiness_key_material_displayed(report)),
        bool_json(readiness_session_id_displayed(report)),
        bool_json(readiness_ciphertext_displayed(report)),
        bool_json(readiness_contents_displayed(report))
    )
}

fn render_readiness_admin_tokens_json(audit: Option<&HostedAdminTokenAudit>) -> String {
    match audit {
        Some(audit) => format!(
            r#"{{
    "configured": true,
    "records": {},
    "active": {},
    "revoked": {},
    "expired": {},
    "accountScopedRecords": {},
    "globalRecords": {},
    "accounts": {},
    "expiringRecords": {},
    "nextExpiresAtUnix": {},
    "lastExpiresAtUnix": {},
    "scopeCredentials": {},
    "scopeTenants": {},
    "scopeDashboard": {},
    "scopeSessions": {},
    "scopeMailboxAudit": {},
    "scopeMailboxPurge": {},
    "payloadDisplayed": {},
    "tokenDisplayed": {},
    "tokenHashDisplayed": {},
    "keyMaterialDisplayed": {},
    "sessionIdDisplayed": {},
    "ciphertextDisplayed": {},
    "contentsDisplayed": {}
  }}"#,
            audit.records,
            audit.active,
            audit.revoked,
            audit.expired,
            audit.account_scoped_records,
            audit.global_records,
            audit.accounts,
            audit.expiring_records,
            optional_u64_json(audit.next_expires_at_unix),
            optional_u64_json(audit.last_expires_at_unix),
            audit.scope_credentials,
            audit.scope_tenants,
            audit.scope_dashboard,
            audit.scope_sessions,
            audit.scope_mailbox_audit,
            audit.scope_mailbox_purge,
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

fn render_readiness_session_state_json(audit: Option<&RelaySessionAudit>) -> String {
    match audit {
        Some(audit) => format!(
            r#"{{
    "configured": true,
    "records": {},
    "activeRecords": {},
    "expiredRecords": {},
    "invalidRecords": {},
    "oldestCreatedUnixMillis": {},
    "newestLastSeenUnixMillis": {},
    "nextExpiresUnixMillis": {},
    "payloadDisplayed": {},
    "tokenDisplayed": {},
    "tokenHashDisplayed": {},
    "keyMaterialDisplayed": {},
    "sessionIdDisplayed": {},
    "ciphertextDisplayed": {},
    "contentsDisplayed": {}
  }}"#,
            audit.records,
            audit.active_records,
            audit.expired_records,
            audit.invalid_records,
            optional_u64_json(audit.oldest_created_unix_millis),
            optional_u64_json(audit.newest_last_seen_unix_millis),
            optional_u64_json(audit.next_expires_unix_millis),
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

fn render_readiness_mailbox_json(audit: Option<&RelayMailboxAudit>) -> String {
    match audit {
        Some(audit) => format!(
            r#"{{
    "configured": true,
    "nodeId": {},
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
        ),
        None => "null".to_string(),
    }
}

fn render_readiness_abuse_thresholds_json(report: Option<&AbuseThresholdReport>) -> String {
    match report {
        Some(report) => format!(
            r#"{{
    "configured": true,
    "source": "{}",
    "thresholdChecks": {},
    "thresholdExceeded": {},
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
            report.source,
            report.threshold_checks,
            report.threshold_exceeded,
            report.records,
            optional_u64_json(report.window_started_unix),
            report.admin_unauthorized,
            report.admin_failed,
            report.unauthorized_sessions,
            report.credential_denied_sessions,
            report.tenant_denied_sessions,
            report.rate_limited_sessions,
            report.session_expired,
            report.quota_denied_forwards,
            report.undelivered_forwards,
            report.mailbox_rejected_forwards,
            report.malformed_client_frames,
            bool_json(report.payload_displayed),
            bool_json(report.token_displayed),
            bool_json(report.token_hash_displayed),
            bool_json(report.key_material_displayed),
            bool_json(report.session_id_displayed),
            bool_json(report.ciphertext_displayed),
            bool_json(report.contents_displayed)
        ),
        None => "null".to_string(),
    }
}

fn readiness_payload_displayed(report: &HostedReadinessReport) -> bool {
    report
        .admin_tokens
        .as_ref()
        .is_some_and(|audit| audit.payload_displayed)
        || report
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
        || report
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
        || report
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
        || report
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
        || report
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
}

fn readiness_token_displayed(report: &HostedReadinessReport) -> bool {
    report
        .credentials
        .as_ref()
        .is_some_and(|audit| audit.token_displayed)
        || report
            .tenants
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || report
            .admin_tokens
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || report
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || report
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || report
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || report
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || report
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
}

fn readiness_token_hash_displayed(report: &HostedReadinessReport) -> bool {
    report
        .admin_tokens
        .as_ref()
        .is_some_and(|audit| audit.token_hash_displayed)
        || report
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
        || report
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
        || report
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
        || report
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
        || report
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
}

fn readiness_key_material_displayed(report: &HostedReadinessReport) -> bool {
    report
        .tenants
        .as_ref()
        .is_some_and(|audit| audit.key_material_displayed)
        || report
            .admin_tokens
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || report
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || report
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || report
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || report
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || report
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
}

fn readiness_session_id_displayed(report: &HostedReadinessReport) -> bool {
    report
        .admin_tokens
        .as_ref()
        .is_some_and(|audit| audit.session_id_displayed)
        || report
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
        || report
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
        || report
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
        || report
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
        || report
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
}

fn readiness_ciphertext_displayed(report: &HostedReadinessReport) -> bool {
    report
        .admin_tokens
        .as_ref()
        .is_some_and(|audit| audit.ciphertext_displayed)
        || report
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
        || report
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
        || report
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
        || report
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
        || report
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
}

fn readiness_contents_displayed(report: &HostedReadinessReport) -> bool {
    report
        .credentials
        .as_ref()
        .is_some_and(|audit| audit.contents_displayed)
        || report
            .tenants
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || report
            .admin_tokens
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || report
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || report
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || report
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || report
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || report
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
}

fn hash_token_from_stdin() -> Result<(), String> {
    let token = read_relay_token_from_reader(io::stdin())?;
    let hash = relay_token_sha256_hex(&token).map_err(|error| error.to_string())?;

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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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

fn admin_session_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_session_audit_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::session_audit(admin_token, parsed.node_id.clone())
        .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "audited" {
        return Err(format!(
            "relay admin session audit did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!(
            "{}",
            render_admin_session_audit_json(&result, &parsed.relay)
        );
    } else {
        println!(
            "{}",
            render_admin_session_audit_text(&result, &parsed.relay)
        );
    }
    Ok(())
}

#[derive(Debug)]
struct AdminSessionAuditArgs {
    node_id: Option<String>,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_session_audit_args(args: Vec<String>) -> Result<AdminSessionAuditArgs, String> {
    let mut node_id = None::<String>;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_session_audit_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_session_audit_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_session_audit_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(admin_session_audit_usage()),
        }
        index += 1;
    }

    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_session_audit_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminSessionAuditArgs {
        node_id,
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_session_audit_usage() -> String {
    "usage: conu-relay --admin-session-audit --relay <ws://host:port/path> --admin-token-stdin [--node <node-id>] [--json]".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbuseThresholdReportExit {
    Success,
    ThresholdExceeded,
}

impl AbuseThresholdReportExit {
    fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::ThresholdExceeded => ExitCode::from(3),
        }
    }
}

fn abuse_threshold_report_exit(
    report: &AbuseThresholdReport,
    fail_on_threshold: bool,
) -> AbuseThresholdReportExit {
    if fail_on_threshold && report.threshold_exceeded > 0 {
        AbuseThresholdReportExit::ThresholdExceeded
    } else {
        AbuseThresholdReportExit::Success
    }
}

fn admin_abuse_threshold_report_from_args(
    args: Vec<String>,
) -> Result<AbuseThresholdReportExit, String> {
    let parsed = parse_admin_abuse_threshold_report_args(args)?;
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
            "relay admin abuse threshold report did not complete: status={}",
            result.status
        ));
    }

    let report =
        abuse_threshold_report_from_admin_result(&result, parsed.thresholds, parsed.relay.clone());
    if parsed.json {
        println!("{}", render_abuse_threshold_report_json(&report));
    } else {
        println!("{}", render_abuse_threshold_report_text(&report));
    }
    Ok(abuse_threshold_report_exit(
        &report,
        parsed.fail_on_threshold,
    ))
}

#[derive(Debug)]
struct AdminAbuseThresholdReportArgs {
    account_id: Option<String>,
    node_id: Option<String>,
    relay: String,
    admin_token_stdin: bool,
    #[cfg(test)]
    thresholds_file: Option<PathBuf>,
    thresholds: AbuseThresholds,
    json: bool,
    fail_on_threshold: bool,
}

fn parse_admin_abuse_threshold_report_args(
    args: Vec<String>,
) -> Result<AdminAbuseThresholdReportArgs, String> {
    let mut account_id = None::<String>;
    let mut node_id = None::<String>;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut thresholds_file = None::<PathBuf>;
    let mut cli_thresholds = AbuseThresholds::default();
    let mut json = false;
    let mut fail_on_threshold = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_abuse_threshold_report_usage());
                };
                account_id = Some(validate_dashboard_filter_id(
                    value.to_string(),
                    "account id",
                )?);
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_abuse_threshold_report_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_abuse_threshold_report_usage());
                };
                relay = Some(value.to_string());
            }
            "--thresholds-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_abuse_threshold_report_usage());
                };
                if value.trim().is_empty() {
                    return Err(admin_abuse_threshold_report_usage());
                }
                thresholds_file = Some(PathBuf::from(value));
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--fail-on-threshold" => fail_on_threshold = true,
            "--help" | "-h" => return Err(admin_abuse_threshold_report_usage()),
            value if value.starts_with("--max-") => {
                index += 1;
                let Some(limit) = args.get(index) else {
                    return Err(admin_abuse_threshold_report_usage());
                };
                parse_abuse_threshold_option(&mut cli_thresholds, value, limit)?;
            }
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(admin_abuse_threshold_report_usage()),
        }
        index += 1;
    }

    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_abuse_threshold_report_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    let thresholds = merged_abuse_thresholds(thresholds_file.as_deref(), cli_thresholds)?;
    if !thresholds.has_any() {
        return Err(admin_abuse_threshold_report_usage());
    }

    Ok(AdminAbuseThresholdReportArgs {
        account_id,
        node_id,
        relay,
        admin_token_stdin,
        #[cfg(test)]
        thresholds_file,
        thresholds,
        json,
        fail_on_threshold,
    })
}

fn admin_abuse_threshold_report_usage() -> String {
    "usage: conu-relay --admin-abuse-threshold-report --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--node <node-id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold]".to_string()
}

fn admin_tenant_upsert_from_args(args: Vec<String>) -> Result<(), String> {
    admin_tenant_account_from_args(args, AdminTenantAccountMode::Upsert)
}

fn admin_tenant_revoke_from_args(args: Vec<String>) -> Result<(), String> {
    admin_tenant_account_from_args(args, AdminTenantAccountMode::Revoke)
}

fn admin_tenant_account_from_args(
    args: Vec<String>,
    mode: AdminTenantAccountMode,
) -> Result<(), String> {
    let parsed = parse_admin_tenant_account_args(args, mode)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = match mode {
        AdminTenantAccountMode::Upsert => {
            RelayAdminRequest::tenant_upsert(admin_token, parsed.account_id.clone())
        }
        AdminTenantAccountMode::Revoke => {
            RelayAdminRequest::tenant_revoke(admin_token, parsed.account_id.clone())
        }
    }
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != mode.success_status() {
        return Err(format!(
            "relay admin tenant {} did not complete: status={}",
            mode.verb(),
            result.status
        ));
    }

    if parsed.json {
        println!("{}", render_admin_tenant_json(&result, &parsed.relay));
    } else {
        println!("{}", render_admin_tenant_text(&result, &parsed.relay));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AdminTenantAccountMode {
    Upsert,
    Revoke,
}

impl AdminTenantAccountMode {
    fn usage(self) -> String {
        match self {
            Self::Upsert => "usage: conu-relay --admin-tenant-upsert <account-id> --relay <ws://host:port/path> --admin-token-stdin [--json]".to_string(),
            Self::Revoke => "usage: conu-relay --admin-tenant-revoke <account-id> --relay <ws://host:port/path> --admin-token-stdin [--json]".to_string(),
        }
    }

    fn success_status(self) -> &'static str {
        match self {
            Self::Upsert => "upserted",
            Self::Revoke => "revoked",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Debug)]
struct AdminTenantAccountArgs {
    account_id: String,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_tenant_account_args(
    args: Vec<String>,
    mode: AdminTenantAccountMode,
) -> Result<AdminTenantAccountArgs, String> {
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
                    return Err(mode.usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(mode.usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(mode.usage());
    }
    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(mode.usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminTenantAccountArgs {
        account_id: positional.remove(0),
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_tenant_node_upsert_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_tenant_node_upsert_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::tenant_node_upsert(
        admin_token,
        parsed.account_id.clone(),
        parsed.node_id.clone(),
        parsed.permissions.messages,
        parsed.permissions.streams,
        parsed.permissions.rooms,
        parsed.permissions.files,
        parsed.permissions.mailbox,
        parsed.signing_key_id.clone(),
        parsed.exchange_key_id.clone(),
    )
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "upserted" {
        return Err(format!(
            "relay admin tenant node upsert did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!("{}", render_admin_tenant_json(&result, &parsed.relay));
    } else {
        println!("{}", render_admin_tenant_text(&result, &parsed.relay));
    }
    Ok(())
}

#[derive(Debug)]
struct AdminTenantNodeUpsertArgs {
    account_id: String,
    node_id: String,
    relay: String,
    admin_token_stdin: bool,
    permissions: HostedTenantPermissions,
    signing_key_id: Option<String>,
    exchange_key_id: Option<String>,
    json: bool,
}

fn parse_admin_tenant_node_upsert_args(
    args: Vec<String>,
) -> Result<AdminTenantNodeUpsertArgs, String> {
    let mut positional = Vec::new();
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut permissions = HostedTenantPermissions::default();
    let mut signing_key_id = None::<String>;
    let mut exchange_key_id = None::<String>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--messages" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                permissions.messages = parse_cli_bool(value, "--messages")?;
            }
            "--streams" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                permissions.streams = parse_cli_bool(value, "--streams")?;
            }
            "--rooms" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                permissions.rooms = parse_cli_bool(value, "--rooms")?;
            }
            "--files" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                permissions.files = parse_cli_bool(value, "--files")?;
            }
            "--mailbox" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                permissions.mailbox = parse_cli_bool(value, "--mailbox")?;
            }
            "--signing-key-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                signing_key_id = Some(value.to_string());
            }
            "--exchange-key-id" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_node_upsert_usage());
                };
                exchange_key_id = Some(value.to_string());
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_tenant_node_upsert_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(admin_tenant_node_upsert_usage());
    }
    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_tenant_node_upsert_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminTenantNodeUpsertArgs {
        account_id: positional.remove(0),
        node_id: positional.remove(0),
        relay,
        admin_token_stdin,
        permissions,
        signing_key_id,
        exchange_key_id,
        json,
    })
}

fn admin_tenant_node_upsert_usage() -> String {
    "usage: conu-relay --admin-tenant-node-upsert <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] [--signing-key-id <id>] [--exchange-key-id <id>] [--json]".to_string()
}

fn admin_tenant_node_revoke_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_tenant_node_revoke_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::tenant_node_revoke(
        admin_token,
        parsed.account_id.clone(),
        parsed.node_id.clone(),
    )
    .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "revoked" {
        return Err(format!(
            "relay admin tenant node revoke did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!("{}", render_admin_tenant_json(&result, &parsed.relay));
    } else {
        println!("{}", render_admin_tenant_text(&result, &parsed.relay));
    }
    Ok(())
}

struct AdminTenantNodeRevokeArgs {
    account_id: String,
    node_id: String,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_tenant_node_revoke_args(
    args: Vec<String>,
) -> Result<AdminTenantNodeRevokeArgs, String> {
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
                    return Err(admin_tenant_node_revoke_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_tenant_node_revoke_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(admin_tenant_node_revoke_usage());
    }
    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_tenant_node_revoke_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminTenantNodeRevokeArgs {
        account_id: positional.remove(0),
        node_id: positional.remove(0),
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_tenant_node_revoke_usage() -> String {
    "usage: conu-relay --admin-tenant-node-revoke <account-id> <node-id> --relay <ws://host:port/path> --admin-token-stdin [--json]".to_string()
}

fn admin_tenant_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_tenant_audit_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::tenant_audit(admin_token, parsed.account_id.clone())
        .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "audited" {
        return Err(format!(
            "relay admin tenant audit did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!("{}", render_admin_tenant_json(&result, &parsed.relay));
    } else {
        println!("{}", render_admin_tenant_text(&result, &parsed.relay));
    }
    Ok(())
}

struct AdminTenantAuditArgs {
    account_id: Option<String>,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_tenant_audit_args(args: Vec<String>) -> Result<AdminTenantAuditArgs, String> {
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
                    return Err(admin_tenant_audit_usage());
                };
                account_id = Some(value.to_string());
            }
            "--relay" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_tenant_audit_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_tenant_audit_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(admin_tenant_audit_usage()),
        }
        index += 1;
    }

    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_tenant_audit_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminTenantAuditArgs {
        account_id,
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_tenant_audit_usage() -> String {
    "usage: conu-relay --admin-tenant-audit --relay <ws://host:port/path> --admin-token-stdin [--account <account-id>] [--json]".to_string()
}

fn admin_hosted_account_suspend_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_admin_account_suspend_args(args)?;
    let admin_token = read_admin_token_from_stdin(parsed.admin_token_stdin)?;
    let request = RelayAdminRequest::account_suspend(admin_token, parsed.account_id.clone())
        .map_err(|error| error.to_string())?;
    let result = send_admin_request(&parsed.relay, request)?;
    if result.status != "suspended" {
        return Err(format!(
            "relay admin hosted account suspend did not complete: status={}",
            result.status
        ));
    }

    if parsed.json {
        println!(
            "{}",
            render_admin_account_suspend_json(&result, &parsed.relay)
        );
    } else {
        println!(
            "{}",
            render_admin_account_suspend_text(&result, &parsed.relay)
        );
    }
    Ok(())
}

#[derive(Debug)]
struct AdminAccountSuspendArgs {
    account_id: String,
    relay: String,
    admin_token_stdin: bool,
    json: bool,
}

fn parse_admin_account_suspend_args(args: Vec<String>) -> Result<AdminAccountSuspendArgs, String> {
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
                    return Err(admin_account_suspend_usage());
                };
                relay = Some(value.to_string());
            }
            "--admin-token-stdin" => admin_token_stdin = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(admin_account_suspend_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(admin_account_suspend_usage());
    }
    let Some(relay) = relay.filter(|value| !value.trim().is_empty()) else {
        return Err(admin_account_suspend_usage());
    };
    if !admin_token_stdin {
        return Err("--admin-token-stdin is required".to_string());
    }

    Ok(AdminAccountSuspendArgs {
        account_id: positional.remove(0),
        relay,
        admin_token_stdin,
        json,
    })
}

fn admin_account_suspend_usage() -> String {
    "usage: conu-relay --admin-hosted-account-suspend <account-id> --relay <ws://host:port/path> --admin-token-stdin [--json]".to_string()
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
    #[cfg(test)]
    retention_policy_file: Option<PathBuf>,
    json: bool,
}

fn parse_admin_mailbox_audit_args(args: Vec<String>) -> Result<AdminMailboxAuditArgs, String> {
    let mut node_id = None::<String>;
    let mut ttl = None::<Duration>;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut retention_policy_file = None::<PathBuf>;
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
            "--retention-policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_audit_usage());
                };
                if value.trim().is_empty() {
                    return Err(admin_mailbox_audit_usage());
                }
                retention_policy_file = Some(PathBuf::from(value));
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
    let retention =
        merged_mailbox_retention_policy(retention_policy_file.as_deref(), node_id, ttl)?;

    Ok(AdminMailboxAuditArgs {
        node_id: retention.node_id,
        ttl: retention.ttl,
        relay,
        admin_token_stdin,
        #[cfg(test)]
        retention_policy_file,
        json,
    })
}

fn admin_mailbox_audit_usage() -> String {
    "usage: conu-relay --admin-mailbox-audit --relay <ws://host:port/path> --admin-token-stdin [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]".to_string()
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
    #[cfg(test)]
    retention_policy_file: Option<PathBuf>,
    json: bool,
}

fn parse_admin_mailbox_purge_args(args: Vec<String>) -> Result<AdminMailboxPurgeArgs, String> {
    let mut node_id = None::<String>;
    let mut ttl = None::<Duration>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut relay = None::<String>;
    let mut admin_token_stdin = false;
    let mut retention_policy_file = None::<PathBuf>;
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
            "--retention-policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(admin_mailbox_purge_usage());
                };
                if value.trim().is_empty() {
                    return Err(admin_mailbox_purge_usage());
                }
                retention_policy_file = Some(PathBuf::from(value));
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
    let retention =
        merged_mailbox_retention_policy(retention_policy_file.as_deref(), node_id, ttl)?;
    let Some(ttl) = retention.ttl else {
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
        node_id: retention.node_id,
        ttl,
        dry_run,
        relay,
        admin_token_stdin,
        #[cfg(test)]
        retention_policy_file,
        json,
    })
}

fn admin_mailbox_purge_usage() -> String {
    "usage: conu-relay --admin-mailbox-purge --relay <ws://host:port/path> --admin-token-stdin [--ttl-seconds <seconds>] [--node <node-id>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]".to_string()
}

fn read_admin_token_from_stdin(required: bool) -> Result<String, String> {
    read_admin_token_from_reader(required, io::stdin())
}

fn read_admin_token_from_reader<R: Read>(required: bool, reader: R) -> Result<String, String> {
    if !required {
        return Err("--admin-token-stdin is required".to_string());
    }
    let token = read_bounded_stdin_token(reader, "relay admin token")?;
    if token.is_empty() {
        return Err("relay admin token cannot be empty".to_string());
    }
    Ok(token)
}

fn read_relay_token_from_reader<R: Read>(reader: R) -> Result<String, String> {
    read_bounded_stdin_token(reader, "relay token")
}

fn read_bounded_stdin_token<R: Read>(mut reader: R, label: &'static str) -> Result<String, String> {
    let mut token = String::new();
    let limit = MAX_RELAY_STDIN_TOKEN_BYTES.saturating_add(1);
    Read::by_ref(&mut reader)
        .take(limit)
        .read_to_string(&mut token)
        .map_err(|error| format!("read {label} from stdin: {error}"))?;
    if token.len() as u64 > MAX_RELAY_STDIN_TOKEN_BYTES {
        return Err(format!(
            "read {label} from stdin: input exceeds {MAX_RELAY_STDIN_TOKEN_BYTES} bytes"
        ));
    }
    Ok(token.trim().to_string())
}

fn ensure_token_out_available(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err("token output file already exists".to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect issued relay token file: {error}")),
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_token_out_directory(parent)?;
    }
    Ok(())
}

fn ensure_token_out_directory(path: &Path) -> Result<(), String> {
    if token_out_directory_exists(path)? {
        return Ok(());
    }
    fs::create_dir_all(path)
        .map_err(|error| format!("create issued relay token directory: {error}"))?;
    if token_out_directory_exists(path)? {
        return Ok(());
    }
    Err("inspect issued relay token directory: directory was not created".to_string())
}

fn token_out_directory_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !metadata.is_dir() {
                return Err(
                    "create issued relay token directory: path is not a directory".to_string(),
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect issued relay token directory: {error}")),
    }
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

fn render_admin_tenant_text(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r"conU hosted relay tenant admin {}

action: {}
account: {}
node: {}
relay: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
hosted policies: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        result.status,
        result.action.as_str(),
        result.account_id.as_deref().unwrap_or("all"),
        result.node_id.as_deref().unwrap_or("none"),
        relay,
        result.tenants,
        result.active_tenants,
        result.revoked_tenants,
        result.nodes,
        result.active_nodes,
        result.revoked_nodes,
        result.tenant_policies,
        yes_no(result.payload_displayed),
        yes_no(result.token_displayed),
        yes_no(result.token_hash_displayed),
        yes_no(result.key_material_displayed),
        yes_no(result.session_id_displayed),
        yes_no(result.ciphertext_displayed),
        yes_no(result.contents_displayed)
    )
}

fn render_admin_tenant_json(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "accountId": {},
  "nodeId": {},
  "relay": "{}",
  "tenants": {},
  "activeTenants": {},
  "revokedTenants": {},
  "nodes": {},
  "activeNodes": {},
  "revokedNodes": {},
  "policies": {},
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
        result.tenants,
        result.active_tenants,
        result.revoked_tenants,
        result.nodes,
        result.active_nodes,
        result.revoked_nodes,
        result.tenant_policies,
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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

fn hosted_account_suspend_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_hosted_account_suspend_args(args)?;
    let suspension = suspend_hosted_account_in_files(
        &parsed.credentials_file,
        &parsed.tenants_file,
        parsed.account_id,
    )
    .map_err(|error| error.to_string())?;
    if parsed.json {
        println!("{}", render_hosted_account_suspend_json(&suspension));
    } else {
        println!("{}", render_hosted_account_suspend_text(&suspension));
    }
    Ok(())
}

#[derive(Debug)]
struct HostedAccountSuspendArgs {
    account_id: String,
    credentials_file: PathBuf,
    tenants_file: PathBuf,
    json: bool,
}

fn parse_hosted_account_suspend_args(
    args: Vec<String>,
) -> Result<HostedAccountSuspendArgs, String> {
    let mut positional = Vec::new();
    let mut credentials_file = None::<PathBuf>;
    let mut tenants_file = None::<PathBuf>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--credentials-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_account_suspend_usage());
                };
                credentials_file = Some(PathBuf::from(value));
            }
            "--tenants-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_account_suspend_usage());
                };
                tenants_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(hosted_account_suspend_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(hosted_account_suspend_usage());
    }
    let Some(credentials_file) = credentials_file.filter(|path| !path.as_os_str().is_empty())
    else {
        return Err(hosted_account_suspend_usage());
    };
    let Some(tenants_file) = tenants_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(hosted_account_suspend_usage());
    };

    Ok(HostedAccountSuspendArgs {
        account_id: positional.remove(0),
        credentials_file,
        tenants_file,
        json,
    })
}

fn hosted_account_suspend_usage() -> String {
    "usage: conu-relay --hosted-account-suspend <account-id> --credentials-file <path> --tenants-file <path> [--json]".to_string()
}

#[derive(Debug, Clone)]
struct HostedFleetAccountAuditArgs {
    account_id: String,
    node_id: Option<String>,
    fleet_file: PathBuf,
    json: bool,
    fail_on_warning: bool,
}

#[derive(Debug, Clone)]
struct HostedFleetAccountAuditRelayReport {
    name: String,
    credentials_file: Option<PathBuf>,
    tenants_file: Option<PathBuf>,
    credentials: usize,
    active: usize,
    revoked: usize,
    expired: usize,
    accounts: usize,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    warnings: Vec<&'static str>,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetAccountAuditTotals {
    relays: usize,
    account_sources: usize,
    credential_sources: usize,
    tenant_sources: usize,
    credentials: usize,
    active: usize,
    revoked: usize,
    expired: usize,
    accounts: usize,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    warnings: usize,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetAccountAuditTotals {
    fn add(&mut self, relay: &HostedFleetAccountAuditRelayReport) {
        self.account_sources += 1;
        if relay.credentials_file.is_some() {
            self.credential_sources += 1;
        }
        if relay.tenants_file.is_some() {
            self.tenant_sources += 1;
        }
        self.credentials += relay.credentials;
        self.active += relay.active;
        self.revoked += relay.revoked;
        self.expired += relay.expired;
        self.accounts += relay.accounts;
        self.tenants += relay.tenants;
        self.active_tenants += relay.active_tenants;
        self.revoked_tenants += relay.revoked_tenants;
        self.nodes += relay.nodes;
        self.active_nodes += relay.active_nodes;
        self.revoked_nodes += relay.revoked_nodes;
        self.tenant_policies += relay.tenant_policies;
        self.warnings += relay.warnings.len();
        self.token_displayed |= relay.token_displayed;
        self.key_material_displayed |= relay.key_material_displayed;
        self.contents_displayed |= relay.contents_displayed;
    }
}

#[derive(Debug, Clone)]
struct HostedFleetAccountAuditReport {
    account_id: String,
    node_id: Option<String>,
    fleet_file: PathBuf,
    relays: Vec<HostedFleetAccountAuditRelayReport>,
    totals: HostedFleetAccountAuditTotals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostedFleetAccountAuditExit {
    Success,
    Warning,
}

impl HostedFleetAccountAuditExit {
    fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::Warning => ExitCode::from(3),
        }
    }
}

fn hosted_fleet_account_audit_from_args(
    args: Vec<String>,
) -> Result<HostedFleetAccountAuditExit, String> {
    let parsed = parse_hosted_fleet_account_audit_args(args)?;
    let report = hosted_fleet_account_audit_report(&parsed)?;
    if parsed.json {
        println!("{}", render_hosted_fleet_account_audit_json(&report));
    } else {
        println!("{}", render_hosted_fleet_account_audit_text(&report));
    }
    Ok(hosted_fleet_account_audit_exit(
        &report,
        parsed.fail_on_warning,
    ))
}

fn parse_hosted_fleet_account_audit_args(
    args: Vec<String>,
) -> Result<HostedFleetAccountAuditArgs, String> {
    let mut positional = Vec::new();
    let mut fleet_file = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut json = false;
    let mut fail_on_warning = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_account_audit_usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_account_audit_usage());
                };
                node_id = Some(value.to_string());
            }
            "--json" => json = true,
            "--fail-on-warning" => fail_on_warning = true,
            "--help" | "-h" => return Err(hosted_fleet_account_audit_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(hosted_fleet_account_audit_usage());
    }
    let account_id = validate_dashboard_filter_id(positional.remove(0), "account id")?;
    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(hosted_fleet_account_audit_usage());
    };
    let node_id = node_id
        .map(|value| validate_dashboard_filter_id(value, "node id"))
        .transpose()?;

    Ok(HostedFleetAccountAuditArgs {
        account_id,
        node_id,
        fleet_file,
        json,
        fail_on_warning,
    })
}

fn hosted_fleet_account_audit_usage() -> String {
    "usage: conu-relay --hosted-fleet-account-audit <account-id> --fleet-file <path> [--node <node-id>] [--json] [--fail-on-warning]".to_string()
}

fn hosted_fleet_account_audit_report(
    args: &HostedFleetAccountAuditArgs,
) -> Result<HostedFleetAccountAuditReport, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    let mut totals = HostedFleetAccountAuditTotals {
        relays: configs.len(),
        ..HostedFleetAccountAuditTotals::default()
    };
    let mut relays = Vec::<HostedFleetAccountAuditRelayReport>::new();

    for config in configs {
        if config.credentials_file.is_none() && config.tenants_file.is_none() {
            continue;
        }
        let relay =
            hosted_fleet_account_audit_relay(config, &args.account_id, args.node_id.as_deref())?;
        totals.add(&relay);
        relays.push(relay);
    }

    if relays.is_empty() {
        return Err(
            "--hosted-fleet-account-audit requires at least one fleet relay credentials_file or tenants_file".to_string(),
        );
    }

    Ok(HostedFleetAccountAuditReport {
        account_id: args.account_id.clone(),
        node_id: args.node_id.clone(),
        fleet_file: args.fleet_file.clone(),
        relays,
        totals,
    })
}

fn hosted_fleet_account_audit_relay(
    config: HostedFleetRelayConfig,
    account_id: &str,
    node_id: Option<&str>,
) -> Result<HostedFleetAccountAuditRelayReport, String> {
    let credentials = config
        .credentials_file
        .as_ref()
        .map(|path| audit_hosted_relay_credentials_file_with_node(path, Some(account_id), node_id))
        .transpose()
        .map_err(|error| error.to_string())?;
    let tenants = config
        .tenants_file
        .as_ref()
        .map(|path| audit_hosted_tenants_file_with_node(path, Some(account_id), node_id))
        .transpose()
        .map_err(|error| error.to_string())?;

    let mut warnings = Vec::<&'static str>::new();
    if credentials.is_none() {
        warnings.push("missing_credentials_source");
    }
    if tenants.is_none() {
        warnings.push("missing_tenants_source");
    }

    let credentials_count = credentials
        .as_ref()
        .map(|audit| audit.credentials)
        .unwrap_or(0);
    let active_credentials = credentials.as_ref().map(|audit| audit.active).unwrap_or(0);
    let tenants_count = tenants.as_ref().map(|audit| audit.tenants).unwrap_or(0);
    let active_tenants = tenants
        .as_ref()
        .map(|audit| audit.active_tenants)
        .unwrap_or(0);
    let revoked_tenants = tenants
        .as_ref()
        .map(|audit| audit.revoked_tenants)
        .unwrap_or(0);
    let active_nodes = tenants
        .as_ref()
        .map(|audit| audit.active_nodes)
        .unwrap_or(0);

    let nodes_count = tenants.as_ref().map(|audit| audit.nodes).unwrap_or(0);
    let revoked_nodes = tenants
        .as_ref()
        .map(|audit| audit.revoked_nodes)
        .unwrap_or(0);

    if node_id.is_some() {
        if credentials.is_some() && credentials_count == 0 {
            warnings.push("node_missing_credentials");
        }
        if tenants.is_some() && tenants_count == 0 {
            warnings.push("account_missing_tenant");
        }
        if tenants.is_some() && nodes_count == 0 {
            warnings.push("tenant_node_missing");
        }
    } else {
        if credentials.is_some() && credentials_count == 0 {
            warnings.push("account_missing_credentials");
        }
        if tenants.is_some() && tenants_count == 0 {
            warnings.push("account_missing_tenant");
        }
    }
    if credentials.is_some() && tenants.is_some() {
        if active_credentials > 0 && active_tenants == 0 {
            warnings.push("active_credentials_without_active_tenant");
        }
        if node_id.is_some() {
            if active_credentials > 0 && active_nodes == 0 {
                warnings.push("active_node_credentials_without_active_tenant_node");
            }
            if active_nodes > 0 && active_credentials == 0 {
                warnings.push("active_tenant_node_without_active_credentials");
            }
            if revoked_nodes > 0 && active_credentials > 0 {
                warnings.push("revoked_tenant_node_with_active_credentials");
            }
        } else {
            if active_credentials > 0 && active_nodes == 0 {
                warnings.push("active_credentials_without_active_tenant_node");
            }
            if active_tenants > 0 && active_credentials == 0 {
                warnings.push("active_tenant_without_active_credentials");
            }
            if active_tenants > 0 && active_nodes == 0 {
                warnings.push("active_tenant_without_active_node");
            }
            if active_nodes > 0 && active_tenants == 0 {
                warnings.push("active_nodes_without_active_tenant");
            }
        }
        if revoked_tenants > 0 && active_credentials > 0 {
            warnings.push("revoked_tenant_with_active_credentials");
        }
    }

    Ok(HostedFleetAccountAuditRelayReport {
        name: config.name,
        credentials_file: config.credentials_file,
        tenants_file: config.tenants_file,
        credentials: credentials_count,
        active: active_credentials,
        revoked: credentials.as_ref().map(|audit| audit.revoked).unwrap_or(0),
        expired: credentials.as_ref().map(|audit| audit.expired).unwrap_or(0),
        accounts: credentials
            .as_ref()
            .map(|audit| audit.accounts)
            .unwrap_or(0),
        tenants: tenants_count,
        active_tenants,
        revoked_tenants,
        nodes: nodes_count,
        active_nodes,
        revoked_nodes,
        tenant_policies: tenants.as_ref().map(|audit| audit.policies).unwrap_or(0),
        warnings,
        token_displayed: credentials
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
            || tenants.as_ref().is_some_and(|audit| audit.token_displayed),
        key_material_displayed: tenants
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed),
        contents_displayed: credentials
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
            || tenants
                .as_ref()
                .is_some_and(|audit| audit.contents_displayed),
    })
}

fn hosted_fleet_account_audit_exit(
    report: &HostedFleetAccountAuditReport,
    fail_on_warning: bool,
) -> HostedFleetAccountAuditExit {
    if fail_on_warning && report.totals.warnings > 0 {
        HostedFleetAccountAuditExit::Warning
    } else {
        HostedFleetAccountAuditExit::Success
    }
}

#[derive(Debug, Clone)]
struct HostedFleetAccountSuspendArgs {
    account_id: String,
    node_id: Option<String>,
    fleet_file: PathBuf,
    dry_run: bool,
    json: bool,
}

#[derive(Debug, Clone)]
struct HostedFleetAccountSuspensionSource {
    name: String,
    credentials_file: PathBuf,
    tenants_file: PathBuf,
}

#[derive(Debug, Clone)]
struct HostedFleetAccountSuspensionRelayReport {
    name: String,
    credentials_file: PathBuf,
    tenants_file: PathBuf,
    credentials: usize,
    active: usize,
    revoked: usize,
    expired: usize,
    accounts: usize,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetAccountSuspensionTotals {
    relays: usize,
    account_sources: usize,
    credentials: usize,
    active: usize,
    revoked: usize,
    expired: usize,
    accounts: usize,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetAccountSuspensionTotals {
    fn add(&mut self, relay: &HostedFleetAccountSuspensionRelayReport) {
        self.account_sources += 1;
        self.credentials += relay.credentials;
        self.active += relay.active;
        self.revoked += relay.revoked;
        self.expired += relay.expired;
        self.accounts += relay.accounts;
        self.tenants += relay.tenants;
        self.active_tenants += relay.active_tenants;
        self.revoked_tenants += relay.revoked_tenants;
        self.nodes += relay.nodes;
        self.active_nodes += relay.active_nodes;
        self.revoked_nodes += relay.revoked_nodes;
        self.tenant_policies += relay.tenant_policies;
        self.token_displayed |= relay.token_displayed;
        self.key_material_displayed |= relay.key_material_displayed;
        self.contents_displayed |= relay.contents_displayed;
    }
}

#[derive(Debug, Clone)]
struct HostedFleetAccountSuspensionReport {
    account_id: String,
    node_id: Option<String>,
    fleet_file: PathBuf,
    dry_run: bool,
    relays: Vec<HostedFleetAccountSuspensionRelayReport>,
    totals: HostedFleetAccountSuspensionTotals,
}

fn hosted_fleet_account_suspend_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_hosted_fleet_account_suspend_args(args)?;
    let report = hosted_fleet_account_suspension_report(&parsed)?;
    if parsed.json {
        println!("{}", render_hosted_fleet_account_suspend_json(&report));
    } else {
        println!("{}", render_hosted_fleet_account_suspend_text(&report));
    }
    Ok(())
}

fn parse_hosted_fleet_account_suspend_args(
    args: Vec<String>,
) -> Result<HostedFleetAccountSuspendArgs, String> {
    let mut positional = Vec::new();
    let mut fleet_file = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_account_suspend_usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_account_suspend_usage());
                };
                node_id = Some(value.to_string());
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(hosted_fleet_account_suspend_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(hosted_fleet_account_suspend_usage());
    }
    let account_id = validate_dashboard_filter_id(positional.remove(0), "account id")?;
    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(hosted_fleet_account_suspend_usage());
    };
    let node_id = node_id
        .map(|value| validate_dashboard_filter_id(value, "node id"))
        .transpose()?;
    match (dry_run, confirm) {
        (true, false) | (false, true) => {}
        _ => {
            return Err(
                "--hosted-fleet-account-suspend requires exactly one of --dry-run or --confirm"
                    .to_string(),
            );
        }
    }

    Ok(HostedFleetAccountSuspendArgs {
        account_id,
        node_id,
        fleet_file,
        dry_run,
        json,
    })
}

fn hosted_fleet_account_suspend_usage() -> String {
    "usage: conu-relay --hosted-fleet-account-suspend <account-id> --fleet-file <path> [--node <node-id>] (--dry-run|--confirm) [--json]".to_string()
}

fn hosted_fleet_account_suspension_report(
    args: &HostedFleetAccountSuspendArgs,
) -> Result<HostedFleetAccountSuspensionReport, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    let sources = hosted_fleet_account_suspension_sources(&configs)?;

    // Preflight every source before confirmed mode mutates any tenant or
    // credential manifest. This avoids avoidable partial fleet updates.
    for source in &sources {
        hosted_fleet_account_suspension_preflight(
            source,
            &args.account_id,
            args.node_id.as_deref(),
        )?;
    }

    let mut totals = HostedFleetAccountSuspensionTotals {
        relays: configs.len(),
        ..HostedFleetAccountSuspensionTotals::default()
    };
    let mut relays = Vec::<HostedFleetAccountSuspensionRelayReport>::new();

    for source in sources {
        let relay = if args.dry_run {
            hosted_fleet_account_suspension_preflight(
                &source,
                &args.account_id,
                args.node_id.as_deref(),
            )?
        } else {
            if let Some(node_id) = args.node_id.as_deref() {
                let suspension = suspend_hosted_account_node_in_files(
                    &source.credentials_file,
                    &source.tenants_file,
                    args.account_id.clone(),
                    node_id,
                )
                .map_err(|error| error.to_string())?;
                hosted_fleet_account_suspension_relay_from_node_suspension(source.name, suspension)
            } else {
                let suspension = suspend_hosted_account_in_files(
                    &source.credentials_file,
                    &source.tenants_file,
                    args.account_id.clone(),
                )
                .map_err(|error| error.to_string())?;
                hosted_fleet_account_suspension_relay_from_suspension(source.name, suspension)
            }
        };
        totals.add(&relay);
        relays.push(relay);
    }

    Ok(HostedFleetAccountSuspensionReport {
        account_id: args.account_id.clone(),
        node_id: args.node_id.clone(),
        fleet_file: args.fleet_file.clone(),
        dry_run: args.dry_run,
        relays,
        totals,
    })
}

fn hosted_fleet_account_suspension_sources(
    configs: &[HostedFleetRelayConfig],
) -> Result<Vec<HostedFleetAccountSuspensionSource>, String> {
    let mut sources = Vec::new();
    for config in configs {
        match (&config.credentials_file, &config.tenants_file) {
            (Some(credentials_file), Some(tenants_file)) => {
                sources.push(HostedFleetAccountSuspensionSource {
                    name: config.name.clone(),
                    credentials_file: credentials_file.clone(),
                    tenants_file: tenants_file.clone(),
                });
            }
            (Some(_), None) => {
                return Err(format!(
                    "--hosted-fleet-account-suspend relay {} requires tenants_file with credentials_file",
                    config.name
                ));
            }
            (None, Some(_)) => {
                return Err(format!(
                    "--hosted-fleet-account-suspend relay {} requires credentials_file with tenants_file",
                    config.name
                ));
            }
            (None, None) => {}
        }
    }
    if sources.is_empty() {
        return Err(
            "--hosted-fleet-account-suspend requires at least one fleet relay with credentials_file and tenants_file".to_string(),
        );
    }
    Ok(sources)
}

fn hosted_fleet_account_suspension_preflight(
    source: &HostedFleetAccountSuspensionSource,
    account_id: &str,
    node_id: Option<&str>,
) -> Result<HostedFleetAccountSuspensionRelayReport, String> {
    let credentials = audit_hosted_relay_credentials_file_with_node(
        &source.credentials_file,
        Some(account_id),
        node_id,
    )
    .map_err(|error| error.to_string())?;
    let tenants =
        audit_hosted_tenants_file_with_node(&source.tenants_file, Some(account_id), node_id)
            .map_err(|error| error.to_string())?;
    if tenants.tenants == 0 {
        return Err(format!(
            "--hosted-fleet-account-suspend relay {} account was not found in tenants file",
            source.name
        ));
    }
    if node_id.is_some() && tenants.nodes == 0 {
        return Err(format!(
            "--hosted-fleet-account-suspend relay {} account node was not found in tenants file",
            source.name
        ));
    }

    Ok(HostedFleetAccountSuspensionRelayReport {
        name: source.name.clone(),
        credentials_file: source.credentials_file.clone(),
        tenants_file: source.tenants_file.clone(),
        credentials: credentials.credentials,
        active: credentials.active,
        revoked: credentials.revoked,
        expired: credentials.expired,
        accounts: credentials.accounts,
        tenants: tenants.tenants,
        active_tenants: tenants.active_tenants,
        revoked_tenants: tenants.revoked_tenants,
        nodes: tenants.nodes,
        active_nodes: tenants.active_nodes,
        revoked_nodes: tenants.revoked_nodes,
        tenant_policies: tenants.policies,
        token_displayed: credentials.token_displayed || tenants.token_displayed,
        key_material_displayed: tenants.key_material_displayed,
        contents_displayed: credentials.contents_displayed || tenants.contents_displayed,
    })
}

fn hosted_fleet_account_suspension_relay_from_suspension(
    name: String,
    suspension: HostedAccountSuspension,
) -> HostedFleetAccountSuspensionRelayReport {
    HostedFleetAccountSuspensionRelayReport {
        name,
        credentials_file: suspension.credentials_file,
        tenants_file: suspension.tenants_file,
        credentials: suspension.credentials,
        active: suspension.active,
        revoked: suspension.revoked,
        expired: suspension.expired,
        accounts: suspension.accounts,
        tenants: suspension.tenants,
        active_tenants: suspension.active_tenants,
        revoked_tenants: suspension.revoked_tenants,
        nodes: suspension.nodes,
        active_nodes: suspension.active_nodes,
        revoked_nodes: suspension.revoked_nodes,
        tenant_policies: suspension.tenant_policies,
        token_displayed: suspension.token_displayed,
        key_material_displayed: suspension.key_material_displayed,
        contents_displayed: suspension.contents_displayed,
    }
}

fn hosted_fleet_account_suspension_relay_from_node_suspension(
    name: String,
    suspension: HostedAccountNodeSuspension,
) -> HostedFleetAccountSuspensionRelayReport {
    HostedFleetAccountSuspensionRelayReport {
        name,
        credentials_file: suspension.credentials_file,
        tenants_file: suspension.tenants_file,
        credentials: suspension.credentials,
        active: suspension.active,
        revoked: suspension.revoked,
        expired: suspension.expired,
        accounts: suspension.accounts,
        tenants: suspension.tenants,
        active_tenants: suspension.active_tenants,
        revoked_tenants: suspension.revoked_tenants,
        nodes: suspension.nodes,
        active_nodes: suspension.active_nodes,
        revoked_nodes: suspension.revoked_nodes,
        tenant_policies: suspension.tenant_policies,
        token_displayed: suspension.token_displayed,
        key_material_displayed: suspension.key_material_displayed,
        contents_displayed: suspension.contents_displayed,
    }
}

#[derive(Debug, Clone)]
struct HostedFleetCredentialRevokeArgs {
    account_id: String,
    node_id: String,
    fleet_file: PathBuf,
    dry_run: bool,
    json: bool,
}

#[derive(Debug, Clone)]
struct HostedFleetCredentialRevokeSource {
    name: String,
    credentials_file: PathBuf,
}

#[derive(Debug, Clone)]
struct HostedFleetCredentialRevokeRelayReport {
    name: String,
    credentials_file: PathBuf,
    credentials: usize,
    active: usize,
    revoked: usize,
    expired: usize,
    accounts: usize,
    token_displayed: bool,
    contents_displayed: bool,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetCredentialRevokeTotals {
    relays: usize,
    credential_sources: usize,
    credentials: usize,
    active: usize,
    revoked: usize,
    expired: usize,
    accounts: usize,
    token_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetCredentialRevokeTotals {
    fn add(&mut self, relay: &HostedFleetCredentialRevokeRelayReport) {
        self.credential_sources += 1;
        self.credentials += relay.credentials;
        self.active += relay.active;
        self.revoked += relay.revoked;
        self.expired += relay.expired;
        self.accounts += relay.accounts;
        self.token_displayed |= relay.token_displayed;
        self.contents_displayed |= relay.contents_displayed;
    }
}

#[derive(Debug, Clone)]
struct HostedFleetCredentialRevokeReport {
    account_id: String,
    node_id: String,
    fleet_file: PathBuf,
    dry_run: bool,
    relays: Vec<HostedFleetCredentialRevokeRelayReport>,
    totals: HostedFleetCredentialRevokeTotals,
}

fn hosted_fleet_credential_revoke_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_hosted_fleet_credential_revoke_args(args)?;
    let report = hosted_fleet_credential_revoke_report(&parsed)?;
    if parsed.json {
        println!("{}", render_hosted_fleet_credential_revoke_json(&report));
    } else {
        println!("{}", render_hosted_fleet_credential_revoke_text(&report));
    }
    Ok(())
}

fn parse_hosted_fleet_credential_revoke_args(
    args: Vec<String>,
) -> Result<HostedFleetCredentialRevokeArgs, String> {
    let mut positional = Vec::new();
    let mut fleet_file = None::<PathBuf>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_credential_revoke_usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(hosted_fleet_credential_revoke_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(hosted_fleet_credential_revoke_usage());
    }
    let account_id = validate_dashboard_filter_id(positional.remove(0), "account id")?;
    let node_id = validate_dashboard_filter_id(positional.remove(0), "node id")?;
    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(hosted_fleet_credential_revoke_usage());
    };
    match (dry_run, confirm) {
        (true, false) | (false, true) => {}
        _ => {
            return Err(
                "--hosted-fleet-credential-revoke requires exactly one of --dry-run or --confirm"
                    .to_string(),
            );
        }
    }

    Ok(HostedFleetCredentialRevokeArgs {
        account_id,
        node_id,
        fleet_file,
        dry_run,
        json,
    })
}

fn hosted_fleet_credential_revoke_usage() -> String {
    "usage: conu-relay --hosted-fleet-credential-revoke <account-id> <node-id> --fleet-file <path> (--dry-run|--confirm) [--json]".to_string()
}

fn hosted_fleet_credential_revoke_report(
    args: &HostedFleetCredentialRevokeArgs,
) -> Result<HostedFleetCredentialRevokeReport, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    let sources = hosted_fleet_credential_revoke_sources(&configs)?;

    // Preflight every credential manifest before confirmed mode mutates any
    // source. This keeps avoidable partial fleet updates out of revoke flows.
    for source in &sources {
        hosted_fleet_credential_revoke_preflight(source, args)?;
    }

    let mut totals = HostedFleetCredentialRevokeTotals {
        relays: configs.len(),
        ..HostedFleetCredentialRevokeTotals::default()
    };
    let mut relays = Vec::<HostedFleetCredentialRevokeRelayReport>::new();

    for source in sources {
        let relay = if args.dry_run {
            hosted_fleet_credential_revoke_snapshot(&source, args)?
        } else {
            hosted_fleet_credential_revoke_confirm(&source, args)?
        };
        totals.add(&relay);
        relays.push(relay);
    }

    Ok(HostedFleetCredentialRevokeReport {
        account_id: args.account_id.clone(),
        node_id: args.node_id.clone(),
        fleet_file: args.fleet_file.clone(),
        dry_run: args.dry_run,
        relays,
        totals,
    })
}

fn hosted_fleet_credential_revoke_sources(
    configs: &[HostedFleetRelayConfig],
) -> Result<Vec<HostedFleetCredentialRevokeSource>, String> {
    let mut sources = Vec::new();
    for config in configs {
        if let Some(credentials_file) = &config.credentials_file {
            sources.push(HostedFleetCredentialRevokeSource {
                name: config.name.clone(),
                credentials_file: credentials_file.clone(),
            });
        }
    }
    if sources.is_empty() {
        return Err(
            "--hosted-fleet-credential-revoke requires at least one fleet relay with credentials_file"
                .to_string(),
        );
    }
    Ok(sources)
}

fn hosted_fleet_credential_revoke_preflight(
    source: &HostedFleetCredentialRevokeSource,
    args: &HostedFleetCredentialRevokeArgs,
) -> Result<(), String> {
    let target = audit_hosted_relay_credentials_file_with_node(
        &source.credentials_file,
        Some(&args.account_id),
        Some(&args.node_id),
    )
    .map_err(|error| error.to_string())?;
    let any_node = audit_hosted_relay_credentials_file_with_node(
        &source.credentials_file,
        None,
        Some(&args.node_id),
    )
    .map_err(|error| error.to_string())?;
    if target.credentials == 0 {
        if any_node.credentials > 0 {
            return Err(format!(
                "--hosted-fleet-credential-revoke relay {} credential node belongs to a different account",
                source.name
            ));
        }
        return Err(format!(
            "--hosted-fleet-credential-revoke relay {} account node credential was not found",
            source.name
        ));
    }
    if any_node.credentials > target.credentials || any_node.accounts > 1 {
        return Err(format!(
            "--hosted-fleet-credential-revoke relay {} credential node belongs to a different account",
            source.name
        ));
    }
    if target.credentials != 1 || any_node.credentials != 1 {
        return Err(format!(
            "--hosted-fleet-credential-revoke relay {} credential node has duplicate records",
            source.name
        ));
    }
    Ok(())
}

fn hosted_fleet_credential_revoke_confirm(
    source: &HostedFleetCredentialRevokeSource,
    args: &HostedFleetCredentialRevokeArgs,
) -> Result<HostedFleetCredentialRevokeRelayReport, String> {
    revoke_hosted_relay_credentials_for_account_node_in_file(
        &source.credentials_file,
        args.account_id.clone(),
        args.node_id.clone(),
    )
    .map_err(|error| error.to_string())?;
    hosted_fleet_credential_revoke_snapshot(source, args)
}

fn hosted_fleet_credential_revoke_snapshot(
    source: &HostedFleetCredentialRevokeSource,
    args: &HostedFleetCredentialRevokeArgs,
) -> Result<HostedFleetCredentialRevokeRelayReport, String> {
    let audit = audit_hosted_relay_credentials_file_with_node(
        &source.credentials_file,
        Some(&args.account_id),
        Some(&args.node_id),
    )
    .map_err(|error| error.to_string())?;

    Ok(HostedFleetCredentialRevokeRelayReport {
        name: source.name.clone(),
        credentials_file: source.credentials_file.clone(),
        credentials: audit.credentials,
        active: audit.active,
        revoked: audit.revoked,
        expired: audit.expired,
        accounts: audit.accounts,
        token_displayed: audit.token_displayed,
        contents_displayed: audit.contents_displayed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostedFleetTenantAccountLifecycleMode {
    Upsert,
    Revoke,
}

impl HostedFleetTenantAccountLifecycleMode {
    fn action(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Revoke => "revoke",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Upsert => "--hosted-fleet-tenant-upsert",
            Self::Revoke => "--hosted-fleet-tenant-revoke",
        }
    }

    fn status(self, dry_run: bool) -> &'static str {
        match (self, dry_run) {
            (Self::Upsert, true) => "would_upsert",
            (Self::Upsert, false) => "upserted",
            (Self::Revoke, true) => "would_revoke",
            (Self::Revoke, false) => "revoked",
        }
    }

    fn usage(self) -> String {
        format!(
            "usage: conu-relay {} <account-id> --fleet-file <path> (--dry-run|--confirm) [--json]",
            self.command()
        )
    }
}

#[derive(Debug, Clone)]
struct HostedFleetTenantAccountLifecycleArgs {
    account_id: String,
    fleet_file: PathBuf,
    dry_run: bool,
    json: bool,
    mode: HostedFleetTenantAccountLifecycleMode,
}

#[derive(Debug, Clone)]
struct HostedFleetTenantAccountLifecycleSource {
    name: String,
    tenants_file: PathBuf,
}

#[derive(Debug, Clone)]
struct HostedFleetTenantAccountLifecycleRelayReport {
    name: String,
    tenants_file: PathBuf,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetTenantAccountLifecycleTotals {
    relays: usize,
    tenant_sources: usize,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetTenantAccountLifecycleTotals {
    fn add(&mut self, relay: &HostedFleetTenantAccountLifecycleRelayReport) {
        self.tenant_sources += 1;
        self.tenants += relay.tenants;
        self.active_tenants += relay.active_tenants;
        self.revoked_tenants += relay.revoked_tenants;
        self.nodes += relay.nodes;
        self.active_nodes += relay.active_nodes;
        self.revoked_nodes += relay.revoked_nodes;
        self.tenant_policies += relay.tenant_policies;
        self.token_displayed |= relay.token_displayed;
        self.key_material_displayed |= relay.key_material_displayed;
        self.contents_displayed |= relay.contents_displayed;
    }
}

#[derive(Debug, Clone)]
struct HostedFleetTenantAccountLifecycleReport {
    account_id: String,
    fleet_file: PathBuf,
    dry_run: bool,
    mode: HostedFleetTenantAccountLifecycleMode,
    relays: Vec<HostedFleetTenantAccountLifecycleRelayReport>,
    totals: HostedFleetTenantAccountLifecycleTotals,
}

fn hosted_fleet_tenant_account_upsert_from_args(args: Vec<String>) -> Result<(), String> {
    hosted_fleet_tenant_account_lifecycle_from_args(
        args,
        HostedFleetTenantAccountLifecycleMode::Upsert,
    )
}

fn hosted_fleet_tenant_account_revoke_from_args(args: Vec<String>) -> Result<(), String> {
    hosted_fleet_tenant_account_lifecycle_from_args(
        args,
        HostedFleetTenantAccountLifecycleMode::Revoke,
    )
}

fn hosted_fleet_tenant_account_lifecycle_from_args(
    args: Vec<String>,
    mode: HostedFleetTenantAccountLifecycleMode,
) -> Result<(), String> {
    let parsed = parse_hosted_fleet_tenant_account_lifecycle_args(args, mode)?;
    let report = hosted_fleet_tenant_account_lifecycle_report(&parsed)?;
    if parsed.json {
        println!(
            "{}",
            render_hosted_fleet_tenant_account_lifecycle_json(&report)
        );
    } else {
        println!(
            "{}",
            render_hosted_fleet_tenant_account_lifecycle_text(&report)
        );
    }
    Ok(())
}

fn parse_hosted_fleet_tenant_account_lifecycle_args(
    args: Vec<String>,
    mode: HostedFleetTenantAccountLifecycleMode,
) -> Result<HostedFleetTenantAccountLifecycleArgs, String> {
    let mut positional = Vec::new();
    let mut fleet_file = None::<PathBuf>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(mode.usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 1 {
        return Err(mode.usage());
    }
    let account_id = validate_dashboard_filter_id(positional.remove(0), "account id")?;
    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(mode.usage());
    };
    match (dry_run, confirm) {
        (true, false) | (false, true) => {}
        _ => {
            return Err(format!(
                "{} requires exactly one of --dry-run or --confirm",
                mode.command()
            ));
        }
    }

    Ok(HostedFleetTenantAccountLifecycleArgs {
        account_id,
        fleet_file,
        dry_run,
        json,
        mode,
    })
}

fn hosted_fleet_tenant_account_lifecycle_report(
    args: &HostedFleetTenantAccountLifecycleArgs,
) -> Result<HostedFleetTenantAccountLifecycleReport, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    let sources = hosted_fleet_tenant_account_lifecycle_sources(&configs, args.mode)?;

    // Preflight every tenant registry before confirmed mode mutates any
    // source. Missing files are allowed for upsert and are created on confirm.
    for source in &sources {
        hosted_fleet_tenant_account_lifecycle_preflight(source, args)?;
    }

    let mut totals = HostedFleetTenantAccountLifecycleTotals {
        relays: configs.len(),
        ..HostedFleetTenantAccountLifecycleTotals::default()
    };
    let mut relays = Vec::<HostedFleetTenantAccountLifecycleRelayReport>::new();

    for source in sources {
        let relay = if args.dry_run {
            hosted_fleet_tenant_account_lifecycle_snapshot(&source, args)?
        } else {
            hosted_fleet_tenant_account_lifecycle_confirm(&source, args)?
        };
        totals.add(&relay);
        relays.push(relay);
    }

    Ok(HostedFleetTenantAccountLifecycleReport {
        account_id: args.account_id.clone(),
        fleet_file: args.fleet_file.clone(),
        dry_run: args.dry_run,
        mode: args.mode,
        relays,
        totals,
    })
}

fn hosted_fleet_tenant_account_lifecycle_sources(
    configs: &[HostedFleetRelayConfig],
    mode: HostedFleetTenantAccountLifecycleMode,
) -> Result<Vec<HostedFleetTenantAccountLifecycleSource>, String> {
    let mut sources = Vec::new();
    for config in configs {
        if let Some(tenants_file) = &config.tenants_file {
            sources.push(HostedFleetTenantAccountLifecycleSource {
                name: config.name.clone(),
                tenants_file: tenants_file.clone(),
            });
        }
    }
    if sources.is_empty() {
        return Err(format!(
            "{} requires at least one fleet relay with tenants_file",
            mode.command()
        ));
    }
    Ok(sources)
}

fn hosted_fleet_tenant_account_lifecycle_preflight(
    source: &HostedFleetTenantAccountLifecycleSource,
    args: &HostedFleetTenantAccountLifecycleArgs,
) -> Result<(), String> {
    let audit =
        audit_hosted_tenants_file_with_node(&source.tenants_file, Some(&args.account_id), None)
            .map_err(|error| error.to_string())?;
    if args.mode == HostedFleetTenantAccountLifecycleMode::Revoke && audit.tenants == 0 {
        return Err(format!(
            "{} relay {} account was not found in tenants file",
            args.mode.command(),
            source.name
        ));
    }
    Ok(())
}

fn hosted_fleet_tenant_account_lifecycle_confirm(
    source: &HostedFleetTenantAccountLifecycleSource,
    args: &HostedFleetTenantAccountLifecycleArgs,
) -> Result<HostedFleetTenantAccountLifecycleRelayReport, String> {
    match args.mode {
        HostedFleetTenantAccountLifecycleMode::Upsert => {
            upsert_hosted_tenant_in_file(&source.tenants_file, args.account_id.clone())
                .map_err(|error| error.to_string())?;
        }
        HostedFleetTenantAccountLifecycleMode::Revoke => {
            revoke_hosted_tenant_in_file(&source.tenants_file, args.account_id.clone())
                .map_err(|error| error.to_string())?;
        }
    }
    hosted_fleet_tenant_account_lifecycle_snapshot(source, args)
}

fn hosted_fleet_tenant_account_lifecycle_snapshot(
    source: &HostedFleetTenantAccountLifecycleSource,
    args: &HostedFleetTenantAccountLifecycleArgs,
) -> Result<HostedFleetTenantAccountLifecycleRelayReport, String> {
    let audit =
        audit_hosted_tenants_file_with_node(&source.tenants_file, Some(&args.account_id), None)
            .map_err(|error| error.to_string())?;

    Ok(HostedFleetTenantAccountLifecycleRelayReport {
        name: source.name.clone(),
        tenants_file: source.tenants_file.clone(),
        tenants: audit.tenants,
        active_tenants: audit.active_tenants,
        revoked_tenants: audit.revoked_tenants,
        nodes: audit.nodes,
        active_nodes: audit.active_nodes,
        revoked_nodes: audit.revoked_nodes,
        tenant_policies: audit.policies,
        token_displayed: audit.token_displayed,
        key_material_displayed: audit.key_material_displayed,
        contents_displayed: audit.contents_displayed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostedFleetTenantNodeLifecycleMode {
    Upsert,
    Revoke,
}

impl HostedFleetTenantNodeLifecycleMode {
    fn action(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Revoke => "revoke",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Upsert => "--hosted-fleet-tenant-node-upsert",
            Self::Revoke => "--hosted-fleet-tenant-node-revoke",
        }
    }

    fn status(self, dry_run: bool) -> &'static str {
        match (self, dry_run) {
            (Self::Upsert, true) => "would_upsert",
            (Self::Upsert, false) => "upserted",
            (Self::Revoke, true) => "would_revoke",
            (Self::Revoke, false) => "revoked",
        }
    }

    fn usage(self) -> String {
        match self {
            Self::Upsert => "usage: conu-relay --hosted-fleet-tenant-node-upsert <account-id> <node-id> --fleet-file <path> [--messages <true|false>] [--streams <true|false>] [--rooms <true|false>] [--files <true|false>] [--mailbox <true|false>] [--signing-key-id <id>] [--exchange-key-id <id>] (--dry-run|--confirm) [--json]".to_string(),
            Self::Revoke => "usage: conu-relay --hosted-fleet-tenant-node-revoke <account-id> <node-id> --fleet-file <path> (--dry-run|--confirm) [--json]".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct HostedFleetTenantNodeLifecycleArgs {
    account_id: String,
    node_id: String,
    fleet_file: PathBuf,
    permissions: HostedTenantPermissions,
    signing_key_id: Option<String>,
    exchange_key_id: Option<String>,
    dry_run: bool,
    json: bool,
    mode: HostedFleetTenantNodeLifecycleMode,
}

#[derive(Debug, Clone)]
struct HostedFleetTenantNodeLifecycleSource {
    name: String,
    tenants_file: PathBuf,
}

#[derive(Debug, Clone)]
struct HostedFleetTenantNodeLifecycleRelayReport {
    name: String,
    tenants_file: PathBuf,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetTenantNodeLifecycleTotals {
    relays: usize,
    tenant_sources: usize,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    nodes: usize,
    active_nodes: usize,
    revoked_nodes: usize,
    tenant_policies: usize,
    token_displayed: bool,
    key_material_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetTenantNodeLifecycleTotals {
    fn add(&mut self, relay: &HostedFleetTenantNodeLifecycleRelayReport) {
        self.tenant_sources += 1;
        self.tenants += relay.tenants;
        self.active_tenants += relay.active_tenants;
        self.revoked_tenants += relay.revoked_tenants;
        self.nodes += relay.nodes;
        self.active_nodes += relay.active_nodes;
        self.revoked_nodes += relay.revoked_nodes;
        self.tenant_policies += relay.tenant_policies;
        self.token_displayed |= relay.token_displayed;
        self.key_material_displayed |= relay.key_material_displayed;
        self.contents_displayed |= relay.contents_displayed;
    }
}

#[derive(Debug, Clone)]
struct HostedFleetTenantNodeLifecycleReport {
    account_id: String,
    node_id: String,
    fleet_file: PathBuf,
    dry_run: bool,
    mode: HostedFleetTenantNodeLifecycleMode,
    permissions: HostedTenantPermissions,
    signing_key_id_provided: bool,
    exchange_key_id_provided: bool,
    relays: Vec<HostedFleetTenantNodeLifecycleRelayReport>,
    totals: HostedFleetTenantNodeLifecycleTotals,
}

fn hosted_fleet_tenant_node_upsert_from_args(args: Vec<String>) -> Result<(), String> {
    hosted_fleet_tenant_node_lifecycle_from_args(args, HostedFleetTenantNodeLifecycleMode::Upsert)
}

fn hosted_fleet_tenant_node_revoke_from_args(args: Vec<String>) -> Result<(), String> {
    hosted_fleet_tenant_node_lifecycle_from_args(args, HostedFleetTenantNodeLifecycleMode::Revoke)
}

fn hosted_fleet_tenant_node_lifecycle_from_args(
    args: Vec<String>,
    mode: HostedFleetTenantNodeLifecycleMode,
) -> Result<(), String> {
    let parsed = parse_hosted_fleet_tenant_node_lifecycle_args(args, mode)?;
    let report = hosted_fleet_tenant_node_lifecycle_report(&parsed)?;
    if parsed.json {
        println!(
            "{}",
            render_hosted_fleet_tenant_node_lifecycle_json(&report)
        );
    } else {
        println!(
            "{}",
            render_hosted_fleet_tenant_node_lifecycle_text(&report)
        );
    }
    Ok(())
}

fn parse_hosted_fleet_tenant_node_lifecycle_args(
    args: Vec<String>,
    mode: HostedFleetTenantNodeLifecycleMode,
) -> Result<HostedFleetTenantNodeLifecycleArgs, String> {
    let mut positional = Vec::new();
    let mut fleet_file = None::<PathBuf>;
    let mut permissions = HostedTenantPermissions::default();
    let mut signing_key_id = None::<String>;
    let mut exchange_key_id = None::<String>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--messages" if mode == HostedFleetTenantNodeLifecycleMode::Upsert => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                permissions.messages = parse_cli_bool(value, "--messages")?;
            }
            "--streams" if mode == HostedFleetTenantNodeLifecycleMode::Upsert => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                permissions.streams = parse_cli_bool(value, "--streams")?;
            }
            "--rooms" if mode == HostedFleetTenantNodeLifecycleMode::Upsert => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                permissions.rooms = parse_cli_bool(value, "--rooms")?;
            }
            "--files" if mode == HostedFleetTenantNodeLifecycleMode::Upsert => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                permissions.files = parse_cli_bool(value, "--files")?;
            }
            "--mailbox" if mode == HostedFleetTenantNodeLifecycleMode::Upsert => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                permissions.mailbox = parse_cli_bool(value, "--mailbox")?;
            }
            "--signing-key-id" if mode == HostedFleetTenantNodeLifecycleMode::Upsert => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                signing_key_id = Some(validate_dashboard_filter_id(
                    value.to_string(),
                    "signing key id",
                )?);
            }
            "--exchange-key-id" if mode == HostedFleetTenantNodeLifecycleMode::Upsert => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mode.usage());
                };
                exchange_key_id = Some(validate_dashboard_filter_id(
                    value.to_string(),
                    "exchange key id",
                )?);
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(mode.usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            value => positional.push(value.to_string()),
        }
        index += 1;
    }

    if positional.len() != 2 {
        return Err(mode.usage());
    }
    let account_id = validate_dashboard_filter_id(positional.remove(0), "account id")?;
    let node_id = validate_dashboard_filter_id(positional.remove(0), "node id")?;
    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(mode.usage());
    };
    match (dry_run, confirm) {
        (true, false) | (false, true) => {}
        _ => {
            return Err(format!(
                "{} requires exactly one of --dry-run or --confirm",
                mode.command()
            ));
        }
    }

    Ok(HostedFleetTenantNodeLifecycleArgs {
        account_id,
        node_id,
        fleet_file,
        permissions,
        signing_key_id,
        exchange_key_id,
        dry_run,
        json,
        mode,
    })
}

fn hosted_fleet_tenant_node_lifecycle_report(
    args: &HostedFleetTenantNodeLifecycleArgs,
) -> Result<HostedFleetTenantNodeLifecycleReport, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    let sources = hosted_fleet_tenant_node_lifecycle_sources(&configs, args.mode)?;

    // Preflight every tenant registry before confirmed mode mutates any
    // source. This keeps avoidable partial fleet updates out of operator flows.
    for source in &sources {
        hosted_fleet_tenant_node_lifecycle_preflight(source, args)?;
    }

    let mut totals = HostedFleetTenantNodeLifecycleTotals {
        relays: configs.len(),
        ..HostedFleetTenantNodeLifecycleTotals::default()
    };
    let mut relays = Vec::<HostedFleetTenantNodeLifecycleRelayReport>::new();

    for source in sources {
        let relay = if args.dry_run {
            hosted_fleet_tenant_node_lifecycle_snapshot(&source, args)?
        } else {
            hosted_fleet_tenant_node_lifecycle_confirm(&source, args)?
        };
        totals.add(&relay);
        relays.push(relay);
    }

    Ok(HostedFleetTenantNodeLifecycleReport {
        account_id: args.account_id.clone(),
        node_id: args.node_id.clone(),
        fleet_file: args.fleet_file.clone(),
        dry_run: args.dry_run,
        mode: args.mode,
        permissions: args.permissions,
        signing_key_id_provided: args.signing_key_id.is_some(),
        exchange_key_id_provided: args.exchange_key_id.is_some(),
        relays,
        totals,
    })
}

fn hosted_fleet_tenant_node_lifecycle_sources(
    configs: &[HostedFleetRelayConfig],
    mode: HostedFleetTenantNodeLifecycleMode,
) -> Result<Vec<HostedFleetTenantNodeLifecycleSource>, String> {
    let mut sources = Vec::new();
    for config in configs {
        if let Some(tenants_file) = &config.tenants_file {
            sources.push(HostedFleetTenantNodeLifecycleSource {
                name: config.name.clone(),
                tenants_file: tenants_file.clone(),
            });
        }
    }
    if sources.is_empty() {
        return Err(format!(
            "{} requires at least one fleet relay with tenants_file",
            mode.command()
        ));
    }
    Ok(sources)
}

fn hosted_fleet_tenant_node_lifecycle_preflight(
    source: &HostedFleetTenantNodeLifecycleSource,
    args: &HostedFleetTenantNodeLifecycleArgs,
) -> Result<(), String> {
    let account =
        audit_hosted_tenants_file_with_node(&source.tenants_file, Some(&args.account_id), None)
            .map_err(|error| error.to_string())?;
    if account.tenants == 0 {
        return Err(format!(
            "{} relay {} account was not found in tenants file",
            args.mode.command(),
            source.name
        ));
    }
    if args.mode == HostedFleetTenantNodeLifecycleMode::Upsert && account.active_tenants == 0 {
        return Err(format!(
            "{} relay {} account is not active in tenants file",
            args.mode.command(),
            source.name
        ));
    }

    let account_node = audit_hosted_tenants_file_with_node(
        &source.tenants_file,
        Some(&args.account_id),
        Some(&args.node_id),
    )
    .map_err(|error| error.to_string())?;
    if args.mode == HostedFleetTenantNodeLifecycleMode::Revoke && account_node.nodes == 0 {
        return Err(format!(
            "{} relay {} account node was not found in tenants file",
            args.mode.command(),
            source.name
        ));
    }
    if args.mode == HostedFleetTenantNodeLifecycleMode::Upsert {
        let any_node =
            audit_hosted_tenants_file_with_node(&source.tenants_file, None, Some(&args.node_id))
                .map_err(|error| error.to_string())?;
        if any_node.nodes > 0 && account_node.nodes == 0 {
            return Err(format!(
                "{} relay {} node belongs to a different account",
                args.mode.command(),
                source.name
            ));
        }
    }
    Ok(())
}

fn hosted_fleet_tenant_node_lifecycle_confirm(
    source: &HostedFleetTenantNodeLifecycleSource,
    args: &HostedFleetTenantNodeLifecycleArgs,
) -> Result<HostedFleetTenantNodeLifecycleRelayReport, String> {
    match args.mode {
        HostedFleetTenantNodeLifecycleMode::Upsert => {
            upsert_hosted_tenant_node_in_file(
                &source.tenants_file,
                args.account_id.clone(),
                args.node_id.clone(),
                args.permissions,
                args.signing_key_id.clone(),
                args.exchange_key_id.clone(),
            )
            .map_err(|error| error.to_string())?;
        }
        HostedFleetTenantNodeLifecycleMode::Revoke => {
            revoke_hosted_tenant_node_in_file(
                &source.tenants_file,
                args.account_id.clone(),
                args.node_id.clone(),
            )
            .map_err(|error| error.to_string())?;
        }
    }
    hosted_fleet_tenant_node_lifecycle_snapshot(source, args)
}

fn hosted_fleet_tenant_node_lifecycle_snapshot(
    source: &HostedFleetTenantNodeLifecycleSource,
    args: &HostedFleetTenantNodeLifecycleArgs,
) -> Result<HostedFleetTenantNodeLifecycleRelayReport, String> {
    let audit = audit_hosted_tenants_file_with_node(
        &source.tenants_file,
        Some(&args.account_id),
        Some(&args.node_id),
    )
    .map_err(|error| error.to_string())?;

    Ok(HostedFleetTenantNodeLifecycleRelayReport {
        name: source.name.clone(),
        tenants_file: source.tenants_file.clone(),
        tenants: audit.tenants,
        active_tenants: audit.active_tenants,
        revoked_tenants: audit.revoked_tenants,
        nodes: audit.nodes,
        active_nodes: audit.active_nodes,
        revoked_nodes: audit.revoked_nodes,
        tenant_policies: audit.policies,
        token_displayed: audit.token_displayed,
        key_material_displayed: audit.key_material_displayed,
        contents_displayed: audit.contents_displayed,
    })
}

#[derive(Debug, Clone)]
struct SessionAuditArgs {
    session_state_dir: PathBuf,
    node_id: Option<String>,
    json: bool,
}

fn session_audit_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_session_audit_args(args)?;
    let audit = audit_relay_session_state_dir(&parsed.session_state_dir, parsed.node_id.as_deref())
        .map_err(|error| error.to_string())?;
    if parsed.json {
        println!(
            "{}",
            render_session_audit_json(&audit, &parsed.session_state_dir)
        );
    } else {
        println!(
            "{}",
            render_session_audit_text(&audit, &parsed.session_state_dir)
        );
    }
    Ok(())
}

fn parse_session_audit_args(args: Vec<String>) -> Result<SessionAuditArgs, String> {
    let mut session_state_dir = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--session-state-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(session_audit_usage());
                };
                session_state_dir = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(session_audit_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(session_audit_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(session_audit_usage()),
        }
        index += 1;
    }

    let Some(session_state_dir) = session_state_dir.filter(|path| !path.as_os_str().is_empty())
    else {
        return Err(session_audit_usage());
    };

    Ok(SessionAuditArgs {
        session_state_dir,
        node_id,
        json,
    })
}

fn session_audit_usage() -> String {
    "usage: conu-relay --session-audit --session-state-dir <path> [--node <node-id>] [--json]"
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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

fn abuse_threshold_report_from_args(args: Vec<String>) -> Result<AbuseThresholdReportExit, String> {
    let parsed = parse_abuse_threshold_report_args(args)?;
    let audit = audit_relay_abuse_dir(&parsed.abuse_dir, parsed.node_id.as_deref())
        .map_err(|error| error.to_string())?;
    let report =
        abuse_threshold_report_from_audit(&audit, parsed.thresholds, parsed.abuse_dir.clone());
    if parsed.json {
        println!("{}", render_abuse_threshold_report_json(&report));
    } else {
        println!("{}", render_abuse_threshold_report_text(&report));
    }
    Ok(abuse_threshold_report_exit(
        &report,
        parsed.fail_on_threshold,
    ))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AbuseThresholds {
    admin_unauthorized: Option<u64>,
    admin_failed: Option<u64>,
    unauthorized_sessions: Option<u64>,
    credential_denied_sessions: Option<u64>,
    tenant_denied_sessions: Option<u64>,
    rate_limited_sessions: Option<u64>,
    session_expired: Option<u64>,
    quota_denied_forwards: Option<u64>,
    undelivered_forwards: Option<u64>,
    mailbox_rejected_forwards: Option<u64>,
    malformed_client_frames: Option<u64>,
}

impl AbuseThresholds {
    fn has_any(self) -> bool {
        self.checked_count() > 0
    }

    fn checked_count(self) -> usize {
        [
            self.admin_unauthorized,
            self.admin_failed,
            self.unauthorized_sessions,
            self.credential_denied_sessions,
            self.tenant_denied_sessions,
            self.rate_limited_sessions,
            self.session_expired,
            self.quota_denied_forwards,
            self.undelivered_forwards,
            self.mailbox_rejected_forwards,
            self.malformed_client_frames,
        ]
        .into_iter()
        .filter(Option::is_some)
        .count()
    }

    fn overlay(self, overrides: Self) -> Self {
        Self {
            admin_unauthorized: overrides.admin_unauthorized.or(self.admin_unauthorized),
            admin_failed: overrides.admin_failed.or(self.admin_failed),
            unauthorized_sessions: overrides
                .unauthorized_sessions
                .or(self.unauthorized_sessions),
            credential_denied_sessions: overrides
                .credential_denied_sessions
                .or(self.credential_denied_sessions),
            tenant_denied_sessions: overrides
                .tenant_denied_sessions
                .or(self.tenant_denied_sessions),
            rate_limited_sessions: overrides
                .rate_limited_sessions
                .or(self.rate_limited_sessions),
            session_expired: overrides.session_expired.or(self.session_expired),
            quota_denied_forwards: overrides
                .quota_denied_forwards
                .or(self.quota_denied_forwards),
            undelivered_forwards: overrides.undelivered_forwards.or(self.undelivered_forwards),
            mailbox_rejected_forwards: overrides
                .mailbox_rejected_forwards
                .or(self.mailbox_rejected_forwards),
            malformed_client_frames: overrides
                .malformed_client_frames
                .or(self.malformed_client_frames),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AbuseThresholdReport {
    source: &'static str,
    relay: Option<String>,
    abuse_dir: Option<PathBuf>,
    account_id: Option<String>,
    node_id: Option<String>,
    records: usize,
    window_started_unix: Option<u64>,
    thresholds: AbuseThresholds,
    threshold_checks: usize,
    threshold_exceeded: usize,
    admin_unauthorized: u64,
    admin_failed: u64,
    unauthorized_sessions: u64,
    credential_denied_sessions: u64,
    tenant_denied_sessions: u64,
    rate_limited_sessions: u64,
    session_expired: u64,
    quota_denied_forwards: u64,
    undelivered_forwards: u64,
    mailbox_rejected_forwards: u64,
    malformed_client_frames: u64,
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
}

#[derive(Debug, Clone)]
struct AbuseThresholdReportArgs {
    abuse_dir: PathBuf,
    node_id: Option<String>,
    #[cfg(test)]
    thresholds_file: Option<PathBuf>,
    thresholds: AbuseThresholds,
    json: bool,
    fail_on_threshold: bool,
}

fn parse_abuse_threshold_report_args(
    args: Vec<String>,
) -> Result<AbuseThresholdReportArgs, String> {
    let mut abuse_dir = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut thresholds_file = None::<PathBuf>;
    let mut cli_thresholds = AbuseThresholds::default();
    let mut json = false;
    let mut fail_on_threshold = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--abuse-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(abuse_threshold_report_usage());
                };
                abuse_dir = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(abuse_threshold_report_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--thresholds-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(abuse_threshold_report_usage());
                };
                if value.trim().is_empty() {
                    return Err(abuse_threshold_report_usage());
                }
                thresholds_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--fail-on-threshold" => fail_on_threshold = true,
            "--help" | "-h" => return Err(abuse_threshold_report_usage()),
            value if value.starts_with("--max-") => {
                index += 1;
                let Some(limit) = args.get(index) else {
                    return Err(abuse_threshold_report_usage());
                };
                parse_abuse_threshold_option(&mut cli_thresholds, value, limit)?;
            }
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(abuse_threshold_report_usage()),
        }
        index += 1;
    }

    let Some(abuse_dir) = abuse_dir.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(abuse_threshold_report_usage());
    };

    let thresholds = merged_abuse_thresholds(thresholds_file.as_deref(), cli_thresholds)?;
    if !thresholds.has_any() {
        return Err(abuse_threshold_report_usage());
    }

    Ok(AbuseThresholdReportArgs {
        abuse_dir,
        node_id,
        #[cfg(test)]
        thresholds_file,
        thresholds,
        json,
        fail_on_threshold,
    })
}

fn abuse_threshold_report_usage() -> String {
    "usage: conu-relay --abuse-threshold-report --abuse-dir <path> [--node <node-id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold]".to_string()
}

fn merged_abuse_thresholds(
    thresholds_file: Option<&Path>,
    cli_thresholds: AbuseThresholds,
) -> Result<AbuseThresholds, String> {
    let file_thresholds = thresholds_file
        .map(load_abuse_threshold_policy_file)
        .transpose()?
        .unwrap_or_default();
    Ok(file_thresholds.overlay(cli_thresholds))
}

fn load_abuse_threshold_policy_file(path: &Path) -> Result<AbuseThresholds, String> {
    let contents = read_required_regular_cli_file(path, "abuse threshold policy")?;
    parse_abuse_threshold_policy_file(&contents)
}

fn parse_abuse_threshold_policy_file(contents: &str) -> Result<AbuseThresholds, String> {
    let mut version = None::<String>;
    let mut thresholds = AbuseThresholds::default();
    let mut guards = AbuseThresholdPolicyGuards::default();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            format!("abuse threshold policy file line {line_number} must use key = value")
        })?;
        let key = key.trim();
        let value = clean_config_value(raw_value);
        if key.is_empty() {
            return Err(format!(
                "abuse threshold policy file line {line_number} must include a key"
            ));
        }

        if key == "version" {
            version = Some(value);
            continue;
        }
        if parse_abuse_threshold_policy_option(&mut thresholds, key, &value, line_number)? {
            continue;
        }
        if guards.record_false(key, &value, line_number)? {
            continue;
        }

        return Err(format!(
            "abuse threshold policy file line {line_number} uses unsupported key {key}"
        ));
    }

    match version.as_deref() {
        Some(ABUSE_THRESHOLD_POLICY_FILE_VERSION) => {}
        Some(_) => return Err("abuse threshold policy file version is unsupported".to_string()),
        None => return Err("abuse threshold policy file version is required".to_string()),
    }
    guards.validate()?;
    Ok(thresholds)
}

fn parse_abuse_threshold_policy_option(
    thresholds: &mut AbuseThresholds,
    key: &str,
    value: &str,
    line_number: usize,
) -> Result<bool, String> {
    match key {
        "max_admin_unauthorized" => {
            thresholds.admin_unauthorized = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_admin_failed" => {
            thresholds.admin_failed = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_unauthorized_sessions" => {
            thresholds.unauthorized_sessions = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_credential_denied_sessions" => {
            thresholds.credential_denied_sessions =
                Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_tenant_denied_sessions" => {
            thresholds.tenant_denied_sessions = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_rate_limited_sessions" => {
            thresholds.rate_limited_sessions = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_session_expired" => {
            thresholds.session_expired = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_quota_denied_forwards" => {
            thresholds.quota_denied_forwards = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_undelivered_forwards" => {
            thresholds.undelivered_forwards = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_mailbox_rejected_forwards" => {
            thresholds.mailbox_rejected_forwards = Some(parse_policy_u64(value, key, line_number)?);
        }
        "max_malformed_client_frames" => {
            thresholds.malformed_client_frames = Some(parse_policy_u64(value, key, line_number)?);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[derive(Default)]
struct AbuseThresholdPolicyGuards {
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
}

impl AbuseThresholdPolicyGuards {
    fn record_false(&mut self, key: &str, value: &str, line_number: usize) -> Result<bool, String> {
        let guard = match key {
            "payload_displayed" => &mut self.payload_displayed,
            "token_displayed" => &mut self.token_displayed,
            "token_hash_displayed" => &mut self.token_hash_displayed,
            "key_material_displayed" => &mut self.key_material_displayed,
            "session_id_displayed" => &mut self.session_id_displayed,
            "ciphertext_displayed" => &mut self.ciphertext_displayed,
            "contents_displayed" => &mut self.contents_displayed,
            _ => return Ok(false),
        };
        if value != "false" {
            return Err(format!(
                "abuse threshold policy file line {line_number} {key} must be false"
            ));
        }
        *guard = true;
        Ok(true)
    }

    fn validate(self) -> Result<(), String> {
        for (key, present) in [
            ("payload_displayed", self.payload_displayed),
            ("token_displayed", self.token_displayed),
            ("token_hash_displayed", self.token_hash_displayed),
            ("key_material_displayed", self.key_material_displayed),
            ("session_id_displayed", self.session_id_displayed),
            ("ciphertext_displayed", self.ciphertext_displayed),
            ("contents_displayed", self.contents_displayed),
        ] {
            if !present {
                return Err(format!(
                    "abuse threshold policy file requires {key} = false"
                ));
            }
        }
        Ok(())
    }
}

fn parse_policy_u64(value: &str, key: &str, line_number: usize) -> Result<u64, String> {
    value.parse::<u64>().map_err(|_| {
        format!("abuse threshold policy file line {line_number} {key} must be an unsigned integer")
    })
}

fn strip_config_comment(line: &str) -> &str {
    line.split_once('#')
        .map(|(before, _)| before)
        .unwrap_or(line)
}

fn clean_config_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn parse_abuse_threshold_option(
    thresholds: &mut AbuseThresholds,
    flag: &str,
    value: &str,
) -> Result<(), String> {
    let limit = parse_cli_u64(value, flag)?;
    match flag {
        "--max-admin-unauthorized" => thresholds.admin_unauthorized = Some(limit),
        "--max-admin-failed" => thresholds.admin_failed = Some(limit),
        "--max-unauthorized-sessions" => thresholds.unauthorized_sessions = Some(limit),
        "--max-credential-denied-sessions" => {
            thresholds.credential_denied_sessions = Some(limit);
        }
        "--max-tenant-denied-sessions" => thresholds.tenant_denied_sessions = Some(limit),
        "--max-rate-limited-sessions" => thresholds.rate_limited_sessions = Some(limit),
        "--max-session-expired" => thresholds.session_expired = Some(limit),
        "--max-quota-denied-forwards" => thresholds.quota_denied_forwards = Some(limit),
        "--max-undelivered-forwards" => thresholds.undelivered_forwards = Some(limit),
        "--max-mailbox-rejected-forwards" => thresholds.mailbox_rejected_forwards = Some(limit),
        "--max-malformed-client-frames" => thresholds.malformed_client_frames = Some(limit),
        _ => return Err(format!("unknown threshold option: {flag}")),
    }
    Ok(())
}

fn parse_cli_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be an unsigned integer"))
}

fn threshold_exceeded(value: u64, threshold: Option<u64>) -> bool {
    threshold.is_some_and(|threshold| value > threshold)
}

fn abuse_threshold_report_from_audit(
    audit: &RelayAbuseAudit,
    thresholds: AbuseThresholds,
    abuse_dir: PathBuf,
) -> AbuseThresholdReport {
    build_abuse_threshold_report(
        "local",
        None,
        Some(abuse_dir),
        None,
        audit.node_id.clone(),
        audit.records,
        audit.window_started_unix,
        thresholds,
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
        audit.payload_displayed,
        audit.token_displayed,
        audit.token_hash_displayed,
        audit.key_material_displayed,
        audit.session_id_displayed,
        audit.ciphertext_displayed,
        audit.contents_displayed,
    )
}

fn abuse_threshold_report_from_admin_result(
    result: &RelayAdminResult,
    thresholds: AbuseThresholds,
    relay: String,
) -> AbuseThresholdReport {
    build_abuse_threshold_report(
        "admin",
        Some(relay),
        None,
        result.account_id.clone(),
        result.node_id.clone(),
        result.abuse_records,
        result.abuse_window_started_unix,
        thresholds,
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
        result.payload_displayed,
        result.token_displayed,
        result.token_hash_displayed,
        result.key_material_displayed,
        result.session_id_displayed,
        result.ciphertext_displayed,
        result.contents_displayed,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_abuse_threshold_report(
    source: &'static str,
    relay: Option<String>,
    abuse_dir: Option<PathBuf>,
    account_id: Option<String>,
    node_id: Option<String>,
    records: usize,
    window_started_unix: Option<u64>,
    thresholds: AbuseThresholds,
    admin_unauthorized: u64,
    admin_failed: u64,
    unauthorized_sessions: u64,
    credential_denied_sessions: u64,
    tenant_denied_sessions: u64,
    rate_limited_sessions: u64,
    session_expired: u64,
    quota_denied_forwards: u64,
    undelivered_forwards: u64,
    mailbox_rejected_forwards: u64,
    malformed_client_frames: u64,
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
) -> AbuseThresholdReport {
    let threshold_exceeded = [
        threshold_exceeded(admin_unauthorized, thresholds.admin_unauthorized),
        threshold_exceeded(admin_failed, thresholds.admin_failed),
        threshold_exceeded(unauthorized_sessions, thresholds.unauthorized_sessions),
        threshold_exceeded(
            credential_denied_sessions,
            thresholds.credential_denied_sessions,
        ),
        threshold_exceeded(tenant_denied_sessions, thresholds.tenant_denied_sessions),
        threshold_exceeded(rate_limited_sessions, thresholds.rate_limited_sessions),
        threshold_exceeded(session_expired, thresholds.session_expired),
        threshold_exceeded(quota_denied_forwards, thresholds.quota_denied_forwards),
        threshold_exceeded(undelivered_forwards, thresholds.undelivered_forwards),
        threshold_exceeded(
            mailbox_rejected_forwards,
            thresholds.mailbox_rejected_forwards,
        ),
        threshold_exceeded(malformed_client_frames, thresholds.malformed_client_frames),
    ]
    .into_iter()
    .filter(|exceeded| *exceeded)
    .count();

    AbuseThresholdReport {
        source,
        relay,
        abuse_dir,
        account_id,
        node_id,
        records,
        window_started_unix,
        thresholds,
        threshold_checks: thresholds.checked_count(),
        threshold_exceeded,
        admin_unauthorized,
        admin_failed,
        unauthorized_sessions,
        credential_denied_sessions,
        tenant_denied_sessions,
        rate_limited_sessions,
        session_expired,
        quota_denied_forwards,
        undelivered_forwards,
        mailbox_rejected_forwards,
        malformed_client_frames,
        payload_displayed,
        token_displayed,
        token_hash_displayed,
        key_material_displayed,
        session_id_displayed,
        ciphertext_displayed,
        contents_displayed,
    }
}

#[derive(Debug, Clone)]
struct MailboxAuditArgs {
    mailbox_dir: PathBuf,
    node_id: Option<String>,
    ttl: Option<Duration>,
    #[cfg(test)]
    retention_policy_file: Option<PathBuf>,
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
    let mut retention_policy_file = None::<PathBuf>;
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
            "--retention-policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_audit_usage());
                };
                if value.trim().is_empty() {
                    return Err(mailbox_audit_usage());
                }
                retention_policy_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--help" | "-h" => return Err(mailbox_audit_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(mailbox_audit_usage()),
        }
        index += 1;
    }

    let Some(mailbox_dir) = mailbox_dir.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(mailbox_audit_usage());
    };
    let retention =
        merged_mailbox_retention_policy(retention_policy_file.as_deref(), node_id, ttl)?;

    Ok(MailboxAuditArgs {
        mailbox_dir,
        node_id: retention.node_id,
        ttl: retention.ttl,
        #[cfg(test)]
        retention_policy_file,
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

#[derive(Debug, Clone, Default)]
struct MailboxRetentionPolicy {
    node_id: Option<String>,
    ttl: Option<Duration>,
}

fn merged_mailbox_retention_policy(
    retention_policy_file: Option<&Path>,
    cli_node_id: Option<String>,
    cli_ttl: Option<Duration>,
) -> Result<MailboxRetentionPolicy, String> {
    let mut policy = retention_policy_file
        .map(load_mailbox_retention_policy_file)
        .transpose()?
        .unwrap_or_default();
    if let Some(node_id) = cli_node_id {
        policy.node_id = Some(node_id);
    }
    if let Some(ttl) = cli_ttl {
        policy.ttl = Some(ttl);
    }
    Ok(policy)
}

fn load_mailbox_retention_policy_file(path: &Path) -> Result<MailboxRetentionPolicy, String> {
    let contents = read_required_regular_cli_file(path, "mailbox retention policy")?;
    parse_mailbox_retention_policy_file(&contents)
}

fn parse_mailbox_retention_policy_file(contents: &str) -> Result<MailboxRetentionPolicy, String> {
    let mut version = None::<String>;
    let mut policy = MailboxRetentionPolicy::default();
    let mut guards = MailboxRetentionPolicyGuards::default();

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            format!("mailbox retention policy file line {line_number} must use key = value")
        })?;
        let key = key.trim();
        let value = clean_config_value(raw_value);
        if key.is_empty() {
            return Err(format!(
                "mailbox retention policy file line {line_number} must include a key"
            ));
        }

        match key {
            "version" => version = Some(value),
            "node_id" => {
                policy.node_id = Some(validate_dashboard_filter_id(value, "node id")?);
            }
            "ttl_seconds" => {
                policy.ttl = Some(parse_mailbox_policy_duration(&value, key, line_number)?);
            }
            _ if guards.record_false(key, &value, line_number)? => {}
            _ => {
                return Err(format!(
                    "mailbox retention policy file line {line_number} uses unsupported key {key}"
                ));
            }
        }
    }

    match version.as_deref() {
        Some(MAILBOX_RETENTION_POLICY_FILE_VERSION) => {}
        Some(_) => return Err("mailbox retention policy file version is unsupported".to_string()),
        None => return Err("mailbox retention policy file version is required".to_string()),
    }
    guards.validate()?;
    Ok(policy)
}

fn parse_mailbox_policy_duration(
    value: &str,
    key: &str,
    line_number: usize,
) -> Result<Duration, String> {
    let seconds = value.parse::<u64>().map_err(|_| {
        format!(
            "mailbox retention policy file line {line_number} {key} must be an unsigned integer"
        )
    })?;
    if seconds == 0 {
        return Err(format!(
            "mailbox retention policy file line {line_number} {key} must be greater than zero"
        ));
    }
    Ok(Duration::from_secs(seconds))
}

#[derive(Default)]
struct MailboxRetentionPolicyGuards {
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
}

impl MailboxRetentionPolicyGuards {
    fn record_false(&mut self, key: &str, value: &str, line_number: usize) -> Result<bool, String> {
        let guard = match key {
            "payload_displayed" => &mut self.payload_displayed,
            "token_displayed" => &mut self.token_displayed,
            "token_hash_displayed" => &mut self.token_hash_displayed,
            "key_material_displayed" => &mut self.key_material_displayed,
            "session_id_displayed" => &mut self.session_id_displayed,
            "ciphertext_displayed" => &mut self.ciphertext_displayed,
            "contents_displayed" => &mut self.contents_displayed,
            _ => return Ok(false),
        };
        if value != "false" {
            return Err(format!(
                "mailbox retention policy file line {line_number} {key} must be false"
            ));
        }
        *guard = true;
        Ok(true)
    }

    fn validate(self) -> Result<(), String> {
        for (key, present) in [
            ("payload_displayed", self.payload_displayed),
            ("token_displayed", self.token_displayed),
            ("token_hash_displayed", self.token_hash_displayed),
            ("key_material_displayed", self.key_material_displayed),
            ("session_id_displayed", self.session_id_displayed),
            ("ciphertext_displayed", self.ciphertext_displayed),
            ("contents_displayed", self.contents_displayed),
        ] {
            if !present {
                return Err(format!(
                    "mailbox retention policy file requires {key} = false"
                ));
            }
        }
        Ok(())
    }
}

fn mailbox_audit_usage() -> String {
    "usage: conu-relay --mailbox-audit --mailbox-dir <path> [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--json]".to_string()
}

#[derive(Debug, Clone)]
struct MailboxPurgeArgs {
    mailbox_dir: PathBuf,
    node_id: Option<String>,
    ttl: Duration,
    dry_run: bool,
    #[cfg(test)]
    retention_policy_file: Option<PathBuf>,
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
    let mut retention_policy_file = None::<PathBuf>;
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
            "--retention-policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(mailbox_purge_usage());
                };
                if value.trim().is_empty() {
                    return Err(mailbox_purge_usage());
                }
                retention_policy_file = Some(PathBuf::from(value));
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(mailbox_purge_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(mailbox_purge_usage()),
        }
        index += 1;
    }

    let Some(mailbox_dir) = mailbox_dir.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(mailbox_purge_usage());
    };
    let retention =
        merged_mailbox_retention_policy(retention_policy_file.as_deref(), node_id, ttl)?;
    let Some(ttl) = retention.ttl else {
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
        node_id: retention.node_id,
        ttl,
        dry_run,
        #[cfg(test)]
        retention_policy_file,
        json,
    })
}

fn mailbox_purge_usage() -> String {
    "usage: conu-relay --mailbox-purge --mailbox-dir <path> [--ttl-seconds <seconds>] [--node <node-id>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]".to_string()
}

#[derive(Debug, Clone)]
struct HostedFleetMailboxPurgeArgs {
    fleet_file: PathBuf,
    retention_policy_file: Option<PathBuf>,
    mailbox_retention_policy: MailboxRetentionPolicy,
    mailbox_ttl: Option<Duration>,
    dry_run: bool,
    json: bool,
}

#[derive(Debug, Clone)]
struct HostedFleetMailboxPurgeRelayReport {
    name: String,
    mailbox_dir: PathBuf,
    report: RelayMailboxPurgeReport,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetMailboxPurgeTotals {
    relays: usize,
    mailbox_sources: usize,
    mailbox_nodes: usize,
    mailbox_records: usize,
    mailbox_invalid_records: usize,
    mailbox_bytes: u64,
    mailbox_expired_records: u64,
    mailbox_expired_bytes: u64,
    mailbox_purged_records: u64,
    mailbox_purged_bytes: u64,
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetMailboxPurgeTotals {
    fn add(&mut self, relay: &HostedFleetMailboxPurgeRelayReport) {
        let report = &relay.report;
        self.mailbox_sources += 1;
        self.mailbox_nodes += report.nodes;
        self.mailbox_records += report.records;
        self.mailbox_invalid_records += report.invalid_records;
        self.mailbox_bytes = self.mailbox_bytes.saturating_add(report.bytes);
        self.mailbox_expired_records = self
            .mailbox_expired_records
            .saturating_add(report.expired_records);
        self.mailbox_expired_bytes = self
            .mailbox_expired_bytes
            .saturating_add(report.expired_bytes);
        self.mailbox_purged_records = self
            .mailbox_purged_records
            .saturating_add(report.purged_records);
        self.mailbox_purged_bytes = self
            .mailbox_purged_bytes
            .saturating_add(report.purged_bytes);
        self.payload_displayed |= report.payload_displayed;
        self.token_displayed |= report.token_displayed;
        self.token_hash_displayed |= report.token_hash_displayed;
        self.key_material_displayed |= report.key_material_displayed;
        self.session_id_displayed |= report.session_id_displayed;
        self.ciphertext_displayed |= report.ciphertext_displayed;
        self.contents_displayed |= report.contents_displayed;
    }
}

#[derive(Debug, Clone)]
struct HostedFleetMailboxPurgeReport {
    fleet_file: PathBuf,
    node_id: Option<String>,
    retention_policy_file: Option<PathBuf>,
    mailbox_ttl: Option<Duration>,
    dry_run: bool,
    relays: Vec<HostedFleetMailboxPurgeRelayReport>,
    totals: HostedFleetMailboxPurgeTotals,
}

fn hosted_fleet_mailbox_purge_from_args(args: Vec<String>) -> Result<(), String> {
    let parsed = parse_hosted_fleet_mailbox_purge_args(args)?;
    let report = hosted_fleet_mailbox_purge_report(&parsed)?;
    if parsed.json {
        println!("{}", render_hosted_fleet_mailbox_purge_json(&report));
    } else {
        println!("{}", render_hosted_fleet_mailbox_purge_text(&report));
    }
    Ok(())
}

fn parse_hosted_fleet_mailbox_purge_args(
    args: Vec<String>,
) -> Result<HostedFleetMailboxPurgeArgs, String> {
    let mut fleet_file = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut retention_policy_file = None::<PathBuf>;
    let mut mailbox_ttl = None::<Duration>;
    let mut dry_run = false;
    let mut confirm = false;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_mailbox_purge_usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_mailbox_purge_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--retention-policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_mailbox_purge_usage());
                };
                if value.trim().is_empty() {
                    return Err(hosted_fleet_mailbox_purge_usage());
                }
                retention_policy_file = Some(PathBuf::from(value));
            }
            "--ttl-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_mailbox_purge_usage());
                };
                mailbox_ttl = Some(parse_positive_cli_duration(value, "--ttl-seconds")?);
            }
            "--dry-run" => dry_run = true,
            "--confirm" => confirm = true,
            "--json" => json = true,
            "--help" | "-h" => return Err(hosted_fleet_mailbox_purge_usage()),
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(hosted_fleet_mailbox_purge_usage()),
        }
        index += 1;
    }

    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(hosted_fleet_mailbox_purge_usage());
    };
    retention_policy_file = retention_policy_file.filter(|path| !path.as_os_str().is_empty());
    let mailbox_retention_policy =
        merged_mailbox_retention_policy(retention_policy_file.as_deref(), node_id, None)?;
    match (dry_run, confirm) {
        (true, false) | (false, true) => {}
        _ => {
            return Err(
                "--hosted-fleet-mailbox-purge requires exactly one of --dry-run or --confirm"
                    .to_string(),
            );
        }
    }

    Ok(HostedFleetMailboxPurgeArgs {
        fleet_file,
        retention_policy_file,
        mailbox_retention_policy,
        mailbox_ttl,
        dry_run,
        json,
    })
}

fn hosted_fleet_mailbox_purge_usage() -> String {
    "usage: conu-relay --hosted-fleet-mailbox-purge --fleet-file <path> [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] (--dry-run|--confirm) [--json]".to_string()
}

fn hosted_fleet_mailbox_purge_report(
    args: &HostedFleetMailboxPurgeArgs,
) -> Result<HostedFleetMailboxPurgeReport, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    let mut sources = Vec::<(String, PathBuf, Duration)>::new();
    for config in &configs {
        let Some(mailbox_dir) = config.mailbox_dir.clone() else {
            continue;
        };
        let ttl = effective_fleet_mailbox_ttl(args, config).ok_or_else(|| {
            format!(
                "hosted fleet mailbox purge relay {} requires --ttl-seconds, retention policy ttl_seconds, or mailbox_ttl_seconds",
                config.name
            )
        })?;
        sources.push((config.name.clone(), mailbox_dir, ttl));
    }
    if sources.is_empty() {
        return Err(
            "--hosted-fleet-mailbox-purge requires at least one fleet relay mailbox_dir"
                .to_string(),
        );
    }

    // Validate every mailbox source before confirmed mode can delete from any source.
    let mut totals = HostedFleetMailboxPurgeTotals {
        relays: configs.len(),
        ..HostedFleetMailboxPurgeTotals::default()
    };
    let mut relays = Vec::<HostedFleetMailboxPurgeRelayReport>::new();

    for (name, mailbox_dir, ttl) in sources {
        let report = purge_relay_mailbox_dir(
            &mailbox_dir,
            args.mailbox_retention_policy.node_id.as_deref(),
            ttl,
            args.dry_run,
        )
        .map_err(|error| error.to_string())?;
        let relay = HostedFleetMailboxPurgeRelayReport {
            name,
            mailbox_dir,
            report,
        };
        totals.add(&relay);
        relays.push(relay);
    }

    Ok(HostedFleetMailboxPurgeReport {
        fleet_file: args.fleet_file.clone(),
        node_id: args.mailbox_retention_policy.node_id.clone(),
        retention_policy_file: args.retention_policy_file.clone(),
        mailbox_ttl: args.mailbox_ttl.or(args.mailbox_retention_policy.ttl),
        dry_run: args.dry_run,
        relays,
        totals,
    })
}

fn effective_fleet_mailbox_ttl(
    args: &HostedFleetMailboxPurgeArgs,
    config: &HostedFleetRelayConfig,
) -> Option<Duration> {
    args.mailbox_ttl
        .or_else(|| config.mailbox_ttl_seconds.map(Duration::from_secs))
        .or(args.mailbox_retention_policy.ttl)
}

#[derive(Debug, Clone)]
struct HostedFleetAbuseResponsePlanArgs {
    fleet_file: PathBuf,
    node_id: Option<String>,
    thresholds_file: Option<PathBuf>,
    abuse_thresholds: AbuseThresholds,
    json: bool,
    fail_on_action: bool,
}

#[derive(Debug, Clone)]
struct HostedFleetAbuseRelayPlan {
    name: String,
    abuse_dir: PathBuf,
    audit: RelayAbuseAudit,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetAbuseResponsePlanTotals {
    relays: usize,
    abuse_sources: usize,
    abuse_records: usize,
    admin_unauthorized: u64,
    admin_failed: u64,
    unauthorized_sessions: u64,
    credential_denied_sessions: u64,
    tenant_denied_sessions: u64,
    rate_limited_sessions: u64,
    session_expired: u64,
    quota_denied_forwards: u64,
    undelivered_forwards: u64,
    mailbox_rejected_forwards: u64,
    malformed_client_frames: u64,
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetAbuseResponsePlanTotals {
    fn add(&mut self, audit: &RelayAbuseAudit) {
        self.abuse_sources += 1;
        self.abuse_records += audit.records;
        self.admin_unauthorized = self
            .admin_unauthorized
            .saturating_add(audit.admin_unauthorized);
        self.admin_failed = self.admin_failed.saturating_add(audit.admin_failed);
        self.unauthorized_sessions = self
            .unauthorized_sessions
            .saturating_add(audit.unauthorized_sessions);
        self.credential_denied_sessions = self
            .credential_denied_sessions
            .saturating_add(audit.credential_denied_sessions);
        self.tenant_denied_sessions = self
            .tenant_denied_sessions
            .saturating_add(audit.tenant_denied_sessions);
        self.rate_limited_sessions = self
            .rate_limited_sessions
            .saturating_add(audit.rate_limited_sessions);
        self.session_expired = self.session_expired.saturating_add(audit.session_expired);
        self.quota_denied_forwards = self
            .quota_denied_forwards
            .saturating_add(audit.quota_denied_forwards);
        self.undelivered_forwards = self
            .undelivered_forwards
            .saturating_add(audit.undelivered_forwards);
        self.mailbox_rejected_forwards = self
            .mailbox_rejected_forwards
            .saturating_add(audit.mailbox_rejected_forwards);
        self.malformed_client_frames = self
            .malformed_client_frames
            .saturating_add(audit.malformed_client_frames);
        self.payload_displayed |= audit.payload_displayed;
        self.token_displayed |= audit.token_displayed;
        self.token_hash_displayed |= audit.token_hash_displayed;
        self.key_material_displayed |= audit.key_material_displayed;
        self.session_id_displayed |= audit.session_id_displayed;
        self.ciphertext_displayed |= audit.ciphertext_displayed;
        self.contents_displayed |= audit.contents_displayed;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AbuseResponseAction {
    category: &'static str,
    workflow: &'static str,
    exceeded_metrics: usize,
}

#[derive(Debug, Clone)]
struct HostedFleetAbuseResponsePlan {
    fleet_file: PathBuf,
    node_id: Option<String>,
    thresholds_file: Option<PathBuf>,
    relays: Vec<HostedFleetAbuseRelayPlan>,
    totals: HostedFleetAbuseResponsePlanTotals,
    threshold_report: AbuseThresholdReport,
    actions: Vec<AbuseResponseAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostedFleetAbuseResponsePlanExit {
    Success,
    ActionRecommended,
}

impl HostedFleetAbuseResponsePlanExit {
    fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::ActionRecommended => ExitCode::from(3),
        }
    }
}

fn hosted_fleet_abuse_response_plan_from_args(
    args: Vec<String>,
) -> Result<HostedFleetAbuseResponsePlanExit, String> {
    let parsed = parse_hosted_fleet_abuse_response_plan_args(args)?;
    let plan = hosted_fleet_abuse_response_plan(&parsed)?;
    if parsed.json {
        println!("{}", render_hosted_fleet_abuse_response_plan_json(&plan));
    } else {
        println!("{}", render_hosted_fleet_abuse_response_plan_text(&plan));
    }
    Ok(hosted_fleet_abuse_response_plan_exit(
        &plan,
        parsed.fail_on_action,
    ))
}

fn parse_hosted_fleet_abuse_response_plan_args(
    args: Vec<String>,
) -> Result<HostedFleetAbuseResponsePlanArgs, String> {
    let mut fleet_file = None::<PathBuf>;
    let mut node_id = None::<String>;
    let mut thresholds_file = None::<PathBuf>;
    let mut cli_thresholds = AbuseThresholds::default();
    let mut json = false;
    let mut fail_on_action = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_abuse_response_plan_usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_abuse_response_plan_usage());
                };
                node_id = Some(validate_dashboard_filter_id(value.to_string(), "node id")?);
            }
            "--thresholds-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_abuse_response_plan_usage());
                };
                if value.trim().is_empty() {
                    return Err(hosted_fleet_abuse_response_plan_usage());
                }
                thresholds_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--fail-on-action" => fail_on_action = true,
            "--help" | "-h" => return Err(hosted_fleet_abuse_response_plan_usage()),
            value if value.starts_with("--max-") => {
                index += 1;
                let Some(limit) = args.get(index) else {
                    return Err(hosted_fleet_abuse_response_plan_usage());
                };
                parse_abuse_threshold_option(&mut cli_thresholds, value, limit)?;
            }
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(hosted_fleet_abuse_response_plan_usage()),
        }
        index += 1;
    }

    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(hosted_fleet_abuse_response_plan_usage());
    };
    thresholds_file = thresholds_file.filter(|path| !path.as_os_str().is_empty());
    if thresholds_file.is_none() && !cli_thresholds.has_any() {
        return Err(hosted_fleet_abuse_response_plan_usage());
    }
    let abuse_thresholds = merged_abuse_thresholds(thresholds_file.as_deref(), cli_thresholds)?;
    if !abuse_thresholds.has_any() {
        return Err(hosted_fleet_abuse_response_plan_usage());
    }

    Ok(HostedFleetAbuseResponsePlanArgs {
        fleet_file,
        node_id,
        thresholds_file,
        abuse_thresholds,
        json,
        fail_on_action,
    })
}

fn hosted_fleet_abuse_response_plan_usage() -> String {
    "usage: conu-relay --hosted-fleet-abuse-response-plan --fleet-file <path> [--node <node-id>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-action]".to_string()
}

fn hosted_fleet_abuse_response_plan(
    args: &HostedFleetAbuseResponsePlanArgs,
) -> Result<HostedFleetAbuseResponsePlan, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    let mut relays = Vec::<HostedFleetAbuseRelayPlan>::new();
    let mut totals = HostedFleetAbuseResponsePlanTotals {
        relays: configs.len(),
        ..HostedFleetAbuseResponsePlanTotals::default()
    };

    for config in configs {
        let Some(abuse_dir) = config.abuse_dir else {
            continue;
        };
        let audit = audit_relay_abuse_dir(&abuse_dir, args.node_id.as_deref())
            .map_err(|error| error.to_string())?;
        totals.add(&audit);
        relays.push(HostedFleetAbuseRelayPlan {
            name: config.name,
            abuse_dir,
            audit,
        });
    }

    if relays.is_empty() {
        return Err(
            "--hosted-fleet-abuse-response-plan requires at least one fleet relay abuse_dir"
                .to_string(),
        );
    }

    let threshold_report = abuse_threshold_report_from_fleet_abuse_totals(
        &totals,
        args.abuse_thresholds,
        args.node_id.clone(),
    );
    let actions = abuse_response_actions(&threshold_report);

    Ok(HostedFleetAbuseResponsePlan {
        fleet_file: args.fleet_file.clone(),
        node_id: args.node_id.clone(),
        thresholds_file: args.thresholds_file.clone(),
        relays,
        totals,
        threshold_report,
        actions,
    })
}

fn abuse_threshold_report_from_fleet_abuse_totals(
    totals: &HostedFleetAbuseResponsePlanTotals,
    thresholds: AbuseThresholds,
    node_id: Option<String>,
) -> AbuseThresholdReport {
    build_abuse_threshold_report(
        "fleet",
        None,
        None,
        None,
        node_id,
        totals.abuse_records,
        None,
        thresholds,
        totals.admin_unauthorized,
        totals.admin_failed,
        totals.unauthorized_sessions,
        totals.credential_denied_sessions,
        totals.tenant_denied_sessions,
        totals.rate_limited_sessions,
        totals.session_expired,
        totals.quota_denied_forwards,
        totals.undelivered_forwards,
        totals.mailbox_rejected_forwards,
        totals.malformed_client_frames,
        totals.payload_displayed,
        totals.token_displayed,
        totals.token_hash_displayed,
        totals.key_material_displayed,
        totals.session_id_displayed,
        totals.ciphertext_displayed,
        totals.contents_displayed,
    )
}

fn abuse_response_actions(report: &AbuseThresholdReport) -> Vec<AbuseResponseAction> {
    let mut actions = Vec::new();
    push_abuse_response_action(
        &mut actions,
        "admin_access",
        "review_admin_access",
        &[
            (
                report.admin_unauthorized,
                report.thresholds.admin_unauthorized,
            ),
            (report.admin_failed, report.thresholds.admin_failed),
        ],
    );
    push_abuse_response_action(
        &mut actions,
        "credential_tenant_access",
        "review_credentials_and_tenants",
        &[
            (
                report.unauthorized_sessions,
                report.thresholds.unauthorized_sessions,
            ),
            (
                report.credential_denied_sessions,
                report.thresholds.credential_denied_sessions,
            ),
            (
                report.tenant_denied_sessions,
                report.thresholds.tenant_denied_sessions,
            ),
        ],
    );
    push_abuse_response_action(
        &mut actions,
        "traffic_pressure",
        "review_limits_and_client_behavior",
        &[
            (
                report.rate_limited_sessions,
                report.thresholds.rate_limited_sessions,
            ),
            (
                report.quota_denied_forwards,
                report.thresholds.quota_denied_forwards,
            ),
            (
                report.malformed_client_frames,
                report.thresholds.malformed_client_frames,
            ),
        ],
    );
    push_abuse_response_action(
        &mut actions,
        "delivery_health",
        "review_delivery_health",
        &[
            (report.session_expired, report.thresholds.session_expired),
            (
                report.undelivered_forwards,
                report.thresholds.undelivered_forwards,
            ),
        ],
    );
    push_abuse_response_action(
        &mut actions,
        "mailbox_pressure",
        "review_mailbox_capacity",
        &[(
            report.mailbox_rejected_forwards,
            report.thresholds.mailbox_rejected_forwards,
        )],
    );
    actions
}

fn push_abuse_response_action(
    actions: &mut Vec<AbuseResponseAction>,
    category: &'static str,
    workflow: &'static str,
    metrics: &[(u64, Option<u64>)],
) {
    let exceeded_metrics = metrics
        .iter()
        .filter(|(count, max)| threshold_exceeded(*count, *max))
        .count();
    if exceeded_metrics > 0 {
        actions.push(AbuseResponseAction {
            category,
            workflow,
            exceeded_metrics,
        });
    }
}

fn abuse_response_plan_status(plan: &HostedFleetAbuseResponsePlan) -> &'static str {
    if plan.actions.is_empty() {
        "ok"
    } else {
        "action_recommended"
    }
}

fn hosted_fleet_abuse_response_plan_exit(
    plan: &HostedFleetAbuseResponsePlan,
    fail_on_action: bool,
) -> HostedFleetAbuseResponsePlanExit {
    if fail_on_action && !plan.actions.is_empty() {
        HostedFleetAbuseResponsePlanExit::ActionRecommended
    } else {
        HostedFleetAbuseResponsePlanExit::Success
    }
}

#[derive(Debug, Clone)]
struct HostedFleetDashboardArgs {
    fleet_file: PathBuf,
    account_id: Option<String>,
    node_id: Option<String>,
    retention_policy_file: Option<PathBuf>,
    mailbox_retention_policy: MailboxRetentionPolicy,
    mailbox_ttl: Option<Duration>,
    thresholds_file: Option<PathBuf>,
    abuse_thresholds: AbuseThresholds,
    json: bool,
    fail_on_threshold: bool,
    fail_on_retention: bool,
}

#[derive(Debug, Clone)]
struct HostedFleetRelayConfig {
    name: String,
    credentials_file: Option<PathBuf>,
    tenants_file: Option<PathBuf>,
    session_state_dir: Option<PathBuf>,
    mailbox_dir: Option<PathBuf>,
    mailbox_ttl_seconds: Option<u64>,
    accounting_dir: Option<PathBuf>,
    abuse_dir: Option<PathBuf>,
}

impl HostedFleetRelayConfig {
    fn has_source(&self) -> bool {
        self.credentials_file.is_some()
            || self.tenants_file.is_some()
            || self.session_state_dir.is_some()
            || self.mailbox_dir.is_some()
            || self.accounting_dir.is_some()
            || self.abuse_dir.is_some()
    }
}

#[derive(Debug, Clone, Default)]
struct HostedFleetRelayConfigBuilder {
    name: Option<String>,
    credentials_file: Option<PathBuf>,
    tenants_file: Option<PathBuf>,
    session_state_dir: Option<PathBuf>,
    mailbox_dir: Option<PathBuf>,
    mailbox_ttl_seconds: Option<u64>,
    accounting_dir: Option<PathBuf>,
    abuse_dir: Option<PathBuf>,
}

impl HostedFleetRelayConfigBuilder {
    fn set(&mut self, base_dir: &Path, key: &str, value: &str, line: usize) -> Result<(), String> {
        match key {
            "name" => {
                self.name = Some(validate_dashboard_filter_id(
                    value.to_string(),
                    "relay name",
                )?);
            }
            "credentials_file" => {
                self.credentials_file = Some(resolve_fleet_path(base_dir, value, key, line)?);
            }
            "tenants_file" => {
                self.tenants_file = Some(resolve_fleet_path(base_dir, value, key, line)?);
            }
            "session_state_dir" => {
                self.session_state_dir = Some(resolve_fleet_path(base_dir, value, key, line)?);
            }
            "mailbox_dir" => {
                self.mailbox_dir = Some(resolve_fleet_path(base_dir, value, key, line)?);
            }
            "mailbox_ttl_seconds" => {
                let ttl = value.parse::<u64>().map_err(|_| {
                    format!(
                        "hosted fleet dashboard file line {line} mailbox_ttl_seconds must be an unsigned integer"
                    )
                })?;
                if ttl == 0 {
                    return Err(format!(
                        "hosted fleet dashboard file line {line} mailbox_ttl_seconds must be greater than zero"
                    ));
                }
                self.mailbox_ttl_seconds = Some(ttl);
            }
            "accounting_dir" => {
                self.accounting_dir = Some(resolve_fleet_path(base_dir, value, key, line)?);
            }
            "abuse_dir" => {
                self.abuse_dir = Some(resolve_fleet_path(base_dir, value, key, line)?);
            }
            _ => {
                return Err(format!(
                    "hosted fleet dashboard file line {line} uses unsupported relay key {key}"
                ));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<HostedFleetRelayConfig, String> {
        let name = self
            .name
            .ok_or_else(|| "hosted fleet dashboard relay entry is missing name".to_string())?;
        let relay = HostedFleetRelayConfig {
            name,
            credentials_file: self.credentials_file,
            tenants_file: self.tenants_file,
            session_state_dir: self.session_state_dir,
            mailbox_dir: self.mailbox_dir,
            mailbox_ttl_seconds: self.mailbox_ttl_seconds,
            accounting_dir: self.accounting_dir,
            abuse_dir: self.abuse_dir,
        };
        if !relay.has_source() {
            return Err(format!(
                "hosted fleet dashboard relay {} has no configured metadata source",
                relay.name
            ));
        }
        if relay.mailbox_ttl_seconds.is_some() && relay.mailbox_dir.is_none() {
            return Err(format!(
                "hosted fleet dashboard relay {} sets mailbox_ttl_seconds without mailbox_dir",
                relay.name
            ));
        }
        Ok(relay)
    }
}

#[derive(Debug, Clone, Default)]
struct HostedFleetDashboardFileGuards {
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetDashboardFileGuards {
    fn record_false(&mut self, key: &str, value: &str, line: usize) -> Result<bool, String> {
        let guard = match key {
            "payload_displayed" => &mut self.payload_displayed,
            "token_displayed" => &mut self.token_displayed,
            "token_hash_displayed" => &mut self.token_hash_displayed,
            "key_material_displayed" => &mut self.key_material_displayed,
            "session_id_displayed" => &mut self.session_id_displayed,
            "ciphertext_displayed" => &mut self.ciphertext_displayed,
            "contents_displayed" => &mut self.contents_displayed,
            _ => return Ok(false),
        };
        if value != "false" {
            return Err(format!(
                "hosted fleet dashboard file line {line} {key} must be false"
            ));
        }
        *guard = true;
        Ok(true)
    }

    fn validate(self) -> Result<(), String> {
        for (key, present) in [
            ("payload_displayed", self.payload_displayed),
            ("token_displayed", self.token_displayed),
            ("token_hash_displayed", self.token_hash_displayed),
            ("key_material_displayed", self.key_material_displayed),
            ("session_id_displayed", self.session_id_displayed),
            ("ciphertext_displayed", self.ciphertext_displayed),
            ("contents_displayed", self.contents_displayed),
        ] {
            if !present {
                return Err(format!(
                    "hosted fleet dashboard file requires {key} = false"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct HostedFleetRelaySnapshot {
    config: HostedFleetRelayConfig,
    credentials: Option<HostedCredentialAudit>,
    tenants: Option<HostedTenantAudit>,
    session_state: Option<RelaySessionAudit>,
    mailbox: Option<RelayMailboxAudit>,
    accounting: Option<RelayAccountingAudit>,
    abuse: Option<RelayAbuseAudit>,
}

#[derive(Debug, Clone, Default)]
struct HostedFleetDashboardTotals {
    relays: usize,
    credential_sources: usize,
    credentials: usize,
    active_credentials: usize,
    revoked_credentials: usize,
    expired_credentials: usize,
    credential_account_entries: usize,
    tenant_sources: usize,
    tenants: usize,
    active_tenants: usize,
    revoked_tenants: usize,
    tenant_nodes: usize,
    active_tenant_nodes: usize,
    revoked_tenant_nodes: usize,
    tenant_policies: usize,
    session_state_sources: usize,
    session_records: usize,
    active_session_records: usize,
    expired_session_records: usize,
    invalid_session_records: usize,
    mailbox_sources: usize,
    mailbox_nodes: usize,
    mailbox_records: usize,
    mailbox_invalid_records: usize,
    mailbox_bytes: u64,
    mailbox_expired_records: u64,
    mailbox_expired_bytes: u64,
    mailbox_retention_checks: usize,
    mailbox_retention_exceeded: usize,
    accounting_sources: usize,
    accounting_records: usize,
    sessions_authenticated: u64,
    sessions_resumed: u64,
    envelopes_sent: u64,
    bytes_sent: u64,
    envelopes_received: u64,
    bytes_received: u64,
    envelopes_mailboxed: u64,
    bytes_mailboxed: u64,
    abuse_sources: usize,
    abuse_records: usize,
    admin_unauthorized: u64,
    admin_failed: u64,
    unauthorized_sessions: u64,
    credential_denied_sessions: u64,
    tenant_denied_sessions: u64,
    rate_limited_sessions: u64,
    session_expired: u64,
    quota_denied_forwards: u64,
    undelivered_forwards: u64,
    mailbox_rejected_forwards: u64,
    malformed_client_frames: u64,
    payload_displayed: bool,
    token_displayed: bool,
    token_hash_displayed: bool,
    key_material_displayed: bool,
    session_id_displayed: bool,
    ciphertext_displayed: bool,
    contents_displayed: bool,
}

impl HostedFleetDashboardTotals {
    fn add(&mut self, relay: &HostedFleetRelaySnapshot) {
        self.relays += 1;
        if let Some(audit) = &relay.credentials {
            self.credential_sources += 1;
            self.credentials += audit.credentials;
            self.active_credentials += audit.active;
            self.revoked_credentials += audit.revoked;
            self.expired_credentials += audit.expired;
            self.credential_account_entries += audit.accounts;
            self.token_displayed |= audit.token_displayed;
            self.contents_displayed |= audit.contents_displayed;
        }
        if let Some(audit) = &relay.tenants {
            self.tenant_sources += 1;
            self.tenants += audit.tenants;
            self.active_tenants += audit.active_tenants;
            self.revoked_tenants += audit.revoked_tenants;
            self.tenant_nodes += audit.nodes;
            self.active_tenant_nodes += audit.active_nodes;
            self.revoked_tenant_nodes += audit.revoked_nodes;
            self.tenant_policies += audit.policies;
            self.token_displayed |= audit.token_displayed;
            self.key_material_displayed |= audit.key_material_displayed;
            self.contents_displayed |= audit.contents_displayed;
        }
        if let Some(audit) = &relay.session_state {
            self.session_state_sources += 1;
            self.session_records += audit.records;
            self.active_session_records += audit.active_records;
            self.expired_session_records += audit.expired_records;
            self.invalid_session_records += audit.invalid_records;
            self.payload_displayed |= audit.payload_displayed;
            self.token_displayed |= audit.token_displayed;
            self.token_hash_displayed |= audit.token_hash_displayed;
            self.key_material_displayed |= audit.key_material_displayed;
            self.session_id_displayed |= audit.session_id_displayed;
            self.ciphertext_displayed |= audit.ciphertext_displayed;
            self.contents_displayed |= audit.contents_displayed;
        }
        if let Some(audit) = &relay.mailbox {
            self.mailbox_sources += 1;
            self.mailbox_nodes += audit.nodes;
            self.mailbox_records += audit.records;
            self.mailbox_invalid_records += audit.invalid_records;
            self.mailbox_bytes = self.mailbox_bytes.saturating_add(audit.bytes);
            self.mailbox_expired_records = self
                .mailbox_expired_records
                .saturating_add(audit.expired_records.unwrap_or(0));
            self.mailbox_expired_bytes = self
                .mailbox_expired_bytes
                .saturating_add(audit.expired_bytes.unwrap_or(0));
            if audit.expired_records.is_some() {
                self.mailbox_retention_checks += 1;
                if audit.expired_records.unwrap_or(0) > 0 {
                    self.mailbox_retention_exceeded += 1;
                }
            }
            self.payload_displayed |= audit.payload_displayed;
            self.token_displayed |= audit.token_displayed;
            self.token_hash_displayed |= audit.token_hash_displayed;
            self.key_material_displayed |= audit.key_material_displayed;
            self.session_id_displayed |= audit.session_id_displayed;
            self.ciphertext_displayed |= audit.ciphertext_displayed;
            self.contents_displayed |= audit.contents_displayed;
        }
        if let Some(audit) = &relay.accounting {
            self.accounting_sources += 1;
            self.accounting_records += audit.records;
            self.sessions_authenticated = self
                .sessions_authenticated
                .saturating_add(audit.sessions_authenticated);
            self.sessions_resumed = self.sessions_resumed.saturating_add(audit.sessions_resumed);
            self.envelopes_sent = self.envelopes_sent.saturating_add(audit.envelopes_sent);
            self.bytes_sent = self.bytes_sent.saturating_add(audit.bytes_sent);
            self.envelopes_received = self
                .envelopes_received
                .saturating_add(audit.envelopes_received);
            self.bytes_received = self.bytes_received.saturating_add(audit.bytes_received);
            self.envelopes_mailboxed = self
                .envelopes_mailboxed
                .saturating_add(audit.envelopes_mailboxed);
            self.bytes_mailboxed = self.bytes_mailboxed.saturating_add(audit.bytes_mailboxed);
            self.payload_displayed |= audit.payload_displayed;
            self.token_displayed |= audit.token_displayed;
            self.token_hash_displayed |= audit.token_hash_displayed;
            self.key_material_displayed |= audit.key_material_displayed;
            self.session_id_displayed |= audit.session_id_displayed;
            self.ciphertext_displayed |= audit.ciphertext_displayed;
            self.contents_displayed |= audit.contents_displayed;
        }
        if let Some(audit) = &relay.abuse {
            self.abuse_sources += 1;
            self.abuse_records += audit.records;
            self.admin_unauthorized = self
                .admin_unauthorized
                .saturating_add(audit.admin_unauthorized);
            self.admin_failed = self.admin_failed.saturating_add(audit.admin_failed);
            self.unauthorized_sessions = self
                .unauthorized_sessions
                .saturating_add(audit.unauthorized_sessions);
            self.credential_denied_sessions = self
                .credential_denied_sessions
                .saturating_add(audit.credential_denied_sessions);
            self.tenant_denied_sessions = self
                .tenant_denied_sessions
                .saturating_add(audit.tenant_denied_sessions);
            self.rate_limited_sessions = self
                .rate_limited_sessions
                .saturating_add(audit.rate_limited_sessions);
            self.session_expired = self.session_expired.saturating_add(audit.session_expired);
            self.quota_denied_forwards = self
                .quota_denied_forwards
                .saturating_add(audit.quota_denied_forwards);
            self.undelivered_forwards = self
                .undelivered_forwards
                .saturating_add(audit.undelivered_forwards);
            self.mailbox_rejected_forwards = self
                .mailbox_rejected_forwards
                .saturating_add(audit.mailbox_rejected_forwards);
            self.malformed_client_frames = self
                .malformed_client_frames
                .saturating_add(audit.malformed_client_frames);
            self.payload_displayed |= audit.payload_displayed;
            self.token_displayed |= audit.token_displayed;
            self.token_hash_displayed |= audit.token_hash_displayed;
            self.key_material_displayed |= audit.key_material_displayed;
            self.session_id_displayed |= audit.session_id_displayed;
            self.ciphertext_displayed |= audit.ciphertext_displayed;
            self.contents_displayed |= audit.contents_displayed;
        }
    }
}

#[derive(Debug, Clone)]
struct HostedFleetDashboardSnapshot {
    fleet_file: PathBuf,
    account_id: Option<String>,
    node_id: Option<String>,
    mailbox_node_id: Option<String>,
    retention_policy_file: Option<PathBuf>,
    mailbox_ttl: Option<Duration>,
    thresholds_file: Option<PathBuf>,
    relays: Vec<HostedFleetRelaySnapshot>,
    totals: HostedFleetDashboardTotals,
    abuse_threshold_report: Option<AbuseThresholdReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostedFleetDashboardExit {
    Success,
    PolicyExceeded,
}

impl HostedFleetDashboardExit {
    fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::PolicyExceeded => ExitCode::from(3),
        }
    }
}

fn hosted_fleet_dashboard_exit(
    snapshot: &HostedFleetDashboardSnapshot,
    fail_on_threshold: bool,
    fail_on_retention: bool,
) -> HostedFleetDashboardExit {
    let abuse_exceeded = fail_on_threshold
        && snapshot
            .abuse_threshold_report
            .as_ref()
            .is_some_and(|report| report.threshold_exceeded > 0);
    let retention_exceeded = fail_on_retention && snapshot.totals.mailbox_retention_exceeded > 0;
    if abuse_exceeded || retention_exceeded {
        HostedFleetDashboardExit::PolicyExceeded
    } else {
        HostedFleetDashboardExit::Success
    }
}

fn hosted_fleet_dashboard_from_args(args: Vec<String>) -> Result<HostedFleetDashboardExit, String> {
    let parsed = parse_hosted_fleet_dashboard_args(args)?;
    let snapshot = hosted_fleet_dashboard_snapshot(&parsed)?;
    if parsed.json {
        println!("{}", render_hosted_fleet_dashboard_json(&snapshot));
    } else {
        println!("{}", render_hosted_fleet_dashboard_text(&snapshot));
    }
    Ok(hosted_fleet_dashboard_exit(
        &snapshot,
        parsed.fail_on_threshold,
        parsed.fail_on_retention,
    ))
}

fn parse_hosted_fleet_dashboard_args(
    args: Vec<String>,
) -> Result<HostedFleetDashboardArgs, String> {
    let mut fleet_file = None::<PathBuf>;
    let mut account_id = None::<String>;
    let mut node_id = None::<String>;
    let mut retention_policy_file = None::<PathBuf>;
    let mut mailbox_ttl = None::<Duration>;
    let mut thresholds_file = None::<PathBuf>;
    let mut cli_thresholds = AbuseThresholds::default();
    let mut json = false;
    let mut fail_on_threshold = false;
    let mut fail_on_retention = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--fleet-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_dashboard_usage());
                };
                fleet_file = Some(PathBuf::from(value));
            }
            "--account" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_dashboard_usage());
                };
                account_id = Some(value.to_string());
            }
            "--node" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_dashboard_usage());
                };
                node_id = Some(value.to_string());
            }
            "--retention-policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_dashboard_usage());
                };
                if value.trim().is_empty() {
                    return Err(hosted_fleet_dashboard_usage());
                }
                retention_policy_file = Some(PathBuf::from(value));
            }
            "--ttl-seconds" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_dashboard_usage());
                };
                mailbox_ttl = Some(parse_positive_cli_duration(value, "--ttl-seconds")?);
            }
            "--thresholds-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(hosted_fleet_dashboard_usage());
                };
                if value.trim().is_empty() {
                    return Err(hosted_fleet_dashboard_usage());
                }
                thresholds_file = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--fail-on-threshold" => fail_on_threshold = true,
            "--fail-on-retention" => fail_on_retention = true,
            "--help" | "-h" => return Err(hosted_fleet_dashboard_usage()),
            value if value.starts_with("--max-") => {
                index += 1;
                let Some(limit) = args.get(index) else {
                    return Err(hosted_fleet_dashboard_usage());
                };
                parse_abuse_threshold_option(&mut cli_thresholds, value, limit)?;
            }
            value if value.starts_with("--") => return Err(unknown_option_error()),
            _ => return Err(hosted_fleet_dashboard_usage()),
        }
        index += 1;
    }

    let Some(fleet_file) = fleet_file.filter(|path| !path.as_os_str().is_empty()) else {
        return Err(hosted_fleet_dashboard_usage());
    };
    let account_id = account_id
        .map(|value| validate_dashboard_filter_id(value, "account id"))
        .transpose()?;
    let node_id = node_id
        .map(|value| validate_dashboard_filter_id(value, "node id"))
        .transpose()?;
    retention_policy_file = retention_policy_file.filter(|path| !path.as_os_str().is_empty());
    let mailbox_retention_policy =
        merged_mailbox_retention_policy(retention_policy_file.as_deref(), None, None)?;
    thresholds_file = thresholds_file.filter(|path| !path.as_os_str().is_empty());
    let threshold_source_configured = thresholds_file.is_some() || cli_thresholds.has_any();
    if fail_on_threshold && !threshold_source_configured {
        return Err("--fail-on-threshold requires --thresholds-file or --max-*".to_string());
    }
    let abuse_thresholds = merged_abuse_thresholds(thresholds_file.as_deref(), cli_thresholds)?;
    if threshold_source_configured && !abuse_thresholds.has_any() {
        return Err(hosted_fleet_dashboard_usage());
    }

    Ok(HostedFleetDashboardArgs {
        fleet_file,
        account_id,
        node_id,
        retention_policy_file,
        mailbox_retention_policy,
        mailbox_ttl,
        thresholds_file,
        abuse_thresholds,
        json,
        fail_on_threshold,
        fail_on_retention,
    })
}

fn hosted_fleet_dashboard_usage() -> String {
    "usage: conu-relay --hosted-fleet-dashboard --fleet-file <path> [--account <account-id>] [--node <node-id>] [--ttl-seconds <seconds>] [--retention-policy-file <path>] [--thresholds-file <path>] [--max-<metric> <count>...] [--json] [--fail-on-threshold] [--fail-on-retention]".to_string()
}

fn hosted_fleet_dashboard_snapshot(
    args: &HostedFleetDashboardArgs,
) -> Result<HostedFleetDashboardSnapshot, String> {
    let configs = parse_hosted_fleet_dashboard_file(&args.fleet_file)?;
    if args.abuse_thresholds.has_any() && !configs.iter().any(|config| config.abuse_dir.is_some()) {
        return Err(
            "--thresholds-file and --max-* require at least one fleet relay abuse_dir".to_string(),
        );
    }
    let mailbox_source_configured = configs.iter().any(|config| config.mailbox_dir.is_some());
    let retention_source_configured =
        args.retention_policy_file.is_some() || args.mailbox_ttl.is_some();
    if retention_source_configured && !mailbox_source_configured {
        return Err(
            "--retention-policy-file and --ttl-seconds require at least one fleet relay mailbox_dir"
                .to_string(),
        );
    }
    if args.fail_on_retention && !mailbox_source_configured {
        return Err(
            "--fail-on-retention requires at least one fleet relay mailbox_dir".to_string(),
        );
    }
    let mailbox_node_id = args
        .node_id
        .clone()
        .or_else(|| args.mailbox_retention_policy.node_id.clone());
    let ttl_configured = args.mailbox_ttl.is_some()
        || args.mailbox_retention_policy.ttl.is_some()
        || configs
            .iter()
            .any(|config| config.mailbox_ttl_seconds.is_some());
    if args.fail_on_retention && !ttl_configured {
        return Err("--fail-on-retention requires --ttl-seconds, a retention policy ttl_seconds, or per-relay mailbox_ttl_seconds".to_string());
    }
    let mut relays = Vec::with_capacity(configs.len());
    let mut totals = HostedFleetDashboardTotals::default();

    for config in configs {
        let credentials = config
            .credentials_file
            .as_ref()
            .map(|path| audit_hosted_relay_credentials_file(path, args.account_id.as_deref()))
            .transpose()
            .map_err(|error| error.to_string())?;
        let tenants = config
            .tenants_file
            .as_ref()
            .map(|path| audit_hosted_tenants_file(path, args.account_id.as_deref()))
            .transpose()
            .map_err(|error| error.to_string())?;
        let session_state = config
            .session_state_dir
            .as_ref()
            .map(|path| audit_relay_session_state_dir(path, args.node_id.as_deref()))
            .transpose()
            .map_err(|error| error.to_string())?;
        let mailbox = config
            .mailbox_dir
            .as_ref()
            .map(|path| {
                let ttl = args
                    .mailbox_ttl
                    .or_else(|| config.mailbox_ttl_seconds.map(Duration::from_secs))
                    .or(args.mailbox_retention_policy.ttl);
                audit_relay_mailbox_dir(path, mailbox_node_id.as_deref(), ttl)
            })
            .transpose()
            .map_err(|error| error.to_string())?;
        let accounting = config
            .accounting_dir
            .as_ref()
            .map(|path| audit_relay_accounting_dir(path, args.node_id.as_deref()))
            .transpose()
            .map_err(|error| error.to_string())?;
        let abuse = config
            .abuse_dir
            .as_ref()
            .map(|path| audit_relay_abuse_dir(path, args.node_id.as_deref()))
            .transpose()
            .map_err(|error| error.to_string())?;

        let relay = HostedFleetRelaySnapshot {
            config,
            credentials,
            tenants,
            session_state,
            mailbox,
            accounting,
            abuse,
        };
        totals.add(&relay);
        relays.push(relay);
    }

    let abuse_threshold_report = if args.abuse_thresholds.has_any() {
        Some(abuse_threshold_report_from_fleet_totals(
            &totals,
            args.abuse_thresholds,
            args.account_id.clone(),
            args.node_id.clone(),
        ))
    } else {
        None
    };

    Ok(HostedFleetDashboardSnapshot {
        fleet_file: args.fleet_file.clone(),
        account_id: args.account_id.clone(),
        node_id: args.node_id.clone(),
        mailbox_node_id,
        retention_policy_file: args.retention_policy_file.clone(),
        mailbox_ttl: args.mailbox_ttl.or(args.mailbox_retention_policy.ttl),
        thresholds_file: args.thresholds_file.clone(),
        relays,
        totals,
        abuse_threshold_report,
    })
}

fn abuse_threshold_report_from_fleet_totals(
    totals: &HostedFleetDashboardTotals,
    thresholds: AbuseThresholds,
    account_id: Option<String>,
    node_id: Option<String>,
) -> AbuseThresholdReport {
    build_abuse_threshold_report(
        "fleet",
        None,
        None,
        account_id,
        node_id,
        totals.abuse_records,
        None,
        thresholds,
        totals.admin_unauthorized,
        totals.admin_failed,
        totals.unauthorized_sessions,
        totals.credential_denied_sessions,
        totals.tenant_denied_sessions,
        totals.rate_limited_sessions,
        totals.session_expired,
        totals.quota_denied_forwards,
        totals.undelivered_forwards,
        totals.mailbox_rejected_forwards,
        totals.malformed_client_frames,
        totals.payload_displayed,
        totals.token_displayed,
        totals.token_hash_displayed,
        totals.key_material_displayed,
        totals.session_id_displayed,
        totals.ciphertext_displayed,
        totals.contents_displayed,
    )
}

fn parse_hosted_fleet_dashboard_file(path: &Path) -> Result<Vec<HostedFleetRelayConfig>, String> {
    let contents = read_required_regular_cli_file(path, "hosted fleet dashboard")?;
    let base_dir = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut version_seen = false;
    let mut guards = HostedFleetDashboardFileGuards::default();
    let mut relays = Vec::<HostedFleetRelayConfig>::new();
    let mut current = None::<HostedFleetRelayConfigBuilder>;

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[relay]]" {
            if let Some(builder) = current.take() {
                push_hosted_fleet_relay(&mut relays, builder.finish()?)?;
            }
            current = Some(HostedFleetRelayConfigBuilder::default());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "hosted fleet dashboard file line {line_number} must use key = value"
            ));
        };
        let key = key.trim();
        let value = clean_config_value(value);

        if let Some(builder) = current.as_mut() {
            builder.set(base_dir, key, &value, line_number)?;
            continue;
        }

        if key == "version" {
            if value != HOSTED_FLEET_DASHBOARD_FILE_VERSION {
                return Err(format!(
                    "hosted fleet dashboard file line {line_number} has unsupported version"
                ));
            }
            version_seen = true;
            continue;
        }
        if guards.record_false(key, &value, line_number)? {
            continue;
        }
        return Err(format!(
            "hosted fleet dashboard file line {line_number} uses unsupported top-level key {key}"
        ));
    }

    if let Some(builder) = current.take() {
        push_hosted_fleet_relay(&mut relays, builder.finish()?)?;
    }
    if !version_seen {
        return Err("hosted fleet dashboard file requires version = \"1\"".to_string());
    }
    guards.validate()?;
    if relays.is_empty() {
        return Err(
            "hosted fleet dashboard file requires at least one [[relay]] entry".to_string(),
        );
    }
    Ok(relays)
}

fn push_hosted_fleet_relay(
    relays: &mut Vec<HostedFleetRelayConfig>,
    relay: HostedFleetRelayConfig,
) -> Result<(), String> {
    if relays.iter().any(|existing| existing.name == relay.name) {
        return Err(format!(
            "hosted fleet dashboard relay {} is duplicated",
            relay.name
        ));
    }
    relays.push(relay);
    Ok(())
}

fn resolve_fleet_path(
    base_dir: &Path,
    value: &str,
    key: &str,
    line: usize,
) -> Result<PathBuf, String> {
    if value.trim().is_empty() {
        return Err(format!(
            "hosted fleet dashboard file line {line} {key} cannot be empty"
        ));
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(base_dir.join(path))
    }
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
            value if value.starts_with("--") => return Err(unknown_option_error()),
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

fn mailbox_retention_status(totals: &HostedFleetDashboardTotals) -> &'static str {
    if totals.mailbox_retention_checks == 0 {
        "not_configured"
    } else if totals.mailbox_retention_exceeded > 0 {
        "exceeded"
    } else {
        "ok"
    }
}

fn render_hosted_fleet_dashboard_text(snapshot: &HostedFleetDashboardSnapshot) -> String {
    let totals = &snapshot.totals;
    let mut output = format!(
        r"conU hosted relay fleet dashboard snapshot

fleet file: {}
account: {}
node: {}
mailbox retention node: {}
retention policy file: {}
mailbox ttl seconds: {}
thresholds file: {}
relays: {}
credential sources: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
credential account entries: {}
tenant sources: {}
tenants: {}
active tenants: {}
revoked tenants: {}
tenant nodes: {}
active tenant nodes: {}
revoked tenant nodes: {}
hosted policies: {}
session-state sources: {}
session records: {}
active session records: {}
expired session records: {}
invalid session records: {}
mailbox sources: {}
mailbox nodes: {}
mailbox records: {}
mailbox invalid records: {}
mailbox bytes: {}
mailbox expired records: {}
mailbox expired bytes: {}
mailbox retention status: {}
mailbox retention checks: {}
mailbox retention exceeded: {}
accounting sources: {}
accounting records: {}
sessions authenticated: {}
sessions resumed: {}
envelopes sent: {}
bytes sent: {}
envelopes received: {}
bytes received: {}
envelopes mailboxed: {}
bytes mailboxed: {}
abuse sources: {}
abuse records: {}
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
abuse threshold status: {}
abuse threshold checks: {}
abuse threshold exceeded: {}

relay sources:",
        snapshot.fleet_file.display(),
        snapshot.account_id.as_deref().unwrap_or("all"),
        snapshot.node_id.as_deref().unwrap_or("all"),
        snapshot.mailbox_node_id.as_deref().unwrap_or("all"),
        optional_path_text(snapshot.retention_policy_file.as_deref()),
        optional_u64_text(snapshot.mailbox_ttl.map(|ttl| ttl.as_secs())),
        optional_path_text(snapshot.thresholds_file.as_deref()),
        totals.relays,
        totals.credential_sources,
        totals.credentials,
        totals.active_credentials,
        totals.revoked_credentials,
        totals.expired_credentials,
        totals.credential_account_entries,
        totals.tenant_sources,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.tenant_nodes,
        totals.active_tenant_nodes,
        totals.revoked_tenant_nodes,
        totals.tenant_policies,
        totals.session_state_sources,
        totals.session_records,
        totals.active_session_records,
        totals.expired_session_records,
        totals.invalid_session_records,
        totals.mailbox_sources,
        totals.mailbox_nodes,
        totals.mailbox_records,
        totals.mailbox_invalid_records,
        totals.mailbox_bytes,
        totals.mailbox_expired_records,
        totals.mailbox_expired_bytes,
        mailbox_retention_status(totals),
        totals.mailbox_retention_checks,
        totals.mailbox_retention_exceeded,
        totals.accounting_sources,
        totals.accounting_records,
        totals.sessions_authenticated,
        totals.sessions_resumed,
        totals.envelopes_sent,
        totals.bytes_sent,
        totals.envelopes_received,
        totals.bytes_received,
        totals.envelopes_mailboxed,
        totals.bytes_mailboxed,
        totals.abuse_sources,
        totals.abuse_records,
        totals.admin_unauthorized,
        totals.admin_failed,
        totals.unauthorized_sessions,
        totals.credential_denied_sessions,
        totals.tenant_denied_sessions,
        totals.rate_limited_sessions,
        totals.session_expired,
        totals.quota_denied_forwards,
        totals.undelivered_forwards,
        totals.mailbox_rejected_forwards,
        totals.malformed_client_frames,
        snapshot
            .abuse_threshold_report
            .as_ref()
            .map(abuse_threshold_status)
            .unwrap_or("not_configured"),
        snapshot
            .abuse_threshold_report
            .as_ref()
            .map(|report| report.threshold_checks)
            .unwrap_or(0),
        snapshot
            .abuse_threshold_report
            .as_ref()
            .map(|report| report.threshold_exceeded)
            .unwrap_or(0)
    );

    for relay in &snapshot.relays {
        output.push_str(&format!(
            "\n- {}: credentials {} tenants {} session-state {} mailbox {} accounting {} abuse {}",
            relay.config.name,
            yes_no(relay.credentials.is_some()),
            yes_no(relay.tenants.is_some()),
            yes_no(relay.session_state.is_some()),
            yes_no(relay.mailbox.is_some()),
            yes_no(relay.accounting.is_some()),
            yes_no(relay.abuse.is_some())
        ));
    }

    if let Some(report) = &snapshot.abuse_threshold_report {
        output.push_str("\n\nfleet abuse thresholds:");
        append_threshold_metric(
            &mut output,
            "admin unauthorized",
            report.admin_unauthorized,
            report.thresholds.admin_unauthorized,
        );
        append_threshold_metric(
            &mut output,
            "admin failed",
            report.admin_failed,
            report.thresholds.admin_failed,
        );
        append_threshold_metric(
            &mut output,
            "unauthorized sessions",
            report.unauthorized_sessions,
            report.thresholds.unauthorized_sessions,
        );
        append_threshold_metric(
            &mut output,
            "credential denied sessions",
            report.credential_denied_sessions,
            report.thresholds.credential_denied_sessions,
        );
        append_threshold_metric(
            &mut output,
            "tenant denied sessions",
            report.tenant_denied_sessions,
            report.thresholds.tenant_denied_sessions,
        );
        append_threshold_metric(
            &mut output,
            "rate limited sessions",
            report.rate_limited_sessions,
            report.thresholds.rate_limited_sessions,
        );
        append_threshold_metric(
            &mut output,
            "session expired",
            report.session_expired,
            report.thresholds.session_expired,
        );
        append_threshold_metric(
            &mut output,
            "quota denied forwards",
            report.quota_denied_forwards,
            report.thresholds.quota_denied_forwards,
        );
        append_threshold_metric(
            &mut output,
            "undelivered forwards",
            report.undelivered_forwards,
            report.thresholds.undelivered_forwards,
        );
        append_threshold_metric(
            &mut output,
            "mailbox rejected forwards",
            report.mailbox_rejected_forwards,
            report.thresholds.mailbox_rejected_forwards,
        );
        append_threshold_metric(
            &mut output,
            "malformed client frames",
            report.malformed_client_frames,
            report.thresholds.malformed_client_frames,
        );
    }

    output.push_str(&format!(
        r"

payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        yes_no(totals.payload_displayed),
        yes_no(totals.token_displayed),
        yes_no(totals.token_hash_displayed),
        yes_no(totals.key_material_displayed),
        yes_no(totals.session_id_displayed),
        yes_no(totals.ciphertext_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn render_hosted_fleet_dashboard_json(snapshot: &HostedFleetDashboardSnapshot) -> String {
    let relays = snapshot
        .relays
        .iter()
        .map(render_hosted_fleet_relay_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "snapshotted",
  "fleetFile": "{}",
  "accountId": {},
  "nodeId": {},
  "mailboxNodeId": {},
  "retentionPolicyFile": {},
  "mailboxTtlSeconds": {},
  "thresholdsFile": {},
  "totals": {},
  "abuseThresholdReport": {},
  "relays": [
{}
  ],
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        json_escape(&snapshot.fleet_file.display().to_string()),
        optional_string_json(snapshot.account_id.as_deref()),
        optional_string_json(snapshot.node_id.as_deref()),
        optional_string_json(snapshot.mailbox_node_id.as_deref()),
        optional_path_json(snapshot.retention_policy_file.as_deref()),
        optional_u64_json(snapshot.mailbox_ttl.map(|ttl| ttl.as_secs())),
        optional_path_json(snapshot.thresholds_file.as_deref()),
        render_hosted_fleet_totals_json(&snapshot.totals),
        snapshot
            .abuse_threshold_report
            .as_ref()
            .map(render_abuse_threshold_report_json)
            .unwrap_or_else(|| "null".to_string()),
        relays,
        bool_json(snapshot.totals.payload_displayed),
        bool_json(snapshot.totals.token_displayed),
        bool_json(snapshot.totals.token_hash_displayed),
        bool_json(snapshot.totals.key_material_displayed),
        bool_json(snapshot.totals.session_id_displayed),
        bool_json(snapshot.totals.ciphertext_displayed),
        bool_json(snapshot.totals.contents_displayed)
    )
}

fn render_hosted_fleet_totals_json(totals: &HostedFleetDashboardTotals) -> String {
    format!(
        r#"{{
    "relays": {},
    "credentialSources": {},
    "credentials": {},
    "activeCredentials": {},
    "revokedCredentials": {},
    "expiredCredentials": {},
    "credentialAccountEntries": {},
    "tenantSources": {},
    "tenants": {},
    "activeTenants": {},
    "revokedTenants": {},
    "tenantNodes": {},
    "activeTenantNodes": {},
    "revokedTenantNodes": {},
    "hostedPolicies": {},
    "sessionStateSources": {},
    "sessionRecords": {},
    "activeSessionRecords": {},
    "expiredSessionRecords": {},
    "invalidSessionRecords": {},
    "mailboxSources": {},
    "mailboxNodes": {},
    "mailboxRecords": {},
    "mailboxInvalidRecords": {},
    "mailboxBytes": {},
    "mailboxExpiredRecords": {},
    "mailboxExpiredBytes": {},
    "mailboxRetentionStatus": "{}",
    "mailboxRetentionChecks": {},
    "mailboxRetentionExceeded": {},
    "accountingSources": {},
    "accountingRecords": {},
    "sessionsAuthenticated": {},
    "sessionsResumed": {},
    "envelopesSent": {},
    "bytesSent": {},
    "envelopesReceived": {},
    "bytesReceived": {},
    "envelopesMailboxed": {},
    "bytesMailboxed": {},
    "abuseSources": {},
    "abuseRecords": {},
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
  }}"#,
        totals.relays,
        totals.credential_sources,
        totals.credentials,
        totals.active_credentials,
        totals.revoked_credentials,
        totals.expired_credentials,
        totals.credential_account_entries,
        totals.tenant_sources,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.tenant_nodes,
        totals.active_tenant_nodes,
        totals.revoked_tenant_nodes,
        totals.tenant_policies,
        totals.session_state_sources,
        totals.session_records,
        totals.active_session_records,
        totals.expired_session_records,
        totals.invalid_session_records,
        totals.mailbox_sources,
        totals.mailbox_nodes,
        totals.mailbox_records,
        totals.mailbox_invalid_records,
        totals.mailbox_bytes,
        totals.mailbox_expired_records,
        totals.mailbox_expired_bytes,
        mailbox_retention_status(totals),
        totals.mailbox_retention_checks,
        totals.mailbox_retention_exceeded,
        totals.accounting_sources,
        totals.accounting_records,
        totals.sessions_authenticated,
        totals.sessions_resumed,
        totals.envelopes_sent,
        totals.bytes_sent,
        totals.envelopes_received,
        totals.bytes_received,
        totals.envelopes_mailboxed,
        totals.bytes_mailboxed,
        totals.abuse_sources,
        totals.abuse_records,
        totals.admin_unauthorized,
        totals.admin_failed,
        totals.unauthorized_sessions,
        totals.credential_denied_sessions,
        totals.tenant_denied_sessions,
        totals.rate_limited_sessions,
        totals.session_expired,
        totals.quota_denied_forwards,
        totals.undelivered_forwards,
        totals.mailbox_rejected_forwards,
        totals.malformed_client_frames
    )
}

fn render_hosted_fleet_abuse_response_plan_text(plan: &HostedFleetAbuseResponsePlan) -> String {
    let totals = &plan.totals;
    let report = &plan.threshold_report;
    let mut output = format!(
        r"conU hosted fleet abuse response plan

status: {}
fleet file: {}
node: {}
thresholds file: {}
relays: {}
abuse sources: {}
abuse records: {}
threshold checks: {}
threshold exceeded: {}
action categories: {}
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
",
        abuse_response_plan_status(plan),
        plan.fleet_file.display(),
        plan.node_id.as_deref().unwrap_or("all"),
        optional_path_text(plan.thresholds_file.as_deref()),
        totals.relays,
        totals.abuse_sources,
        totals.abuse_records,
        report.threshold_checks,
        report.threshold_exceeded,
        plan.actions.len(),
        totals.admin_unauthorized,
        totals.admin_failed,
        totals.unauthorized_sessions,
        totals.credential_denied_sessions,
        totals.tenant_denied_sessions,
        totals.rate_limited_sessions,
        totals.session_expired,
        totals.quota_denied_forwards,
        totals.undelivered_forwards,
        totals.mailbox_rejected_forwards,
        totals.malformed_client_frames,
    );

    output.push_str("\nthresholds:\n");
    append_threshold_metric(
        &mut output,
        "admin unauthorized",
        report.admin_unauthorized,
        report.thresholds.admin_unauthorized,
    );
    append_threshold_metric(
        &mut output,
        "admin failed",
        report.admin_failed,
        report.thresholds.admin_failed,
    );
    append_threshold_metric(
        &mut output,
        "unauthorized sessions",
        report.unauthorized_sessions,
        report.thresholds.unauthorized_sessions,
    );
    append_threshold_metric(
        &mut output,
        "credential denied sessions",
        report.credential_denied_sessions,
        report.thresholds.credential_denied_sessions,
    );
    append_threshold_metric(
        &mut output,
        "tenant denied sessions",
        report.tenant_denied_sessions,
        report.thresholds.tenant_denied_sessions,
    );
    append_threshold_metric(
        &mut output,
        "rate limited sessions",
        report.rate_limited_sessions,
        report.thresholds.rate_limited_sessions,
    );
    append_threshold_metric(
        &mut output,
        "session expired",
        report.session_expired,
        report.thresholds.session_expired,
    );
    append_threshold_metric(
        &mut output,
        "quota denied forwards",
        report.quota_denied_forwards,
        report.thresholds.quota_denied_forwards,
    );
    append_threshold_metric(
        &mut output,
        "undelivered forwards",
        report.undelivered_forwards,
        report.thresholds.undelivered_forwards,
    );
    append_threshold_metric(
        &mut output,
        "mailbox rejected forwards",
        report.mailbox_rejected_forwards,
        report.thresholds.mailbox_rejected_forwards,
    );
    append_threshold_metric(
        &mut output,
        "malformed client frames",
        report.malformed_client_frames,
        report.thresholds.malformed_client_frames,
    );

    output.push_str("\nrecommended actions:");
    if plan.actions.is_empty() {
        output.push_str("\n- none");
    } else {
        for action in &plan.actions {
            output.push_str(&format!(
                "\n- {}: workflow={} exceeded_metrics={}",
                action.category, action.workflow, action.exceeded_metrics
            ));
        }
    }

    output.push_str("\n\nabuse sources:");
    for relay in &plan.relays {
        output.push_str(&format!(
            "\n- {}: records {} abuse_dir {}",
            relay.name,
            relay.audit.records,
            relay.abuse_dir.display()
        ));
    }

    output.push_str(&format!(
        r"

payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        yes_no(totals.payload_displayed),
        yes_no(totals.token_displayed),
        yes_no(totals.token_hash_displayed),
        yes_no(totals.key_material_displayed),
        yes_no(totals.session_id_displayed),
        yes_no(totals.ciphertext_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn render_hosted_fleet_abuse_response_plan_json(plan: &HostedFleetAbuseResponsePlan) -> String {
    let actions = plan
        .actions
        .iter()
        .map(render_abuse_response_action_json)
        .collect::<Vec<_>>()
        .join(",\n");
    let relays = plan
        .relays
        .iter()
        .map(render_hosted_fleet_abuse_relay_plan_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "{}",
  "fleetFile": "{}",
  "nodeId": {},
  "thresholdsFile": {},
  "totals": {},
  "thresholdReport": {},
  "actions": [
{}
  ],
  "relays": [
{}
  ],
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        abuse_response_plan_status(plan),
        json_escape(&plan.fleet_file.display().to_string()),
        optional_string_json(plan.node_id.as_deref()),
        optional_path_json(plan.thresholds_file.as_deref()),
        render_hosted_fleet_abuse_response_totals_json(&plan.totals, plan.actions.len()),
        render_abuse_threshold_report_json(&plan.threshold_report),
        actions,
        relays,
        bool_json(plan.totals.payload_displayed),
        bool_json(plan.totals.token_displayed),
        bool_json(plan.totals.token_hash_displayed),
        bool_json(plan.totals.key_material_displayed),
        bool_json(plan.totals.session_id_displayed),
        bool_json(plan.totals.ciphertext_displayed),
        bool_json(plan.totals.contents_displayed)
    )
}

fn render_hosted_fleet_abuse_response_totals_json(
    totals: &HostedFleetAbuseResponsePlanTotals,
    action_categories: usize,
) -> String {
    format!(
        r#"{{
    "relays": {},
    "abuseSources": {},
    "abuseRecords": {},
    "actionCategories": {},
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
  }}"#,
        totals.relays,
        totals.abuse_sources,
        totals.abuse_records,
        action_categories,
        totals.admin_unauthorized,
        totals.admin_failed,
        totals.unauthorized_sessions,
        totals.credential_denied_sessions,
        totals.tenant_denied_sessions,
        totals.rate_limited_sessions,
        totals.session_expired,
        totals.quota_denied_forwards,
        totals.undelivered_forwards,
        totals.mailbox_rejected_forwards,
        totals.malformed_client_frames
    )
}

fn render_abuse_response_action_json(action: &AbuseResponseAction) -> String {
    format!(
        r#"    {{
      "category": "{}",
      "workflow": "{}",
      "exceededMetrics": {}
    }}"#,
        action.category, action.workflow, action.exceeded_metrics
    )
}

fn render_hosted_fleet_abuse_relay_plan_json(relay: &HostedFleetAbuseRelayPlan) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "abuseDir": {},
      "abuse": {},
      "payloadDisplayed": {},
      "tokenDisplayed": {},
      "tokenHashDisplayed": {},
      "keyMaterialDisplayed": {},
      "sessionIdDisplayed": {},
      "ciphertextDisplayed": {},
      "contentsDisplayed": {}
    }}"#,
        json_escape(&relay.name),
        optional_path_json(Some(relay.abuse_dir.as_path())),
        render_dashboard_abuse_json(Some(&relay.audit)),
        bool_json(relay.audit.payload_displayed),
        bool_json(relay.audit.token_displayed),
        bool_json(relay.audit.token_hash_displayed),
        bool_json(relay.audit.key_material_displayed),
        bool_json(relay.audit.session_id_displayed),
        bool_json(relay.audit.ciphertext_displayed),
        bool_json(relay.audit.contents_displayed)
    )
}

fn render_hosted_fleet_relay_json(relay: &HostedFleetRelaySnapshot) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "sources": {{
        "credentialsFile": {},
        "tenantsFile": {},
        "sessionStateDir": {},
        "mailboxDir": {},
        "mailboxTtlSeconds": {},
        "accountingDir": {},
        "abuseDir": {}
      }},
      "credentials": {},
      "tenants": {},
      "sessionState": {},
      "mailbox": {},
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
        json_escape(&relay.config.name),
        optional_path_json(relay.config.credentials_file.as_deref()),
        optional_path_json(relay.config.tenants_file.as_deref()),
        optional_path_json(relay.config.session_state_dir.as_deref()),
        optional_path_json(relay.config.mailbox_dir.as_deref()),
        optional_u64_json(relay.config.mailbox_ttl_seconds),
        optional_path_json(relay.config.accounting_dir.as_deref()),
        optional_path_json(relay.config.abuse_dir.as_deref()),
        render_dashboard_credentials_json(relay.credentials.as_ref()),
        render_dashboard_tenants_json(relay.tenants.as_ref()),
        render_readiness_session_state_json(relay.session_state.as_ref()),
        render_readiness_mailbox_json(relay.mailbox.as_ref()),
        render_dashboard_accounting_json(relay.accounting.as_ref()),
        render_dashboard_abuse_json(relay.abuse.as_ref()),
        bool_json(hosted_fleet_relay_payload_displayed(relay)),
        bool_json(hosted_fleet_relay_token_displayed(relay)),
        bool_json(hosted_fleet_relay_token_hash_displayed(relay)),
        bool_json(hosted_fleet_relay_key_material_displayed(relay)),
        bool_json(hosted_fleet_relay_session_id_displayed(relay)),
        bool_json(hosted_fleet_relay_ciphertext_displayed(relay)),
        bool_json(hosted_fleet_relay_contents_displayed(relay))
    )
}

fn hosted_fleet_relay_payload_displayed(relay: &HostedFleetRelaySnapshot) -> bool {
    relay
        .session_state
        .as_ref()
        .is_some_and(|audit| audit.payload_displayed)
        || relay
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
        || relay
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
        || relay
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.payload_displayed)
}

fn hosted_fleet_relay_token_displayed(relay: &HostedFleetRelaySnapshot) -> bool {
    relay
        .credentials
        .as_ref()
        .is_some_and(|audit| audit.token_displayed)
        || relay
            .tenants
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || relay
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || relay
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || relay
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
        || relay
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.token_displayed)
}

fn hosted_fleet_relay_token_hash_displayed(relay: &HostedFleetRelaySnapshot) -> bool {
    relay
        .session_state
        .as_ref()
        .is_some_and(|audit| audit.token_hash_displayed)
        || relay
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
        || relay
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
        || relay
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.token_hash_displayed)
}

fn hosted_fleet_relay_key_material_displayed(relay: &HostedFleetRelaySnapshot) -> bool {
    relay
        .tenants
        .as_ref()
        .is_some_and(|audit| audit.key_material_displayed)
        || relay
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || relay
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || relay
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
        || relay
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.key_material_displayed)
}

fn hosted_fleet_relay_session_id_displayed(relay: &HostedFleetRelaySnapshot) -> bool {
    relay
        .session_state
        .as_ref()
        .is_some_and(|audit| audit.session_id_displayed)
        || relay
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
        || relay
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
        || relay
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.session_id_displayed)
}

fn hosted_fleet_relay_ciphertext_displayed(relay: &HostedFleetRelaySnapshot) -> bool {
    relay
        .session_state
        .as_ref()
        .is_some_and(|audit| audit.ciphertext_displayed)
        || relay
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
        || relay
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
        || relay
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.ciphertext_displayed)
}

fn hosted_fleet_relay_contents_displayed(relay: &HostedFleetRelaySnapshot) -> bool {
    relay
        .credentials
        .as_ref()
        .is_some_and(|audit| audit.contents_displayed)
        || relay
            .tenants
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || relay
            .session_state
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || relay
            .mailbox
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || relay
            .accounting
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
        || relay
            .abuse
            .as_ref()
            .is_some_and(|audit| audit.contents_displayed)
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

fn render_hosted_account_suspend_text(suspension: &HostedAccountSuspension) -> String {
    format!(
        r"conU hosted account suspension

status: suspended
account: {}
credentials file: {}
tenants file: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
accounts: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
tenant policies: {}
payload displayed: no
token displayed: {}
token hash displayed: no
key material displayed: {}
contents displayed: {}",
        suspension.account_id,
        suspension.credentials_file.display(),
        suspension.tenants_file.display(),
        suspension.credentials,
        suspension.active,
        suspension.revoked,
        suspension.expired,
        suspension.accounts,
        suspension.tenants,
        suspension.active_tenants,
        suspension.revoked_tenants,
        suspension.nodes,
        suspension.active_nodes,
        suspension.revoked_nodes,
        suspension.tenant_policies,
        yes_no(suspension.token_displayed),
        yes_no(suspension.key_material_displayed),
        yes_no(suspension.contents_displayed)
    )
}

fn render_hosted_account_suspend_json(suspension: &HostedAccountSuspension) -> String {
    format!(
        r#"{{
  "status": "suspended",
  "accountId": "{}",
  "credentialsFile": "{}",
  "tenantsFile": "{}",
  "credentials": {},
  "active": {},
  "revoked": {},
  "expired": {},
  "accounts": {},
  "tenants": {},
  "activeTenants": {},
  "revokedTenants": {},
  "nodes": {},
  "activeNodes": {},
  "revokedNodes": {},
  "tenantPolicies": {},
  "payloadDisplayed": false,
  "tokenDisplayed": {},
  "tokenHashDisplayed": false,
  "keyMaterialDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        json_escape(&suspension.account_id),
        json_escape(&suspension.credentials_file.display().to_string()),
        json_escape(&suspension.tenants_file.display().to_string()),
        suspension.credentials,
        suspension.active,
        suspension.revoked,
        suspension.expired,
        suspension.accounts,
        suspension.tenants,
        suspension.active_tenants,
        suspension.revoked_tenants,
        suspension.nodes,
        suspension.active_nodes,
        suspension.revoked_nodes,
        suspension.tenant_policies,
        bool_json(suspension.token_displayed),
        bool_json(suspension.key_material_displayed),
        bool_json(suspension.contents_displayed)
    )
}

fn render_hosted_fleet_account_audit_text(report: &HostedFleetAccountAuditReport) -> String {
    let totals = &report.totals;
    let mut output = format!(
        r"conU hosted relay fleet account audit

status: {}
account: {}
node: {}
fleet file: {}
relays: {}
account sources: {}
credential sources: {}
tenant sources: {}
warnings: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
accounts: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
tenant policies: {}

relay account sources:",
        hosted_fleet_account_audit_status(report),
        report.account_id,
        report.node_id.as_deref().unwrap_or("all"),
        report.fleet_file.display(),
        totals.relays,
        totals.account_sources,
        totals.credential_sources,
        totals.tenant_sources,
        totals.warnings,
        totals.credentials,
        totals.active,
        totals.revoked,
        totals.expired,
        totals.accounts,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    );

    for relay in &report.relays {
        let warnings = if relay.warnings.is_empty() {
            "none".to_string()
        } else {
            relay.warnings.join(",")
        };
        output.push_str(&format!(
            "\n- {}: credentials {} tenants {} active credentials {} active tenants {} active nodes {} warnings {}",
            relay.name,
            optional_path_text(relay.credentials_file.as_deref()),
            optional_path_text(relay.tenants_file.as_deref()),
            relay.active,
            relay.active_tenants,
            relay.active_nodes,
            warnings
        ));
    }

    output.push_str(&format!(
        r"

payload displayed: no
token displayed: {}
token hash displayed: no
key material displayed: {}
session id displayed: no
ciphertext displayed: no
contents displayed: {}",
        yes_no(totals.token_displayed),
        yes_no(totals.key_material_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn hosted_fleet_account_audit_status(report: &HostedFleetAccountAuditReport) -> &'static str {
    if report.totals.warnings == 0 {
        "ok"
    } else {
        "warning"
    }
}

fn render_hosted_fleet_account_audit_json(report: &HostedFleetAccountAuditReport) -> String {
    let relays = report
        .relays
        .iter()
        .map(render_hosted_fleet_account_audit_relay_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "{}",
  "accountId": "{}",
  "nodeId": {},
  "fleetFile": "{}",
  "totals": {},
  "relays": [
{}
  ],
  "payloadDisplayed": false,
  "tokenDisplayed": {},
  "tokenHashDisplayed": false,
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": false,
  "ciphertextDisplayed": false,
  "contentsDisplayed": {}
}}"#,
        hosted_fleet_account_audit_status(report),
        json_escape(&report.account_id),
        optional_string_json(report.node_id.as_deref()),
        json_escape(&report.fleet_file.display().to_string()),
        render_hosted_fleet_account_audit_totals_json(&report.totals),
        relays,
        bool_json(report.totals.token_displayed),
        bool_json(report.totals.key_material_displayed),
        bool_json(report.totals.contents_displayed)
    )
}

fn render_hosted_fleet_account_audit_totals_json(totals: &HostedFleetAccountAuditTotals) -> String {
    format!(
        r#"{{
    "relays": {},
    "accountSources": {},
    "credentialSources": {},
    "tenantSources": {},
    "warnings": {},
    "credentials": {},
    "activeCredentials": {},
    "revokedCredentials": {},
    "expiredCredentials": {},
    "accounts": {},
    "tenants": {},
    "activeTenants": {},
    "revokedTenants": {},
    "nodes": {},
    "activeNodes": {},
    "revokedNodes": {},
    "tenantPolicies": {}
  }}"#,
        totals.relays,
        totals.account_sources,
        totals.credential_sources,
        totals.tenant_sources,
        totals.warnings,
        totals.credentials,
        totals.active,
        totals.revoked,
        totals.expired,
        totals.accounts,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    )
}

fn render_hosted_fleet_account_audit_relay_json(
    relay: &HostedFleetAccountAuditRelayReport,
) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "credentialsFile": {},
      "tenantsFile": {},
      "warnings": {},
      "credentials": {},
      "activeCredentials": {},
      "revokedCredentials": {},
      "expiredCredentials": {},
      "accounts": {},
      "tenants": {},
      "activeTenants": {},
      "revokedTenants": {},
      "nodes": {},
      "activeNodes": {},
      "revokedNodes": {},
      "tenantPolicies": {},
      "payloadDisplayed": false,
      "tokenDisplayed": {},
      "tokenHashDisplayed": false,
      "keyMaterialDisplayed": {},
      "sessionIdDisplayed": false,
      "ciphertextDisplayed": false,
      "contentsDisplayed": {}
    }}"#,
        json_escape(&relay.name),
        optional_path_json(relay.credentials_file.as_deref()),
        optional_path_json(relay.tenants_file.as_deref()),
        render_warning_array_json(&relay.warnings),
        relay.credentials,
        relay.active,
        relay.revoked,
        relay.expired,
        relay.accounts,
        relay.tenants,
        relay.active_tenants,
        relay.revoked_tenants,
        relay.nodes,
        relay.active_nodes,
        relay.revoked_nodes,
        relay.tenant_policies,
        bool_json(relay.token_displayed),
        bool_json(relay.key_material_displayed),
        bool_json(relay.contents_displayed)
    )
}

fn render_warning_array_json(warnings: &[&'static str]) -> String {
    format!(
        "[{}]",
        warnings
            .iter()
            .map(|warning| format!(r#""{}""#, json_escape(warning)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn render_hosted_fleet_account_suspend_text(report: &HostedFleetAccountSuspensionReport) -> String {
    let status = if report.dry_run {
        "would_suspend"
    } else {
        "suspended"
    };
    let mode = if report.dry_run {
        "dry-run"
    } else {
        "confirmed"
    };
    let totals = &report.totals;
    let mut output = format!(
        r"conU hosted relay fleet account suspension

status: {}
mode: {}
account: {}
node: {}
fleet file: {}
relays: {}
account sources: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
accounts: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
tenant policies: {}

relay account sources:",
        status,
        mode,
        report.account_id,
        report.node_id.as_deref().unwrap_or("all"),
        report.fleet_file.display(),
        totals.relays,
        totals.account_sources,
        totals.credentials,
        totals.active,
        totals.revoked,
        totals.expired,
        totals.accounts,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    );

    for relay in &report.relays {
        output.push_str(&format!(
            "\n- {}: credentials {} tenants {} active credentials {} revoked credentials {} active tenants {} active nodes {}",
            relay.name,
            relay.credentials_file.display(),
            relay.tenants_file.display(),
            relay.active,
            relay.revoked,
            relay.active_tenants,
            relay.active_nodes
        ));
    }

    output.push_str(&format!(
        r"

payload displayed: no
token displayed: {}
token hash displayed: no
key material displayed: {}
session id displayed: no
ciphertext displayed: no
contents displayed: {}",
        yes_no(totals.token_displayed),
        yes_no(totals.key_material_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn render_hosted_fleet_account_suspend_json(report: &HostedFleetAccountSuspensionReport) -> String {
    let status = if report.dry_run {
        "would_suspend"
    } else {
        "suspended"
    };
    let relays = report
        .relays
        .iter()
        .map(render_hosted_fleet_account_suspend_relay_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "{}",
  "mode": "{}",
  "accountId": "{}",
  "nodeId": {},
  "fleetFile": "{}",
  "dryRun": {},
  "confirmed": {},
  "totals": {},
  "relays": [
{}
  ],
  "payloadDisplayed": false,
  "tokenDisplayed": {},
  "tokenHashDisplayed": false,
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": false,
  "ciphertextDisplayed": false,
  "contentsDisplayed": {}
}}"#,
        status,
        if report.dry_run {
            "dry-run"
        } else {
            "confirmed"
        },
        json_escape(&report.account_id),
        optional_string_json(report.node_id.as_deref()),
        json_escape(&report.fleet_file.display().to_string()),
        bool_json(report.dry_run),
        bool_json(!report.dry_run),
        render_hosted_fleet_account_suspend_totals_json(&report.totals),
        relays,
        bool_json(report.totals.token_displayed),
        bool_json(report.totals.key_material_displayed),
        bool_json(report.totals.contents_displayed)
    )
}

fn render_hosted_fleet_account_suspend_totals_json(
    totals: &HostedFleetAccountSuspensionTotals,
) -> String {
    format!(
        r#"{{
    "relays": {},
    "accountSources": {},
    "credentials": {},
    "activeCredentials": {},
    "revokedCredentials": {},
    "expiredCredentials": {},
    "accounts": {},
    "tenants": {},
    "activeTenants": {},
    "revokedTenants": {},
    "nodes": {},
    "activeNodes": {},
    "revokedNodes": {},
    "tenantPolicies": {}
  }}"#,
        totals.relays,
        totals.account_sources,
        totals.credentials,
        totals.active,
        totals.revoked,
        totals.expired,
        totals.accounts,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    )
}

fn render_hosted_fleet_account_suspend_relay_json(
    relay: &HostedFleetAccountSuspensionRelayReport,
) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "credentialsFile": "{}",
      "tenantsFile": "{}",
      "credentials": {},
      "activeCredentials": {},
      "revokedCredentials": {},
      "expiredCredentials": {},
      "accounts": {},
      "tenants": {},
      "activeTenants": {},
      "revokedTenants": {},
      "nodes": {},
      "activeNodes": {},
      "revokedNodes": {},
      "tenantPolicies": {},
      "payloadDisplayed": false,
      "tokenDisplayed": {},
      "tokenHashDisplayed": false,
      "keyMaterialDisplayed": {},
      "sessionIdDisplayed": false,
      "ciphertextDisplayed": false,
      "contentsDisplayed": {}
    }}"#,
        json_escape(&relay.name),
        json_escape(&relay.credentials_file.display().to_string()),
        json_escape(&relay.tenants_file.display().to_string()),
        relay.credentials,
        relay.active,
        relay.revoked,
        relay.expired,
        relay.accounts,
        relay.tenants,
        relay.active_tenants,
        relay.revoked_tenants,
        relay.nodes,
        relay.active_nodes,
        relay.revoked_nodes,
        relay.tenant_policies,
        bool_json(relay.token_displayed),
        bool_json(relay.key_material_displayed),
        bool_json(relay.contents_displayed)
    )
}

fn render_hosted_fleet_credential_revoke_text(
    report: &HostedFleetCredentialRevokeReport,
) -> String {
    let status = if report.dry_run {
        "would_revoke"
    } else {
        "revoked"
    };
    let mode = if report.dry_run {
        "dry-run"
    } else {
        "confirmed"
    };
    let totals = &report.totals;
    let mut output = format!(
        r"conU hosted relay fleet credential revoke

status: {}
action: revoke
mode: {}
account: {}
node: {}
fleet file: {}
relays: {}
credential sources: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
accounts: {}

relay credential sources:",
        status,
        mode,
        report.account_id,
        report.node_id,
        report.fleet_file.display(),
        totals.relays,
        totals.credential_sources,
        totals.credentials,
        totals.active,
        totals.revoked,
        totals.expired,
        totals.accounts
    );

    for relay in &report.relays {
        output.push_str(&format!(
            "\n- {}: credentials {} active credentials {} revoked credentials {} expired credentials {} accounts {}",
            relay.name,
            relay.credentials_file.display(),
            relay.active,
            relay.revoked,
            relay.expired,
            relay.accounts
        ));
    }

    output.push_str(&format!(
        r"

payload displayed: no
token displayed: {}
token hash displayed: no
key material displayed: no
session id displayed: no
ciphertext displayed: no
contents displayed: {}",
        yes_no(totals.token_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn render_hosted_fleet_credential_revoke_json(
    report: &HostedFleetCredentialRevokeReport,
) -> String {
    let status = if report.dry_run {
        "would_revoke"
    } else {
        "revoked"
    };
    let relays = report
        .relays
        .iter()
        .map(render_hosted_fleet_credential_revoke_relay_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "{}",
  "action": "revoke",
  "mode": "{}",
  "accountId": "{}",
  "nodeId": "{}",
  "fleetFile": "{}",
  "dryRun": {},
  "confirmed": {},
  "totals": {},
  "relays": [
{}
  ],
  "payloadDisplayed": false,
  "tokenDisplayed": {},
  "tokenHashDisplayed": false,
  "keyMaterialDisplayed": false,
  "sessionIdDisplayed": false,
  "ciphertextDisplayed": false,
  "contentsDisplayed": {}
}}"#,
        status,
        if report.dry_run {
            "dry-run"
        } else {
            "confirmed"
        },
        json_escape(&report.account_id),
        json_escape(&report.node_id),
        json_escape(&report.fleet_file.display().to_string()),
        bool_json(report.dry_run),
        bool_json(!report.dry_run),
        render_hosted_fleet_credential_revoke_totals_json(&report.totals),
        relays,
        bool_json(report.totals.token_displayed),
        bool_json(report.totals.contents_displayed)
    )
}

fn render_hosted_fleet_credential_revoke_totals_json(
    totals: &HostedFleetCredentialRevokeTotals,
) -> String {
    format!(
        r#"{{
    "relays": {},
    "credentialSources": {},
    "credentials": {},
    "activeCredentials": {},
    "revokedCredentials": {},
    "expiredCredentials": {},
    "accounts": {}
  }}"#,
        totals.relays,
        totals.credential_sources,
        totals.credentials,
        totals.active,
        totals.revoked,
        totals.expired,
        totals.accounts
    )
}

fn render_hosted_fleet_credential_revoke_relay_json(
    relay: &HostedFleetCredentialRevokeRelayReport,
) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "credentialsFile": "{}",
      "credentials": {},
      "activeCredentials": {},
      "revokedCredentials": {},
      "expiredCredentials": {},
      "accounts": {},
      "payloadDisplayed": false,
      "tokenDisplayed": {},
      "tokenHashDisplayed": false,
      "keyMaterialDisplayed": false,
      "sessionIdDisplayed": false,
      "ciphertextDisplayed": false,
      "contentsDisplayed": {}
    }}"#,
        json_escape(&relay.name),
        json_escape(&relay.credentials_file.display().to_string()),
        relay.credentials,
        relay.active,
        relay.revoked,
        relay.expired,
        relay.accounts,
        bool_json(relay.token_displayed),
        bool_json(relay.contents_displayed)
    )
}

fn render_hosted_fleet_tenant_account_lifecycle_text(
    report: &HostedFleetTenantAccountLifecycleReport,
) -> String {
    let mode = if report.dry_run {
        "dry-run"
    } else {
        "confirmed"
    };
    let totals = &report.totals;
    let mut output = format!(
        r"conU hosted relay fleet tenant account lifecycle

status: {}
action: {}
mode: {}
account: {}
fleet file: {}
relays: {}
tenant sources: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
tenant policies: {}

relay tenant sources:",
        report.mode.status(report.dry_run),
        report.mode.action(),
        mode,
        report.account_id,
        report.fleet_file.display(),
        totals.relays,
        totals.tenant_sources,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    );

    for relay in &report.relays {
        output.push_str(&format!(
            "\n- {}: tenants {} active tenants {} revoked tenants {} nodes {} active nodes {} revoked nodes {} policies {}",
            relay.name,
            relay.tenants_file.display(),
            relay.active_tenants,
            relay.revoked_tenants,
            relay.nodes,
            relay.active_nodes,
            relay.revoked_nodes,
            relay.tenant_policies
        ));
    }

    output.push_str(&format!(
        r"

payload displayed: no
token displayed: {}
token hash displayed: no
key material displayed: {}
session id displayed: no
ciphertext displayed: no
contents displayed: {}",
        yes_no(totals.token_displayed),
        yes_no(totals.key_material_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn render_hosted_fleet_tenant_account_lifecycle_json(
    report: &HostedFleetTenantAccountLifecycleReport,
) -> String {
    let relays = report
        .relays
        .iter()
        .map(render_hosted_fleet_tenant_account_lifecycle_relay_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "mode": "{}",
  "accountId": "{}",
  "fleetFile": "{}",
  "dryRun": {},
  "confirmed": {},
  "totals": {},
  "relays": [
{}
  ],
  "payloadDisplayed": false,
  "tokenDisplayed": {},
  "tokenHashDisplayed": false,
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": false,
  "ciphertextDisplayed": false,
  "contentsDisplayed": {}
}}"#,
        report.mode.status(report.dry_run),
        report.mode.action(),
        if report.dry_run {
            "dry-run"
        } else {
            "confirmed"
        },
        json_escape(&report.account_id),
        json_escape(&report.fleet_file.display().to_string()),
        bool_json(report.dry_run),
        bool_json(!report.dry_run),
        render_hosted_fleet_tenant_account_lifecycle_totals_json(&report.totals),
        relays,
        bool_json(report.totals.token_displayed),
        bool_json(report.totals.key_material_displayed),
        bool_json(report.totals.contents_displayed)
    )
}

fn render_hosted_fleet_tenant_account_lifecycle_totals_json(
    totals: &HostedFleetTenantAccountLifecycleTotals,
) -> String {
    format!(
        r#"{{
    "relays": {},
    "tenantSources": {},
    "tenants": {},
    "activeTenants": {},
    "revokedTenants": {},
    "nodes": {},
    "activeNodes": {},
    "revokedNodes": {},
    "tenantPolicies": {}
  }}"#,
        totals.relays,
        totals.tenant_sources,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    )
}

fn render_hosted_fleet_tenant_account_lifecycle_relay_json(
    relay: &HostedFleetTenantAccountLifecycleRelayReport,
) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "tenantsFile": "{}",
      "tenants": {},
      "activeTenants": {},
      "revokedTenants": {},
      "nodes": {},
      "activeNodes": {},
      "revokedNodes": {},
      "tenantPolicies": {},
      "payloadDisplayed": false,
      "tokenDisplayed": {},
      "tokenHashDisplayed": false,
      "keyMaterialDisplayed": {},
      "sessionIdDisplayed": false,
      "ciphertextDisplayed": false,
      "contentsDisplayed": {}
    }}"#,
        json_escape(&relay.name),
        json_escape(&relay.tenants_file.display().to_string()),
        relay.tenants,
        relay.active_tenants,
        relay.revoked_tenants,
        relay.nodes,
        relay.active_nodes,
        relay.revoked_nodes,
        relay.tenant_policies,
        bool_json(relay.token_displayed),
        bool_json(relay.key_material_displayed),
        bool_json(relay.contents_displayed)
    )
}

fn render_hosted_fleet_tenant_node_lifecycle_text(
    report: &HostedFleetTenantNodeLifecycleReport,
) -> String {
    let mode = if report.dry_run {
        "dry-run"
    } else {
        "confirmed"
    };
    let totals = &report.totals;
    let mut output = format!(
        r"conU hosted relay fleet tenant node lifecycle

status: {}
action: {}
mode: {}
account: {}
node: {}
fleet file: {}
relays: {}
tenant sources: {}
requested permissions: {}
signing key id provided: {}
exchange key id provided: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
tenant policies: {}

relay tenant sources:",
        report.mode.status(report.dry_run),
        report.mode.action(),
        mode,
        report.account_id,
        report.node_id,
        report.fleet_file.display(),
        totals.relays,
        totals.tenant_sources,
        render_hosted_tenant_permissions_text(report.mode, report.permissions),
        yes_no(report.signing_key_id_provided),
        yes_no(report.exchange_key_id_provided),
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    );

    for relay in &report.relays {
        output.push_str(&format!(
            "\n- {}: tenants {} active tenants {} node records {} active nodes {} revoked nodes {} policies {}",
            relay.name,
            relay.tenants_file.display(),
            relay.active_tenants,
            relay.nodes,
            relay.active_nodes,
            relay.revoked_nodes,
            relay.tenant_policies
        ));
    }

    output.push_str(&format!(
        r"

payload displayed: no
token displayed: {}
token hash displayed: no
key material displayed: {}
session id displayed: no
ciphertext displayed: no
contents displayed: {}",
        yes_no(totals.token_displayed),
        yes_no(totals.key_material_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn render_hosted_fleet_tenant_node_lifecycle_json(
    report: &HostedFleetTenantNodeLifecycleReport,
) -> String {
    let relays = report
        .relays
        .iter()
        .map(render_hosted_fleet_tenant_node_lifecycle_relay_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "mode": "{}",
  "accountId": "{}",
  "nodeId": "{}",
  "fleetFile": "{}",
  "dryRun": {},
  "confirmed": {},
  "requestedPermissions": {},
  "signingKeyIdProvided": {},
  "exchangeKeyIdProvided": {},
  "totals": {},
  "relays": [
{}
  ],
  "payloadDisplayed": false,
  "tokenDisplayed": {},
  "tokenHashDisplayed": false,
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": false,
  "ciphertextDisplayed": false,
  "contentsDisplayed": {}
}}"#,
        report.mode.status(report.dry_run),
        report.mode.action(),
        if report.dry_run {
            "dry-run"
        } else {
            "confirmed"
        },
        json_escape(&report.account_id),
        json_escape(&report.node_id),
        json_escape(&report.fleet_file.display().to_string()),
        bool_json(report.dry_run),
        bool_json(!report.dry_run),
        render_hosted_tenant_permissions_json(report.mode, report.permissions),
        bool_json(report.signing_key_id_provided),
        bool_json(report.exchange_key_id_provided),
        render_hosted_fleet_tenant_node_lifecycle_totals_json(&report.totals),
        relays,
        bool_json(report.totals.token_displayed),
        bool_json(report.totals.key_material_displayed),
        bool_json(report.totals.contents_displayed)
    )
}

fn render_hosted_fleet_tenant_node_lifecycle_totals_json(
    totals: &HostedFleetTenantNodeLifecycleTotals,
) -> String {
    format!(
        r#"{{
    "relays": {},
    "tenantSources": {},
    "tenants": {},
    "activeTenants": {},
    "revokedTenants": {},
    "nodes": {},
    "activeNodes": {},
    "revokedNodes": {},
    "tenantPolicies": {}
  }}"#,
        totals.relays,
        totals.tenant_sources,
        totals.tenants,
        totals.active_tenants,
        totals.revoked_tenants,
        totals.nodes,
        totals.active_nodes,
        totals.revoked_nodes,
        totals.tenant_policies
    )
}

fn render_hosted_fleet_tenant_node_lifecycle_relay_json(
    relay: &HostedFleetTenantNodeLifecycleRelayReport,
) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "tenantsFile": "{}",
      "tenants": {},
      "activeTenants": {},
      "revokedTenants": {},
      "nodes": {},
      "activeNodes": {},
      "revokedNodes": {},
      "tenantPolicies": {},
      "payloadDisplayed": false,
      "tokenDisplayed": {},
      "tokenHashDisplayed": false,
      "keyMaterialDisplayed": {},
      "sessionIdDisplayed": false,
      "ciphertextDisplayed": false,
      "contentsDisplayed": {}
    }}"#,
        json_escape(&relay.name),
        json_escape(&relay.tenants_file.display().to_string()),
        relay.tenants,
        relay.active_tenants,
        relay.revoked_tenants,
        relay.nodes,
        relay.active_nodes,
        relay.revoked_nodes,
        relay.tenant_policies,
        bool_json(relay.token_displayed),
        bool_json(relay.key_material_displayed),
        bool_json(relay.contents_displayed)
    )
}

fn render_hosted_tenant_permissions_text(
    mode: HostedFleetTenantNodeLifecycleMode,
    permissions: HostedTenantPermissions,
) -> String {
    if mode == HostedFleetTenantNodeLifecycleMode::Revoke {
        return "none".to_string();
    }
    format!(
        "messages={} streams={} rooms={} files={} mailbox={}",
        permissions.messages,
        permissions.streams,
        permissions.rooms,
        permissions.files,
        permissions.mailbox
    )
}

fn render_hosted_tenant_permissions_json(
    mode: HostedFleetTenantNodeLifecycleMode,
    permissions: HostedTenantPermissions,
) -> String {
    if mode == HostedFleetTenantNodeLifecycleMode::Revoke {
        return "null".to_string();
    }
    format!(
        r#"{{
    "messages": {},
    "streams": {},
    "rooms": {},
    "files": {},
    "mailbox": {}
  }}"#,
        bool_json(permissions.messages),
        bool_json(permissions.streams),
        bool_json(permissions.rooms),
        bool_json(permissions.files),
        bool_json(permissions.mailbox)
    )
}

fn render_admin_account_suspend_text(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r"conU hosted relay admin account suspension

relay: {}
status: {}
account: {}
credentials: {}
active credentials: {}
revoked credentials: {}
expired credentials: {}
accounts: {}
tenants: {}
active tenants: {}
revoked tenants: {}
nodes: {}
active nodes: {}
revoked nodes: {}
tenant policies: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
contents displayed: {}",
        relay,
        result.status,
        result.account_id.as_deref().unwrap_or("none"),
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
        yes_no(result.payload_displayed),
        yes_no(result.token_displayed),
        yes_no(result.token_hash_displayed),
        yes_no(result.key_material_displayed),
        yes_no(result.contents_displayed)
    )
}

fn render_admin_account_suspend_json(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r#"{{
  "relay": "{}",
  "status": "{}",
  "accountId": {},
  "credentials": {},
  "active": {},
  "revoked": {},
  "expired": {},
  "accounts": {},
  "tenants": {},
  "activeTenants": {},
  "revokedTenants": {},
  "nodes": {},
  "activeNodes": {},
  "revokedNodes": {},
  "tenantPolicies": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        json_escape(relay),
        json_escape(&result.status),
        optional_string_json(result.account_id.as_deref()),
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
        bool_json(result.payload_displayed),
        bool_json(result.token_displayed),
        bool_json(result.token_hash_displayed),
        bool_json(result.key_material_displayed),
        bool_json(result.contents_displayed)
    )
}

fn render_session_audit_text(audit: &RelaySessionAudit, session_state_dir: &Path) -> String {
    format!(
        r"conU relay session-state audit

scope: {}
session state dir: {}
records: {}
active records: {}
expired records: {}
invalid records: {}
oldest created unix millis: {}
newest last seen unix millis: {}
next expires unix millis: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        audit.node_id.as_deref().unwrap_or("all"),
        session_state_dir.display(),
        audit.records,
        audit.active_records,
        audit.expired_records,
        audit.invalid_records,
        optional_u64_text(audit.oldest_created_unix_millis),
        optional_u64_text(audit.newest_last_seen_unix_millis),
        optional_u64_text(audit.next_expires_unix_millis),
        yes_no(audit.payload_displayed),
        yes_no(audit.token_displayed),
        yes_no(audit.token_hash_displayed),
        yes_no(audit.key_material_displayed),
        yes_no(audit.session_id_displayed),
        yes_no(audit.ciphertext_displayed),
        yes_no(audit.contents_displayed)
    )
}

fn render_session_audit_json(audit: &RelaySessionAudit, session_state_dir: &Path) -> String {
    format!(
        r#"{{
  "scope": {},
  "sessionStateDir": "{}",
  "records": {},
  "activeRecords": {},
  "expiredRecords": {},
  "invalidRecords": {},
  "oldestCreatedUnixMillis": {},
  "newestLastSeenUnixMillis": {},
  "nextExpiresUnixMillis": {},
  "payloadDisplayed": {},
  "tokenDisplayed": {},
  "tokenHashDisplayed": {},
  "keyMaterialDisplayed": {},
  "sessionIdDisplayed": {},
  "ciphertextDisplayed": {},
  "contentsDisplayed": {}
}}"#,
        optional_string_json(audit.node_id.as_deref()),
        json_escape(&session_state_dir.display().to_string()),
        audit.records,
        audit.active_records,
        audit.expired_records,
        audit.invalid_records,
        optional_u64_json(audit.oldest_created_unix_millis),
        optional_u64_json(audit.newest_last_seen_unix_millis),
        optional_u64_json(audit.next_expires_unix_millis),
        bool_json(audit.payload_displayed),
        bool_json(audit.token_displayed),
        bool_json(audit.token_hash_displayed),
        bool_json(audit.key_material_displayed),
        bool_json(audit.session_id_displayed),
        bool_json(audit.ciphertext_displayed),
        bool_json(audit.contents_displayed)
    )
}

fn render_admin_session_audit_text(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r"conU hosted relay admin session-state audit

node: {}
relay: {}
records: {}
active records: {}
expired records: {}
invalid records: {}
oldest created unix millis: {}
newest last seen unix millis: {}
next expires unix millis: {}
payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        result.node_id.as_deref().unwrap_or("all"),
        relay,
        result.session_state_records,
        result.session_state_active_records,
        result.session_state_expired_records,
        result.session_state_invalid_records,
        optional_u64_text(result.session_state_oldest_created_unix_millis),
        optional_u64_text(result.session_state_newest_last_seen_unix_millis),
        optional_u64_text(result.session_state_next_expires_unix_millis),
        yes_no(result.payload_displayed),
        yes_no(result.token_displayed),
        yes_no(result.token_hash_displayed),
        yes_no(result.key_material_displayed),
        yes_no(result.session_id_displayed),
        yes_no(result.ciphertext_displayed),
        yes_no(result.contents_displayed)
    )
}

fn render_admin_session_audit_json(result: &RelayAdminResult, relay: &str) -> String {
    format!(
        r#"{{
  "status": "{}",
  "action": "{}",
  "nodeId": {},
  "relay": "{}",
  "records": {},
  "activeRecords": {},
  "expiredRecords": {},
  "invalidRecords": {},
  "oldestCreatedUnixMillis": {},
  "newestLastSeenUnixMillis": {},
  "nextExpiresUnixMillis": {},
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
        result.session_state_records,
        result.session_state_active_records,
        result.session_state_expired_records,
        result.session_state_invalid_records,
        optional_u64_json(result.session_state_oldest_created_unix_millis),
        optional_u64_json(result.session_state_newest_last_seen_unix_millis),
        optional_u64_json(result.session_state_next_expires_unix_millis),
        bool_json(result.payload_displayed),
        bool_json(result.token_displayed),
        bool_json(result.token_hash_displayed),
        bool_json(result.key_material_displayed),
        bool_json(result.session_id_displayed),
        bool_json(result.ciphertext_displayed),
        bool_json(result.contents_displayed)
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

fn render_abuse_threshold_report_text(report: &AbuseThresholdReport) -> String {
    let mut output = format!(
        "conU relay abuse threshold report\n\nstatus: {}\nsource: {}\naccount: {}\nnode: {}\nrelay: {}\nabuse dir: {}\nrecords: {}\nwindow started unix: {}\nthreshold checks: {}\nthreshold exceeded: {}\n",
        abuse_threshold_status(report),
        report.source,
        report.account_id.as_deref().unwrap_or("all"),
        report.node_id.as_deref().unwrap_or("all"),
        report.relay.as_deref().unwrap_or("not configured"),
        optional_path_text(report.abuse_dir.as_deref()),
        report.records,
        optional_u64_text(report.window_started_unix),
        report.threshold_checks,
        report.threshold_exceeded
    );
    append_threshold_metric(
        &mut output,
        "admin unauthorized",
        report.admin_unauthorized,
        report.thresholds.admin_unauthorized,
    );
    append_threshold_metric(
        &mut output,
        "admin failed",
        report.admin_failed,
        report.thresholds.admin_failed,
    );
    append_threshold_metric(
        &mut output,
        "unauthorized sessions",
        report.unauthorized_sessions,
        report.thresholds.unauthorized_sessions,
    );
    append_threshold_metric(
        &mut output,
        "credential denied sessions",
        report.credential_denied_sessions,
        report.thresholds.credential_denied_sessions,
    );
    append_threshold_metric(
        &mut output,
        "tenant denied sessions",
        report.tenant_denied_sessions,
        report.thresholds.tenant_denied_sessions,
    );
    append_threshold_metric(
        &mut output,
        "rate limited sessions",
        report.rate_limited_sessions,
        report.thresholds.rate_limited_sessions,
    );
    append_threshold_metric(
        &mut output,
        "session expired",
        report.session_expired,
        report.thresholds.session_expired,
    );
    append_threshold_metric(
        &mut output,
        "quota denied forwards",
        report.quota_denied_forwards,
        report.thresholds.quota_denied_forwards,
    );
    append_threshold_metric(
        &mut output,
        "undelivered forwards",
        report.undelivered_forwards,
        report.thresholds.undelivered_forwards,
    );
    append_threshold_metric(
        &mut output,
        "mailbox rejected forwards",
        report.mailbox_rejected_forwards,
        report.thresholds.mailbox_rejected_forwards,
    );
    append_threshold_metric(
        &mut output,
        "malformed client frames",
        report.malformed_client_frames,
        report.thresholds.malformed_client_frames,
    );
    output.push_str(&format!(
        "payload displayed: {}\ntoken displayed: {}\ntoken hash displayed: {}\nkey material displayed: {}\nsession id displayed: {}\nciphertext displayed: {}\ncontents displayed: {}",
        yes_no(report.payload_displayed),
        yes_no(report.token_displayed),
        yes_no(report.token_hash_displayed),
        yes_no(report.key_material_displayed),
        yes_no(report.session_id_displayed),
        yes_no(report.ciphertext_displayed),
        yes_no(report.contents_displayed)
    ));
    output
}

fn append_threshold_metric(output: &mut String, label: &str, count: u64, max: Option<u64>) {
    output.push_str(&format!(
        "{}: {} max={} exceeded={}\n",
        label,
        count,
        optional_u64_text(max),
        yes_no(threshold_exceeded(count, max))
    ));
}

fn render_abuse_threshold_report_json(report: &AbuseThresholdReport) -> String {
    format!(
        r#"{{
  "status": "{}",
  "source": "{}",
  "accountId": {},
  "nodeId": {},
  "relay": {},
  "abuseDir": {},
  "records": {},
  "windowStartedUnix": {},
  "thresholdChecks": {},
  "thresholdExceeded": {},
  "metrics": {{
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
        abuse_threshold_status(report),
        report.source,
        optional_string_json(report.account_id.as_deref()),
        optional_string_json(report.node_id.as_deref()),
        optional_string_json(report.relay.as_deref()),
        optional_path_json(report.abuse_dir.as_deref()),
        report.records,
        optional_u64_json(report.window_started_unix),
        report.threshold_checks,
        report.threshold_exceeded,
        threshold_metric_json(
            report.admin_unauthorized,
            report.thresholds.admin_unauthorized
        ),
        threshold_metric_json(report.admin_failed, report.thresholds.admin_failed),
        threshold_metric_json(
            report.unauthorized_sessions,
            report.thresholds.unauthorized_sessions
        ),
        threshold_metric_json(
            report.credential_denied_sessions,
            report.thresholds.credential_denied_sessions
        ),
        threshold_metric_json(
            report.tenant_denied_sessions,
            report.thresholds.tenant_denied_sessions
        ),
        threshold_metric_json(
            report.rate_limited_sessions,
            report.thresholds.rate_limited_sessions
        ),
        threshold_metric_json(report.session_expired, report.thresholds.session_expired),
        threshold_metric_json(
            report.quota_denied_forwards,
            report.thresholds.quota_denied_forwards
        ),
        threshold_metric_json(
            report.undelivered_forwards,
            report.thresholds.undelivered_forwards
        ),
        threshold_metric_json(
            report.mailbox_rejected_forwards,
            report.thresholds.mailbox_rejected_forwards
        ),
        threshold_metric_json(
            report.malformed_client_frames,
            report.thresholds.malformed_client_frames
        ),
        bool_json(report.payload_displayed),
        bool_json(report.token_displayed),
        bool_json(report.token_hash_displayed),
        bool_json(report.key_material_displayed),
        bool_json(report.session_id_displayed),
        bool_json(report.ciphertext_displayed),
        bool_json(report.contents_displayed)
    )
}

fn threshold_metric_json(count: u64, max: Option<u64>) -> String {
    format!(
        r#"{{"count":{},"max":{},"exceeded":{}}}"#,
        count,
        optional_u64_json(max),
        bool_json(threshold_exceeded(count, max))
    )
}

fn abuse_threshold_status(report: &AbuseThresholdReport) -> &'static str {
    if report.threshold_exceeded == 0 {
        "ok"
    } else {
        "threshold_exceeded"
    }
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

fn render_hosted_fleet_mailbox_purge_text(report: &HostedFleetMailboxPurgeReport) -> String {
    let totals = &report.totals;
    let mode = if report.dry_run {
        "dry-run"
    } else {
        "confirmed"
    };
    let mut output = format!(
        r"conU hosted relay fleet mailbox purge

mode: {}
fleet file: {}
node: {}
retention policy file: {}
default mailbox ttl seconds: {}
relays: {}
mailbox sources: {}
mailbox nodes: {}
mailbox records: {}
mailbox invalid records: {}
mailbox bytes: {}
mailbox expired records: {}
mailbox expired bytes: {}
mailbox purged records: {}
mailbox purged bytes: {}

relay mailbox sources:",
        mode,
        report.fleet_file.display(),
        report.node_id.as_deref().unwrap_or("all"),
        optional_path_text(report.retention_policy_file.as_deref()),
        optional_u64_text(report.mailbox_ttl.map(|ttl| ttl.as_secs())),
        totals.relays,
        totals.mailbox_sources,
        totals.mailbox_nodes,
        totals.mailbox_records,
        totals.mailbox_invalid_records,
        totals.mailbox_bytes,
        totals.mailbox_expired_records,
        totals.mailbox_expired_bytes,
        totals.mailbox_purged_records,
        totals.mailbox_purged_bytes
    );

    for relay in &report.relays {
        output.push_str(&format!(
            "\n- {}: mailbox {} ttl {} records {} expired {} purged {} bytes purged {}",
            relay.name,
            relay.mailbox_dir.display(),
            relay.report.retention_ttl_seconds,
            relay.report.records,
            relay.report.expired_records,
            relay.report.purged_records,
            relay.report.purged_bytes
        ));
    }

    output.push_str(&format!(
        r"

payload displayed: {}
token displayed: {}
token hash displayed: {}
key material displayed: {}
session id displayed: {}
ciphertext displayed: {}
contents displayed: {}",
        yes_no(totals.payload_displayed),
        yes_no(totals.token_displayed),
        yes_no(totals.token_hash_displayed),
        yes_no(totals.key_material_displayed),
        yes_no(totals.session_id_displayed),
        yes_no(totals.ciphertext_displayed),
        yes_no(totals.contents_displayed)
    ));
    output
}

fn render_hosted_fleet_mailbox_purge_json(report: &HostedFleetMailboxPurgeReport) -> String {
    let status = if report.dry_run { "dry_run" } else { "purged" };
    let relays = report
        .relays
        .iter()
        .map(render_hosted_fleet_mailbox_purge_relay_json)
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"{{
  "status": "{}",
  "mode": "{}",
  "fleetFile": "{}",
  "nodeId": {},
  "retentionPolicyFile": {},
  "defaultMailboxTtlSeconds": {},
  "dryRun": {},
  "confirmed": {},
  "totals": {},
  "relays": [
{}
  ],
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
        json_escape(&report.fleet_file.display().to_string()),
        optional_string_json(report.node_id.as_deref()),
        optional_path_json(report.retention_policy_file.as_deref()),
        optional_u64_json(report.mailbox_ttl.map(|ttl| ttl.as_secs())),
        bool_json(report.dry_run),
        bool_json(!report.dry_run),
        render_hosted_fleet_mailbox_purge_totals_json(&report.totals),
        relays,
        bool_json(report.totals.payload_displayed),
        bool_json(report.totals.token_displayed),
        bool_json(report.totals.token_hash_displayed),
        bool_json(report.totals.key_material_displayed),
        bool_json(report.totals.session_id_displayed),
        bool_json(report.totals.ciphertext_displayed),
        bool_json(report.totals.contents_displayed)
    )
}

fn render_hosted_fleet_mailbox_purge_totals_json(totals: &HostedFleetMailboxPurgeTotals) -> String {
    format!(
        r#"{{
    "relays": {},
    "mailboxSources": {},
    "mailboxNodes": {},
    "mailboxRecords": {},
    "mailboxInvalidRecords": {},
    "mailboxBytes": {},
    "mailboxExpiredRecords": {},
    "mailboxExpiredBytes": {},
    "mailboxPurgedRecords": {},
    "mailboxPurgedBytes": {}
  }}"#,
        totals.relays,
        totals.mailbox_sources,
        totals.mailbox_nodes,
        totals.mailbox_records,
        totals.mailbox_invalid_records,
        totals.mailbox_bytes,
        totals.mailbox_expired_records,
        totals.mailbox_expired_bytes,
        totals.mailbox_purged_records,
        totals.mailbox_purged_bytes
    )
}

fn render_hosted_fleet_mailbox_purge_relay_json(
    relay: &HostedFleetMailboxPurgeRelayReport,
) -> String {
    format!(
        r#"    {{
      "name": "{}",
      "mailboxDir": "{}",
      "retentionTtlSeconds": {},
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
        json_escape(&relay.name),
        json_escape(&relay.mailbox_dir.display().to_string()),
        relay.report.retention_ttl_seconds,
        relay.report.nodes,
        relay.report.records,
        relay.report.invalid_records,
        relay.report.bytes,
        relay.report.expired_records,
        relay.report.expired_bytes,
        relay.report.purged_records,
        relay.report.purged_bytes,
        bool_json(relay.report.payload_displayed),
        bool_json(relay.report.token_displayed),
        bool_json(relay.report.token_hash_displayed),
        bool_json(relay.report.key_material_displayed),
        bool_json(relay.report.session_id_displayed),
        bool_json(relay.report.ciphertext_displayed),
        bool_json(relay.report.contents_displayed)
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
    let admin_tokens_file = env::var("CONU_RELAY_ADMIN_TOKENS_FILE")
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

    let admin_token = env::var("CONU_RELAY_ADMIN_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if admin_token.is_some() || admin_tokens_file.is_some() {
        let Some(credentials_file) = credentials_file.clone() else {
            return Err(
                "CONU_RELAY_ADMIN_TOKEN or CONU_RELAY_ADMIN_TOKENS_FILE requires CONU_RELAY_CREDENTIALS_FILE"
                    .to_string(),
            );
        };
        if let Some(admin_token) = admin_token {
            config = config
                .with_admin_token(admin_token, credentials_file.clone())
                .map_err(|error| error.to_string())?;
            if let Some(admin_tokens_file) = admin_tokens_file {
                config = config
                    .with_additional_admin_tokens_file(admin_tokens_file)
                    .map_err(|error| error.to_string())?;
            }
        } else if let Some(admin_tokens_file) = admin_tokens_file {
            config = config
                .with_admin_tokens_file(admin_tokens_file, credentials_file.clone())
                .map_err(|error| error.to_string())?;
        }
        if let Some(tenants_file) = tenants_file {
            config = config
                .with_admin_tenants_file(tenants_file)
                .map_err(|error| error.to_string())?;
        }
    } else if tenants_file.is_some() {
        return Err(
            "CONU_RELAY_TENANTS_FILE requires CONU_RELAY_ADMIN_TOKEN or CONU_RELAY_ADMIN_TOKENS_FILE plus CONU_RELAY_CREDENTIALS_FILE"
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn unknown_option_error_redacts_argument_contents() {
        let secret_marker = "--relay-secret-token";
        let error = unknown_option_error();

        assert!(error.contains("unknown option"));
        assert!(error.contains("contentsDisplayed=false"));
        assert!(!error.contains(secret_marker));
    }

    fn abuse_threshold_policy_contents(thresholds: &str) -> String {
        format!(
            "version = \"1\"\n{thresholds}payload_displayed = false\ntoken_displayed = false\ntoken_hash_displayed = false\nkey_material_displayed = false\nsession_id_displayed = false\nciphertext_displayed = false\ncontents_displayed = false\n"
        )
    }

    fn write_abuse_threshold_policy_file(contents: &str) -> PathBuf {
        let counter = TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "conu-relay-abuse-threshold-policy-{}-{nanos}-{counter}.toml",
            std::process::id(),
        ));
        fs::write(&path, contents).expect("write abuse threshold policy file");
        path
    }

    fn mailbox_retention_policy_contents(settings: &str) -> String {
        format!(
            "version = \"1\"\n{settings}payload_displayed = false\ntoken_displayed = false\ntoken_hash_displayed = false\nkey_material_displayed = false\nsession_id_displayed = false\nciphertext_displayed = false\ncontents_displayed = false\n"
        )
    }

    fn write_mailbox_retention_policy_file(contents: &str) -> PathBuf {
        let counter = TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "conu-relay-mailbox-retention-policy-{}-{nanos}-{counter}.toml",
            std::process::id(),
        ));
        fs::write(&path, contents).expect("write mailbox retention policy file");
        path
    }

    fn hosted_fleet_dashboard_file_contents(relays: &str) -> String {
        format!(
            "version = \"1\"\npayload_displayed = false\ntoken_displayed = false\ntoken_hash_displayed = false\nkey_material_displayed = false\nsession_id_displayed = false\nciphertext_displayed = false\ncontents_displayed = false\n{relays}"
        )
    }

    fn write_hosted_fleet_dashboard_file(contents: &str) -> PathBuf {
        let counter = TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "conu-relay-hosted-fleet-dashboard-{}-{nanos}-{counter}",
            std::process::id(),
        ));
        fs::create_dir_all(&dir).expect("create hosted fleet dashboard test dir");
        let path = dir.join("fleet.toml");
        fs::write(&path, contents).expect("write hosted fleet dashboard file");
        path
    }

    fn unique_temp_path(label: &str, file_name: &str) -> PathBuf {
        let counter = TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        env::temp_dir()
            .join(format!(
                "conu-relay-{label}-{}-{nanos}-{counter}",
                std::process::id(),
            ))
            .join(file_name)
    }

    fn write_oversized_cli_file(label: &str, file_name: &str, secret: &str) -> PathBuf {
        let path = unique_temp_path(label, file_name);
        fs::create_dir_all(path.parent().expect("oversized file parent"))
            .expect("create oversized file dir");
        let mut contents = format!("# {secret}\n");
        contents.push_str(&"a".repeat((MAX_RELAY_CLI_FILE_BYTES + 1) as usize));
        fs::write(&path, contents).expect("write oversized file");
        path
    }

    #[cfg(unix)]
    #[test]
    fn token_out_preflight_rejects_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let token_path = unique_temp_path("token-out-dangling-link", "node.token");
        fs::create_dir_all(token_path.parent().expect("token link parent"))
            .expect("create token link parent");
        let missing_target = token_path
            .parent()
            .expect("token link parent")
            .join("missing-token-target");
        symlink(&missing_target, &token_path).expect("create dangling token symlink");

        let error = ensure_token_out_available(&token_path)
            .expect_err("dangling symlink token output should fail closed");

        assert!(error.contains("token output file already exists"));
        assert!(
            fs::symlink_metadata(&token_path)
                .expect("token symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn token_out_preflight_rejects_symlinked_output_directory() {
        use std::os::unix::fs::symlink;

        let outside = unique_temp_path("token-out-dir-target", "outside");
        fs::create_dir_all(&outside).expect("create outside token dir");
        let token_dir = unique_temp_path("token-out-dir-link", "tokens");
        fs::create_dir_all(token_dir.parent().expect("token dir link parent"))
            .expect("create token dir link parent");
        symlink(&outside, &token_dir).expect("create token dir symlink");
        let token_path = token_dir.join("node.token");

        let error = ensure_token_out_available(&token_path)
            .expect_err("symlinked token output directory should fail closed");

        assert!(error.contains("create issued relay token directory"));
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside token dir reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&token_dir)
                .expect("token dir symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn relay_cli_policy_file_reads_reject_symlinks_without_reading_targets() {
        use std::os::unix::fs::symlink;

        let abuse_target = unique_temp_path("abuse-policy-target", "policy.toml");
        fs::create_dir_all(abuse_target.parent().expect("abuse target parent"))
            .expect("create abuse target dir");
        let abuse_secret = "relay-secret-token-abuse";
        let abuse_target_contents =
            abuse_threshold_policy_contents(&format!("max_admin_failed = 1\n# {abuse_secret}\n"));
        fs::write(&abuse_target, &abuse_target_contents).expect("write abuse target");
        let abuse_link = unique_temp_path("abuse-policy-link", "policy.toml");
        fs::create_dir_all(abuse_link.parent().expect("abuse link parent"))
            .expect("create abuse link dir");
        symlink(&abuse_target, &abuse_link).expect("create abuse policy symlink");
        let abuse_error = parse_abuse_threshold_report_args(vec![
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--thresholds-file".to_string(),
            abuse_link.to_string_lossy().to_string(),
        ])
        .expect_err("symlinked abuse threshold policy should fail closed");
        assert!(abuse_error.contains("inspect abuse threshold policy file"));
        assert!(!abuse_error.contains(abuse_secret));

        let retention_target = unique_temp_path("retention-policy-target", "policy.toml");
        fs::create_dir_all(retention_target.parent().expect("retention target parent"))
            .expect("create retention target dir");
        let retention_secret = "relay-secret-token-retention";
        let retention_target_contents = mailbox_retention_policy_contents(&format!(
            "ttl_seconds = 3600\n# {retention_secret}\n"
        ));
        fs::write(&retention_target, &retention_target_contents).expect("write retention target");
        let retention_link = unique_temp_path("retention-policy-link", "policy.toml");
        fs::create_dir_all(retention_link.parent().expect("retention link parent"))
            .expect("create retention link dir");
        symlink(&retention_target, &retention_link).expect("create retention policy symlink");
        let retention_error = parse_mailbox_audit_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--retention-policy-file".to_string(),
            retention_link.to_string_lossy().to_string(),
        ])
        .expect_err("symlinked retention policy should fail closed");
        assert!(retention_error.contains("inspect mailbox retention policy file"));
        assert!(!retention_error.contains(retention_secret));

        let fleet_target = unique_temp_path("fleet-target", "fleet.toml");
        fs::create_dir_all(fleet_target.parent().expect("fleet target parent"))
            .expect("create fleet target dir");
        let fleet_secret = "relay-secret-token-fleet";
        let fleet_target_contents =
            hosted_fleet_dashboard_file_contents(&format!("# {fleet_secret}\n"));
        fs::write(&fleet_target, &fleet_target_contents).expect("write fleet target");
        let fleet_link = unique_temp_path("fleet-link", "fleet.toml");
        fs::create_dir_all(fleet_link.parent().expect("fleet link parent"))
            .expect("create fleet link dir");
        symlink(&fleet_target, &fleet_link).expect("create fleet symlink");
        let fleet_error = parse_hosted_fleet_dashboard_file(&fleet_link)
            .expect_err("symlinked fleet file should fail closed");
        assert!(fleet_error.contains("inspect hosted fleet dashboard file"));
        assert!(!fleet_error.contains(fleet_secret));

        for (target, link, contents) in [
            (&abuse_target, &abuse_link, &abuse_target_contents),
            (
                &retention_target,
                &retention_link,
                &retention_target_contents,
            ),
            (&fleet_target, &fleet_link, &fleet_target_contents),
        ] {
            assert_eq!(
                fs::read_to_string(target).expect("target remains readable"),
                contents.as_str()
            );
            assert!(
                fs::symlink_metadata(link)
                    .expect("link metadata reads")
                    .file_type()
                    .is_symlink()
            );
        }
    }

    #[test]
    fn relay_cli_policy_file_reads_reject_oversized_files_without_reading_contents() {
        let abuse_secret = "relay-secret-token-abuse-oversized";
        let abuse_path =
            write_oversized_cli_file("abuse-policy-oversized", "policy.toml", abuse_secret);
        let abuse_error = parse_abuse_threshold_report_args(vec![
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--thresholds-file".to_string(),
            abuse_path.to_string_lossy().to_string(),
        ])
        .expect_err("oversized abuse threshold policy should fail closed");
        assert!(abuse_error.contains("abuse threshold policy file"));
        assert!(abuse_error.contains("exceeds"));
        assert!(!abuse_error.contains(abuse_secret));

        let retention_secret = "relay-secret-token-retention-oversized";
        let retention_path = write_oversized_cli_file(
            "retention-policy-oversized",
            "policy.toml",
            retention_secret,
        );
        let retention_error = parse_mailbox_audit_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--retention-policy-file".to_string(),
            retention_path.to_string_lossy().to_string(),
        ])
        .expect_err("oversized retention policy should fail closed");
        assert!(retention_error.contains("mailbox retention policy file"));
        assert!(retention_error.contains("exceeds"));
        assert!(!retention_error.contains(retention_secret));

        let fleet_secret = "relay-secret-token-fleet-oversized";
        let fleet_path = write_oversized_cli_file("fleet-oversized", "fleet.toml", fleet_secret);
        let fleet_error = parse_hosted_fleet_dashboard_file(&fleet_path)
            .expect_err("oversized fleet file should fail closed");
        assert!(fleet_error.contains("hosted fleet dashboard file"));
        assert!(fleet_error.contains("exceeds"));
        assert!(!fleet_error.contains(fleet_secret));
    }

    #[test]
    fn relay_stdin_token_reads_are_bounded_without_echoing_contents() {
        let relay_token =
            read_relay_token_from_reader(b"  relay-token-1234567890abcdef\n" as &[u8])
                .expect("relay token reads");
        assert_eq!(relay_token, "relay-token-1234567890abcdef");

        let admin_token =
            read_admin_token_from_reader(true, b" admin-token-1234567890abcdef\n" as &[u8])
                .expect("admin token reads");
        assert_eq!(admin_token, "admin-token-1234567890abcdef");

        let missing_error = read_admin_token_from_reader(false, b"ignored-token" as &[u8])
            .expect_err("missing admin token flag should fail");
        assert!(missing_error.contains("--admin-token-stdin is required"));
        assert!(!missing_error.contains("ignored-token"));

        let empty_error = read_admin_token_from_reader(true, b" \n\t" as &[u8])
            .expect_err("empty admin token should fail");
        assert!(empty_error.contains("relay admin token cannot be empty"));

        let secret = "relay-secret-token-stdin-oversized";
        let mut oversized = format!("{secret}\n");
        oversized.push_str(&"a".repeat((MAX_RELAY_STDIN_TOKEN_BYTES + 1) as usize));

        let relay_error = read_relay_token_from_reader(oversized.as_bytes())
            .expect_err("oversized relay token stdin should fail closed");
        assert!(relay_error.contains("relay token"));
        assert!(relay_error.contains("exceeds"));
        assert!(!relay_error.contains(secret));

        let admin_error = read_admin_token_from_reader(true, oversized.as_bytes())
            .expect_err("oversized admin token stdin should fail closed");
        assert!(admin_error.contains("relay admin token"));
        assert!(admin_error.contains("exceeds"));
        assert!(!admin_error.contains(secret));
    }

    #[test]
    fn admin_token_audit_parser_and_renderers_are_metadata_only() {
        let parsed = parse_admin_token_audit_args(vec![
            "--admin-tokens-file".to_string(),
            "admin-tokens.toml".to_string(),
            "--bind-addr".to_string(),
            "0.0.0.0:8787".to_string(),
            "--account".to_string(),
            "account.prod".to_string(),
            "--json".to_string(),
        ])
        .expect("admin token audit args parse");
        assert_eq!(
            parsed.admin_tokens_file.as_path(),
            Path::new("admin-tokens.toml")
        );
        assert_eq!(parsed.bind_addr, "0.0.0.0:8787");
        assert_eq!(parsed.account_id.as_deref(), Some("account.prod"));
        assert!(parsed.json);

        let parsed_default = parse_admin_token_audit_args(vec![
            "--admin-tokens-file".to_string(),
            "admin-tokens.toml".to_string(),
        ])
        .expect("default bind addr parses");
        assert_eq!(parsed_default.bind_addr, "127.0.0.1:0");
        assert!(parse_admin_token_audit_args(Vec::new()).is_err());
        let invalid_filter = parse_admin_token_audit_args(vec![
            "--admin-tokens-file".to_string(),
            "admin-tokens.toml".to_string(),
            "--account".to_string(),
            "bad secret value".to_string(),
        ])
        .expect_err("invalid account filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));
        let invalid_bind = parse_admin_token_audit_args(vec![
            "--admin-tokens-file".to_string(),
            "admin-tokens.toml".to_string(),
            "--bind-addr".to_string(),
            "0.0.0.0:8787/secret".to_string(),
        ])
        .expect_err("invalid bind addr should fail closed");
        assert!(!invalid_bind.contains("0.0.0.0:8787/secret"));

        let audit = HostedAdminTokenAudit {
            account_id: Some("account.prod".to_string()),
            records: 3,
            active: 1,
            revoked: 1,
            expired: 1,
            account_scoped_records: 2,
            global_records: 1,
            accounts: 1,
            expiring_records: 2,
            next_expires_at_unix: Some(1_763_596_900),
            last_expires_at_unix: Some(1_763_597_900),
            scope_credentials: 1,
            scope_tenants: 1,
            scope_dashboard: 1,
            scope_sessions: 1,
            scope_mailbox_audit: 1,
            scope_mailbox_purge: 1,
            payload_displayed: false,
            token_displayed: false,
            token_hash_displayed: false,
            key_material_displayed: false,
            session_id_displayed: false,
            ciphertext_displayed: false,
            contents_displayed: false,
        };
        let secret_token = "relay-admin-secret-token-123456";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_admin_token_audit_text(&audit, Path::new("admin-tokens.toml"), "0.0.0.0:8787"),
            render_admin_token_audit_json(&audit, Path::new("admin-tokens.toml"), "0.0.0.0:8787"),
        ];

        for output in outputs {
            assert!(output.contains("admin-token") || output.contains("adminTokensFile"));
            assert!(output.contains("account.prod"));
            assert!(output.contains("scope"));
            assert!(output.contains("false") || output.contains("no"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }
    }

    #[test]
    fn hosted_readiness_parser_and_renderers_are_metadata_only() {
        let retention_policy =
            write_mailbox_retention_policy_file(&mailbox_retention_policy_contents(
                "ttl_seconds = 7200\nnode_id = \"node.from-policy\"\n",
            ));
        let threshold_policy = write_abuse_threshold_policy_file(&abuse_threshold_policy_contents(
            "max_rate_limited_sessions = 0\n",
        ));
        let parsed = parse_hosted_readiness_args(vec![
            "--bind-addr".to_string(),
            "0.0.0.0:8787".to_string(),
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--tenants-file".to_string(),
            "tenants.toml".to_string(),
            "--admin-tokens-file".to_string(),
            "admin-tokens.toml".to_string(),
            "--session-state-dir".to_string(),
            "sessions".to_string(),
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--retention-policy-file".to_string(),
            retention_policy.display().to_string(),
            "--ttl-seconds".to_string(),
            "3600".to_string(),
            "--accounting-dir".to_string(),
            "accounting".to_string(),
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--thresholds-file".to_string(),
            threshold_policy.display().to_string(),
            "--max-admin-failed".to_string(),
            "1".to_string(),
            "--account".to_string(),
            "account.prod".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--json".to_string(),
            "--fail-on-warning".to_string(),
        ])
        .expect("hosted readiness args parse");
        assert_eq!(parsed.bind_addr, "0.0.0.0:8787");
        assert_eq!(
            parsed.credentials_file.as_deref(),
            Some(Path::new("credentials.toml"))
        );
        assert_eq!(
            parsed.admin_tokens_file.as_deref(),
            Some(Path::new("admin-tokens.toml"))
        );
        assert_eq!(
            parsed.retention_policy_file.as_deref(),
            Some(retention_policy.as_path())
        );
        assert_eq!(parsed.mailbox_node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.mailbox_ttl, Some(Duration::from_secs(3600)));
        assert_eq!(
            parsed.thresholds_file.as_deref(),
            Some(threshold_policy.as_path())
        );
        assert_eq!(parsed.abuse_thresholds.rate_limited_sessions, Some(0));
        assert_eq!(parsed.abuse_thresholds.admin_failed, Some(1));
        assert_eq!(parsed.account_id.as_deref(), Some("account.prod"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert!(parsed.json);
        assert!(parsed.fail_on_warning);
        assert!(parse_hosted_readiness_args(Vec::new()).is_err());
        let invalid_filter = parse_hosted_readiness_args(vec![
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--account".to_string(),
            "bad secret value".to_string(),
        ])
        .expect_err("invalid account filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));
        let invalid_bind = parse_hosted_readiness_args(vec![
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--bind-addr".to_string(),
            "0.0.0.0:8787/secret".to_string(),
        ])
        .expect_err("invalid bind addr should fail closed");
        assert!(!invalid_bind.contains("0.0.0.0:8787/secret"));
        let missing_mailbox_dependency = parse_hosted_readiness_args(vec![
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--retention-policy-file".to_string(),
            "missing-retention-policy.toml".to_string(),
        ])
        .expect_err("retention policy should require mailbox dir before reading file");
        assert!(missing_mailbox_dependency.contains("requires --mailbox-dir"));
        let missing_abuse_dependency = parse_hosted_readiness_args(vec![
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--thresholds-file".to_string(),
            "missing-thresholds-policy.toml".to_string(),
        ])
        .expect_err("threshold policy should require abuse dir before reading file");
        assert!(missing_abuse_dependency.contains("require --abuse-dir"));
        let missing_abuse_cli_dependency = parse_hosted_readiness_args(vec![
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--max-rate-limited-sessions".to_string(),
            "0".to_string(),
        ])
        .expect_err("inline threshold should require abuse dir");
        assert!(missing_abuse_cli_dependency.contains("require --abuse-dir"));

        let report = HostedReadinessReport {
            bind_addr: "0.0.0.0:8787".to_string(),
            public_bind: true,
            credentials_file: Some(PathBuf::from("credentials.toml")),
            tenants_file: Some(PathBuf::from("tenants.toml")),
            admin_tokens_file: Some(PathBuf::from("admin-tokens.toml")),
            session_state_dir: Some(PathBuf::from("sessions")),
            mailbox_dir: Some(PathBuf::from("mailbox")),
            retention_policy_file: Some(PathBuf::from("mailbox-retention.toml")),
            mailbox_ttl: Some(Duration::from_secs(3600)),
            accounting_dir: Some(PathBuf::from("accounting")),
            abuse_dir: Some(PathBuf::from("abuse")),
            thresholds_file: Some(PathBuf::from("abuse-thresholds.toml")),
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            credentials: Some(HostedCredentialAudit {
                account_id: Some("account.prod".to_string()),
                credentials: 2,
                active: 2,
                revoked: 0,
                expired: 0,
                accounts: 1,
                token_displayed: false,
                contents_displayed: false,
            }),
            tenants: Some(HostedTenantAudit {
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
            }),
            admin_tokens: Some(HostedAdminTokenAudit {
                account_id: Some("account.prod".to_string()),
                records: 2,
                active: 2,
                revoked: 0,
                expired: 0,
                account_scoped_records: 2,
                global_records: 0,
                accounts: 1,
                expiring_records: 1,
                next_expires_at_unix: Some(1_763_596_900),
                last_expires_at_unix: Some(1_763_596_900),
                scope_credentials: 1,
                scope_tenants: 1,
                scope_dashboard: 1,
                scope_sessions: 1,
                scope_mailbox_audit: 1,
                scope_mailbox_purge: 1,
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            }),
            session_state: Some(RelaySessionAudit {
                node_id: Some("node.hosted".to_string()),
                records: 1,
                active_records: 1,
                expired_records: 0,
                invalid_records: 0,
                oldest_created_unix_millis: Some(1_763_596_000_000),
                newest_last_seen_unix_millis: Some(1_763_596_500_000),
                next_expires_unix_millis: Some(1_763_600_000_000),
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            }),
            mailbox: Some(RelayMailboxAudit {
                node_id: Some("node.hosted".to_string()),
                retention_ttl_seconds: Some(3600),
                nodes: 1,
                records: 2,
                invalid_records: 0,
                bytes: 2048,
                oldest_queued_unix_millis: Some(1_763_596_000_000),
                newest_queued_unix_millis: Some(1_763_596_500_000),
                expired_records: Some(0),
                expired_bytes: Some(0),
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            }),
            accounting: Some(RelayAccountingAudit {
                node_id: Some("node.hosted".to_string()),
                records: 1,
                window_started_unix: Some(1_763_596_000),
                sessions_authenticated: 2,
                sessions_resumed: 1,
                envelopes_sent: 3,
                bytes_sent: 300,
                envelopes_received: 4,
                bytes_received: 400,
                envelopes_mailboxed: 1,
                bytes_mailboxed: 100,
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
                window_started_unix: Some(1_763_596_000),
                admin_unauthorized: 0,
                admin_failed: 0,
                unauthorized_sessions: 0,
                credential_denied_sessions: 0,
                tenant_denied_sessions: 0,
                rate_limited_sessions: 0,
                session_expired: 0,
                quota_denied_forwards: 0,
                undelivered_forwards: 0,
                mailbox_rejected_forwards: 0,
                malformed_client_frames: 0,
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            }),
            abuse_threshold_report: Some(build_abuse_threshold_report(
                "local",
                None,
                Some(PathBuf::from("abuse")),
                None,
                Some("node.hosted".to_string()),
                1,
                Some(1_763_596_000),
                AbuseThresholds {
                    rate_limited_sessions: Some(0),
                    admin_failed: Some(1),
                    ..AbuseThresholds::default()
                },
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
            )),
        };
        assert_eq!(report.status(), "ready");
        assert_eq!(report.warning_count(), 0);
        assert_eq!(report.checked_surfaces(), 7);
        assert!(report.public_bind_has_credentials());
        assert!(report.display_guards_clean());

        let secret_token = "hosted-readiness-admin-token-123456";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";
        let outputs = [
            render_hosted_readiness_text(&report),
            render_hosted_readiness_json(&report),
        ];
        for output in outputs {
            assert!(output.contains("readiness") || output.contains("\"status\""));
            assert!(output.contains("account.prod"));
            assert!(output.contains("node.hosted"));
            assert!(output.contains("false") || output.contains("no"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let mut warning_report = report;
        warning_report.credentials = None;
        warning_report.abuse_threshold_report = Some(build_abuse_threshold_report(
            "local",
            None,
            Some(PathBuf::from("abuse")),
            None,
            Some("node.hosted".to_string()),
            1,
            Some(1_763_596_000),
            AbuseThresholds {
                rate_limited_sessions: Some(0),
                ..AbuseThresholds::default()
            },
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        ));
        assert_eq!(warning_report.status(), "needs_attention");
        assert!(warning_report.warning_count() >= 2);
    }

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
        let suspension = HostedAccountSuspension {
            account_id: "account.prod".to_string(),
            credentials_file: PathBuf::from("credentials.toml"),
            tenants_file: PathBuf::from("tenants.toml"),
            credentials: 2,
            active: 0,
            revoked: 2,
            expired: 0,
            accounts: 1,
            tenants: 1,
            active_tenants: 0,
            revoked_tenants: 1,
            nodes: 1,
            active_nodes: 1,
            revoked_nodes: 0,
            tenant_policies: 1,
            token_displayed: false,
            key_material_displayed: false,
            contents_displayed: false,
        };
        let secret_token = "tenant-node-token-secret";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let parsed_suspend = parse_hosted_account_suspend_args(vec![
            "account.prod".to_string(),
            "--credentials-file".to_string(),
            "credentials.toml".to_string(),
            "--tenants-file".to_string(),
            "tenants.toml".to_string(),
            "--json".to_string(),
        ])
        .expect("hosted account suspend args parse");
        assert_eq!(parsed_suspend.account_id, "account.prod");
        assert_eq!(
            parsed_suspend.credentials_file,
            PathBuf::from("credentials.toml")
        );
        assert_eq!(parsed_suspend.tenants_file, PathBuf::from("tenants.toml"));
        assert!(parsed_suspend.json);
        assert!(parse_hosted_account_suspend_args(Vec::new()).is_err());

        let outputs = [
            render_tenant_update_text(&update),
            render_tenant_update_json(&update),
            render_tenant_audit_text(&audit, Path::new("tenants.toml")),
            render_tenant_audit_json(&audit, Path::new("tenants.toml")),
            render_hosted_account_suspend_text(&suspension),
            render_hosted_account_suspend_json(&suspension),
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
    fn hosted_fleet_account_audit_parser_report_and_renderers_are_metadata_only() {
        let fleet_file = write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
            "[[relay]]\nname = \"relay.ok\"\ncredentials_file = \"ok-credentials.toml\"\ntenants_file = \"ok-tenants.toml\"\n\n[[relay]]\nname = \"relay.partial\"\ncredentials_file = \"partial-credentials.toml\"\n\n[[relay]]\nname = \"relay.mismatch\"\ncredentials_file = \"mismatch-credentials.toml\"\ntenants_file = \"mismatch-tenants.toml\"\n",
        ));
        let base_dir = fleet_file.parent().expect("fleet file parent");
        let ok_credentials = base_dir.join("ok-credentials.toml");
        let ok_tenants = base_dir.join("ok-tenants.toml");
        let partial_credentials = base_dir.join("partial-credentials.toml");
        let mismatch_credentials = base_dir.join("mismatch-credentials.toml");
        let mismatch_tenants = base_dir.join("mismatch-tenants.toml");
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let secret_token = "raw-hosted-account-audit-token";

        upsert_hosted_tenant_in_file(&ok_tenants, "account.prod").expect("ok tenant upsert");
        upsert_hosted_tenant_node_in_file(
            &ok_tenants,
            "account.prod",
            "node.prod",
            HostedTenantPermissions {
                messages: true,
                streams: true,
                rooms: true,
                files: false,
                mailbox: true,
            },
            Some("signing.key".to_string()),
            Some("exchange.key".to_string()),
        )
        .expect("ok tenant node upsert");
        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &ok_credentials,
            "account.prod",
            "node.prod",
            secret_hash,
            64,
            None,
            false,
        )
        .expect("ok credential hash upsert");
        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &partial_credentials,
            "account.prod",
            "node.partial",
            secret_hash,
            64,
            None,
            false,
        )
        .expect("partial credential hash upsert");
        upsert_hosted_tenant_in_file(&mismatch_tenants, "account.prod")
            .expect("mismatch tenant upsert");
        revoke_hosted_tenant_in_file(&mismatch_tenants, "account.prod")
            .expect("mismatch tenant revoke");
        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &mismatch_credentials,
            "account.prod",
            "node.mismatch",
            secret_hash,
            64,
            None,
            false,
        )
        .expect("mismatch credential hash upsert");

        let parsed = parse_hosted_fleet_account_audit_args(vec![
            "account.prod".to_string(),
            "--fleet-file".to_string(),
            fleet_file.display().to_string(),
            "--json".to_string(),
            "--fail-on-warning".to_string(),
        ])
        .expect("hosted fleet account audit args parse");
        assert_eq!(parsed.account_id, "account.prod");
        assert_eq!(parsed.node_id, None);
        assert_eq!(parsed.fleet_file, fleet_file);
        assert!(parsed.json);
        assert!(parsed.fail_on_warning);
        assert!(parse_hosted_fleet_account_audit_args(Vec::new()).is_err());
        let invalid_account = parse_hosted_fleet_account_audit_args(vec![
            "bad secret value".to_string(),
            "--fleet-file".to_string(),
            parsed.fleet_file.display().to_string(),
        ])
        .expect_err("invalid account should fail closed");
        assert!(!invalid_account.contains("bad secret value"));
        let invalid_node = parse_hosted_fleet_account_audit_args(vec![
            "account.prod".to_string(),
            "--fleet-file".to_string(),
            parsed.fleet_file.display().to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
        ])
        .expect_err("invalid node should fail closed");
        assert!(!invalid_node.contains("bad secret value"));

        let report =
            hosted_fleet_account_audit_report(&parsed).expect("hosted fleet account audit report");
        assert_eq!(report.totals.relays, 3);
        assert_eq!(report.totals.account_sources, 3);
        assert_eq!(report.totals.credential_sources, 3);
        assert_eq!(report.totals.tenant_sources, 2);
        assert_eq!(report.totals.active, 3);
        assert_eq!(report.totals.active_tenants, 1);
        assert_eq!(report.totals.revoked_tenants, 1);
        assert_eq!(report.totals.warnings, 4);
        assert_eq!(
            hosted_fleet_account_audit_exit(&report, true),
            HostedFleetAccountAuditExit::Warning
        );
        assert_eq!(
            hosted_fleet_account_audit_exit(&report, false),
            HostedFleetAccountAuditExit::Success
        );

        let outputs = [
            render_hosted_fleet_account_audit_text(&report),
            render_hosted_fleet_account_audit_json(&report),
        ];
        for output in outputs {
            assert!(output.contains("fleet"));
            assert!(output.contains("warning"));
            assert!(output.contains("missing_tenants_source"));
            assert!(output.contains("active_credentials_without_active_tenant"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let node_parsed = parse_hosted_fleet_account_audit_args(vec![
            "account.prod".to_string(),
            "--fleet-file".to_string(),
            fleet_file.display().to_string(),
            "--node".to_string(),
            "node.prod".to_string(),
            "--json".to_string(),
            "--fail-on-warning".to_string(),
        ])
        .expect("hosted fleet account node audit args parse");
        assert_eq!(node_parsed.node_id.as_deref(), Some("node.prod"));
        let node_report = hosted_fleet_account_audit_report(&node_parsed)
            .expect("hosted fleet account node audit report");
        assert_eq!(node_report.node_id.as_deref(), Some("node.prod"));
        assert_eq!(node_report.totals.account_sources, 3);
        assert_eq!(node_report.totals.active, 1);
        assert_eq!(node_report.totals.accounts, 1);
        assert_eq!(node_report.totals.active_tenants, 1);
        assert_eq!(node_report.totals.active_nodes, 1);
        assert_eq!(node_report.totals.warnings, 4);
        let node_outputs = [
            render_hosted_fleet_account_audit_text(&node_report),
            render_hosted_fleet_account_audit_json(&node_report),
        ];
        for output in node_outputs {
            assert!(output.contains("node.prod"));
            assert!(output.contains("node_missing_credentials"));
            assert!(output.contains("tenant_node_missing"));
            assert!(output.contains("missing_tenants_source"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let no_account_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.abuse\"\nabuse_dir = \"abuse\"\n",
            ));
        let no_account_error = hosted_fleet_account_audit_report(&HostedFleetAccountAuditArgs {
            account_id: "account.prod".to_string(),
            node_id: None,
            fleet_file: no_account_fleet,
            json: false,
            fail_on_warning: false,
        })
        .expect_err("account audit should require an account source");
        assert!(no_account_error.contains("credentials_file or tenants_file"));
    }

    #[test]
    fn hosted_fleet_account_suspend_parser_report_and_renderers_are_metadata_only() {
        let fleet_file = write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
            "[[relay]]\nname = \"relay.a\"\ncredentials_file = \"credentials.toml\"\ntenants_file = \"tenants.toml\"\n",
        ));
        let base_dir = fleet_file.parent().expect("fleet file parent");
        let credentials_file = base_dir.join("credentials.toml");
        let tenants_file = base_dir.join("tenants.toml");
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let secret_token = "raw-hosted-account-token";

        upsert_hosted_tenant_in_file(&tenants_file, "account.prod").expect("hosted tenant upsert");
        upsert_hosted_tenant_node_in_file(
            &tenants_file,
            "account.prod",
            "node.prod",
            HostedTenantPermissions {
                messages: true,
                streams: true,
                rooms: false,
                files: false,
                mailbox: true,
            },
            Some("signing.key".to_string()),
            Some("exchange.key".to_string()),
        )
        .expect("hosted tenant node upsert");
        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &credentials_file,
            "account.prod",
            "node.prod",
            secret_hash,
            64,
            None,
            false,
        )
        .expect("hosted credential hash upsert");
        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &credentials_file,
            "account.other",
            "node.other",
            "1111111111111111111111111111111111111111111111111111111111111111",
            64,
            None,
            false,
        )
        .expect("other account credential hash upsert");

        let parsed = parse_hosted_fleet_account_suspend_args(vec![
            "account.prod".to_string(),
            "--fleet-file".to_string(),
            fleet_file.display().to_string(),
            "--dry-run".to_string(),
            "--json".to_string(),
        ])
        .expect("hosted fleet account suspend args parse");
        assert_eq!(parsed.account_id, "account.prod");
        assert_eq!(parsed.node_id, None);
        assert_eq!(parsed.fleet_file, fleet_file);
        assert!(parsed.dry_run);
        assert!(parsed.json);
        assert!(parse_hosted_fleet_account_suspend_args(Vec::new()).is_err());
        assert!(
            parse_hosted_fleet_account_suspend_args(vec![
                "account.prod".to_string(),
                "--fleet-file".to_string(),
                parsed.fleet_file.display().to_string(),
            ])
            .is_err()
        );
        let invalid_account = parse_hosted_fleet_account_suspend_args(vec![
            "bad secret value".to_string(),
            "--fleet-file".to_string(),
            parsed.fleet_file.display().to_string(),
            "--dry-run".to_string(),
        ])
        .expect_err("invalid account should fail closed");
        assert!(!invalid_account.contains("bad secret value"));
        let invalid_node = parse_hosted_fleet_account_suspend_args(vec![
            "account.prod".to_string(),
            "--fleet-file".to_string(),
            parsed.fleet_file.display().to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
            "--dry-run".to_string(),
        ])
        .expect_err("invalid node should fail closed");
        assert!(!invalid_node.contains("bad secret value"));

        let dry_report = hosted_fleet_account_suspension_report(&parsed)
            .expect("hosted fleet account dry-run report");
        assert!(dry_report.dry_run);
        assert_eq!(dry_report.totals.account_sources, 1);
        assert_eq!(dry_report.totals.accounts, 2);
        assert_eq!(dry_report.totals.credentials, 1);
        assert_eq!(dry_report.totals.active, 1);
        assert_eq!(dry_report.totals.revoked, 0);
        assert_eq!(dry_report.totals.active_tenants, 1);

        let tenant_after_dry_run = audit_hosted_tenants_file(&tenants_file, Some("account.prod"))
            .expect("tenant audit after dry-run");
        assert_eq!(tenant_after_dry_run.active_tenants, 1);

        let confirmed = hosted_fleet_account_suspension_report(&HostedFleetAccountSuspendArgs {
            account_id: "account.prod".to_string(),
            node_id: None,
            fleet_file: parsed.fleet_file.clone(),
            dry_run: false,
            json: true,
        })
        .expect("hosted fleet account confirmed report");
        assert!(!confirmed.dry_run);
        assert_eq!(confirmed.totals.account_sources, 1);
        assert_eq!(confirmed.totals.accounts, 2);
        assert_eq!(confirmed.totals.active, 0);
        assert_eq!(confirmed.totals.revoked, 1);
        assert_eq!(confirmed.totals.active_tenants, 0);
        assert_eq!(confirmed.totals.revoked_tenants, 1);

        let outputs = [
            render_hosted_fleet_account_suspend_text(&dry_report),
            render_hosted_fleet_account_suspend_json(&dry_report),
            render_hosted_fleet_account_suspend_text(&confirmed),
            render_hosted_fleet_account_suspend_json(&confirmed),
        ];
        for output in outputs {
            assert!(output.contains("fleet"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let node_fleet_file = write_hosted_fleet_dashboard_file(
            &hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.node\"\ncredentials_file = \"node-credentials.toml\"\ntenants_file = \"node-tenants.toml\"\n",
            ),
        );
        let node_base_dir = node_fleet_file.parent().expect("node fleet file parent");
        let node_credentials_file = node_base_dir.join("node-credentials.toml");
        let node_tenants_file = node_base_dir.join("node-tenants.toml");
        let node_secret_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        upsert_hosted_tenant_in_file(&node_tenants_file, "account.prod")
            .expect("node hosted tenant upsert");
        upsert_hosted_tenant_node_in_file(
            &node_tenants_file,
            "account.prod",
            "node.prod",
            HostedTenantPermissions {
                messages: true,
                streams: false,
                rooms: false,
                files: false,
                mailbox: true,
            },
            Some("signing.node".to_string()),
            Some("exchange.node".to_string()),
        )
        .expect("node hosted tenant node upsert");
        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &node_credentials_file,
            "account.prod",
            "node.prod",
            node_secret_hash,
            64,
            None,
            false,
        )
        .expect("node hosted credential hash upsert");

        let node_parsed = parse_hosted_fleet_account_suspend_args(vec![
            "account.prod".to_string(),
            "--fleet-file".to_string(),
            node_fleet_file.display().to_string(),
            "--node".to_string(),
            "node.prod".to_string(),
            "--dry-run".to_string(),
            "--json".to_string(),
        ])
        .expect("hosted fleet account node suspend args parse");
        assert_eq!(node_parsed.node_id.as_deref(), Some("node.prod"));
        let node_dry_report = hosted_fleet_account_suspension_report(&node_parsed)
            .expect("hosted fleet account node dry-run report");
        assert_eq!(node_dry_report.node_id.as_deref(), Some("node.prod"));
        assert!(node_dry_report.dry_run);
        assert_eq!(node_dry_report.totals.account_sources, 1);
        assert_eq!(node_dry_report.totals.active, 1);
        assert_eq!(node_dry_report.totals.active_tenants, 1);
        assert_eq!(node_dry_report.totals.active_nodes, 1);
        let node_tenant_after_dry_run = audit_hosted_tenants_file_with_node(
            &node_tenants_file,
            Some("account.prod"),
            Some("node.prod"),
        )
        .expect("tenant node audit after dry-run");
        assert_eq!(node_tenant_after_dry_run.active_nodes, 1);

        let node_confirmed =
            hosted_fleet_account_suspension_report(&HostedFleetAccountSuspendArgs {
                account_id: "account.prod".to_string(),
                node_id: Some("node.prod".to_string()),
                fleet_file: node_parsed.fleet_file.clone(),
                dry_run: false,
                json: true,
            })
            .expect("hosted fleet account node confirmed report");
        assert!(!node_confirmed.dry_run);
        assert_eq!(node_confirmed.totals.account_sources, 1);
        assert_eq!(node_confirmed.totals.active, 0);
        assert_eq!(node_confirmed.totals.revoked, 1);
        assert_eq!(node_confirmed.totals.active_tenants, 1);
        assert_eq!(node_confirmed.totals.active_nodes, 0);
        assert_eq!(node_confirmed.totals.revoked_nodes, 1);
        let node_credentials_after_confirm = audit_hosted_relay_credentials_file_with_node(
            &node_credentials_file,
            Some("account.prod"),
            Some("node.prod"),
        )
        .expect("credential node audit after confirm");
        assert_eq!(node_credentials_after_confirm.revoked, 1);

        let node_outputs = [
            render_hosted_fleet_account_suspend_text(&node_dry_report),
            render_hosted_fleet_account_suspend_json(&node_dry_report),
            render_hosted_fleet_account_suspend_text(&node_confirmed),
            render_hosted_fleet_account_suspend_json(&node_confirmed),
        ];
        for output in node_outputs {
            assert!(output.contains("node.prod"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(node_secret_hash));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let partial_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.partial\"\ncredentials_file = \"credentials.toml\"\n",
            ));
        let partial_error =
            hosted_fleet_account_suspension_report(&HostedFleetAccountSuspendArgs {
                account_id: "account.prod".to_string(),
                node_id: None,
                fleet_file: partial_fleet,
                dry_run: true,
                json: false,
            })
            .expect_err("partial account source should fail closed");
        assert!(partial_error.contains("requires tenants_file"));
    }

    #[test]
    fn hosted_fleet_credential_revoke_parser_report_and_renderers_are_metadata_only() {
        let fleet_file = write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
            "[[relay]]\nname = \"relay.a\"\ncredentials_file = \"credentials.toml\"\n\n[[relay]]\nname = \"relay.metrics\"\nabuse_dir = \"abuse\"\n",
        ));
        let base_dir = fleet_file.parent().expect("fleet file parent");
        let credentials_file = base_dir.join("credentials.toml");
        let secret_token = "raw-hosted-fleet-credential-revoke-token-123456";
        let secret_hash = relay_token_sha256_hex(secret_token).expect("secret hash");

        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &credentials_file,
            "account.prod",
            "node.prod",
            secret_hash.clone(),
            secret_token.len(),
            None,
            false,
        )
        .expect("hosted credential hash upsert");

        let parsed = parse_hosted_fleet_credential_revoke_args(vec![
            "account.prod".to_string(),
            "node.prod".to_string(),
            "--fleet-file".to_string(),
            fleet_file.display().to_string(),
            "--dry-run".to_string(),
            "--json".to_string(),
        ])
        .expect("hosted fleet credential revoke args parse");
        assert_eq!(parsed.account_id, "account.prod");
        assert_eq!(parsed.node_id, "node.prod");
        assert_eq!(parsed.fleet_file, fleet_file);
        assert!(parsed.dry_run);
        assert!(parsed.json);
        assert!(parse_hosted_fleet_credential_revoke_args(Vec::new()).is_err());
        assert!(
            parse_hosted_fleet_credential_revoke_args(vec![
                "account.prod".to_string(),
                "node.prod".to_string(),
                "--fleet-file".to_string(),
                parsed.fleet_file.display().to_string(),
            ])
            .is_err()
        );
        let invalid_account = parse_hosted_fleet_credential_revoke_args(vec![
            "bad secret value".to_string(),
            "node.prod".to_string(),
            "--fleet-file".to_string(),
            parsed.fleet_file.display().to_string(),
            "--dry-run".to_string(),
        ])
        .expect_err("invalid account should fail closed");
        assert!(!invalid_account.contains("bad secret value"));
        let invalid_node = parse_hosted_fleet_credential_revoke_args(vec![
            "account.prod".to_string(),
            "bad secret value".to_string(),
            "--fleet-file".to_string(),
            parsed.fleet_file.display().to_string(),
            "--dry-run".to_string(),
        ])
        .expect_err("invalid node should fail closed");
        assert!(!invalid_node.contains("bad secret value"));

        let dry_report = hosted_fleet_credential_revoke_report(&parsed)
            .expect("hosted fleet credential revoke dry-run report");
        assert!(dry_report.dry_run);
        assert_eq!(dry_report.totals.relays, 2);
        assert_eq!(dry_report.totals.credential_sources, 1);
        assert_eq!(dry_report.totals.credentials, 1);
        assert_eq!(dry_report.totals.active, 1);
        assert_eq!(dry_report.totals.revoked, 0);
        let dry_audit = audit_hosted_relay_credentials_file_with_node(
            &credentials_file,
            Some("account.prod"),
            Some("node.prod"),
        )
        .expect("credential audit after dry-run");
        assert_eq!(dry_audit.active, 1);

        let confirmed = hosted_fleet_credential_revoke_report(&HostedFleetCredentialRevokeArgs {
            dry_run: false,
            json: true,
            ..parsed.clone()
        })
        .expect("hosted fleet credential revoke confirmed report");
        assert!(!confirmed.dry_run);
        assert_eq!(confirmed.totals.credential_sources, 1);
        assert_eq!(confirmed.totals.credentials, 1);
        assert_eq!(confirmed.totals.active, 0);
        assert_eq!(confirmed.totals.revoked, 1);
        let confirmed_audit = audit_hosted_relay_credentials_file_with_node(
            &credentials_file,
            Some("account.prod"),
            Some("node.prod"),
        )
        .expect("credential audit after confirm");
        assert_eq!(confirmed_audit.revoked, 1);

        let outputs = [
            render_hosted_fleet_credential_revoke_text(&dry_report),
            render_hosted_fleet_credential_revoke_json(&dry_report),
            render_hosted_fleet_credential_revoke_text(&confirmed),
            render_hosted_fleet_credential_revoke_json(&confirmed),
        ];
        for output in outputs {
            assert!(output.contains("credential"));
            assert!(output.contains("revoke"));
            assert!(output.contains("account.prod"));
            assert!(output.contains("node.prod"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(&secret_hash));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let no_credentials_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.tenants\"\ntenants_file = \"tenants.toml\"\n",
            ));
        let no_credentials_error =
            hosted_fleet_credential_revoke_report(&HostedFleetCredentialRevokeArgs {
                account_id: "account.prod".to_string(),
                node_id: "node.prod".to_string(),
                fleet_file: no_credentials_fleet,
                dry_run: true,
                json: false,
            })
            .expect_err("credential revoke should require credential sources");
        assert!(no_credentials_error.contains("credentials_file"));

        let collision_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.collision\"\ncredentials_file = \"credentials.toml\"\n",
            ));
        let collision_credentials = collision_fleet
            .parent()
            .expect("collision fleet parent")
            .join("credentials.toml");
        conu_relay::upsert_hosted_relay_credential_hash_in_file(
            &collision_credentials,
            "account.other",
            "node.prod",
            secret_hash.clone(),
            secret_token.len(),
            None,
            false,
        )
        .expect("collision credential hash upsert");
        let collision_error =
            hosted_fleet_credential_revoke_report(&HostedFleetCredentialRevokeArgs {
                account_id: "account.prod".to_string(),
                node_id: "node.prod".to_string(),
                fleet_file: collision_fleet,
                dry_run: true,
                json: false,
            })
            .expect_err("credential revoke should reject account collision");
        assert!(collision_error.contains("different account"));
        assert!(!collision_error.contains(secret_token));
        assert!(!collision_error.contains(&secret_hash));

        let duplicate_collision_fleet = write_hosted_fleet_dashboard_file(
            &hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.duplicate-collision\"\ncredentials_file = \"credentials.toml\"\n",
            ),
        );
        let duplicate_collision_credentials = duplicate_collision_fleet
            .parent()
            .expect("duplicate collision fleet parent")
            .join("credentials.toml");
        fs::write(
            &duplicate_collision_credentials,
            format!(
                "version = \"1\"\n\n\
[[credential]]\n\
account_id = \"account.prod\"\n\
node_id = \"node.prod\"\n\
token_sha256_hex = \"{secret_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
payload_displayed = false\n\
token_displayed = false\n\n\
[[credential]]\n\
account_id = \"account.other\"\n\
node_id = \"node.prod\"\n\
token_sha256_hex = \"{secret_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
payload_displayed = false\n\
token_displayed = false\n",
                secret_token.len(),
                secret_token.len()
            ),
        )
        .expect("duplicate collision credentials write");
        let duplicate_collision_error =
            hosted_fleet_credential_revoke_report(&HostedFleetCredentialRevokeArgs {
                account_id: "account.prod".to_string(),
                node_id: "node.prod".to_string(),
                fleet_file: duplicate_collision_fleet,
                dry_run: true,
                json: false,
            })
            .expect_err("credential revoke should reject duplicate account collision");
        assert!(duplicate_collision_error.contains("different account"));
        assert!(!duplicate_collision_error.contains(secret_token));
        assert!(!duplicate_collision_error.contains(&secret_hash));

        let duplicate_same_account_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.duplicate\"\ncredentials_file = \"credentials.toml\"\n",
            ));
        let duplicate_same_account_credentials = duplicate_same_account_fleet
            .parent()
            .expect("duplicate same-account fleet parent")
            .join("credentials.toml");
        fs::write(
            &duplicate_same_account_credentials,
            format!(
                "version = \"1\"\n\n\
[[credential]]\n\
account_id = \"account.prod\"\n\
node_id = \"node.prod\"\n\
token_sha256_hex = \"{secret_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
payload_displayed = false\n\
token_displayed = false\n\n\
[[credential]]\n\
account_id = \"account.prod\"\n\
node_id = \"node.prod\"\n\
token_sha256_hex = \"{secret_hash}\"\n\
token_length = {}\n\
status = \"active\"\n\
payload_displayed = false\n\
token_displayed = false\n",
                secret_token.len(),
                secret_token.len()
            ),
        )
        .expect("duplicate same-account credentials write");
        let duplicate_same_account_error =
            hosted_fleet_credential_revoke_report(&HostedFleetCredentialRevokeArgs {
                account_id: "account.prod".to_string(),
                node_id: "node.prod".to_string(),
                fleet_file: duplicate_same_account_fleet,
                dry_run: true,
                json: false,
            })
            .expect_err("credential revoke should reject duplicate node records");
        assert!(duplicate_same_account_error.contains("duplicate records"));
        assert!(!duplicate_same_account_error.contains(secret_token));
        assert!(!duplicate_same_account_error.contains(&secret_hash));
    }

    #[test]
    fn hosted_fleet_tenant_account_lifecycle_parser_report_and_renderers_are_metadata_only() {
        let fleet_file = write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
            "[[relay]]\nname = \"relay.a\"\ntenants_file = \"tenants.toml\"\n\n[[relay]]\nname = \"relay.metrics\"\nabuse_dir = \"abuse\"\n",
        ));
        let base_dir = fleet_file.parent().expect("fleet file parent");
        let tenants_file = base_dir.join("tenants.toml");
        let secret_token = "raw-hosted-fleet-tenant-account-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let signing_key_id = "signing.secret";
        let exchange_key_id = "exchange.secret";

        let parsed = parse_hosted_fleet_tenant_account_lifecycle_args(
            vec![
                "account.prod".to_string(),
                "--fleet-file".to_string(),
                fleet_file.display().to_string(),
                "--dry-run".to_string(),
                "--json".to_string(),
            ],
            HostedFleetTenantAccountLifecycleMode::Upsert,
        )
        .expect("hosted fleet tenant account upsert args parse");
        assert_eq!(parsed.account_id, "account.prod");
        assert_eq!(parsed.fleet_file, fleet_file);
        assert!(parsed.dry_run);
        assert!(parsed.json);
        assert_eq!(parsed.mode, HostedFleetTenantAccountLifecycleMode::Upsert);
        assert!(
            parse_hosted_fleet_tenant_account_lifecycle_args(
                Vec::new(),
                HostedFleetTenantAccountLifecycleMode::Upsert,
            )
            .is_err()
        );
        assert!(
            parse_hosted_fleet_tenant_account_lifecycle_args(
                vec![
                    "account.prod".to_string(),
                    "--fleet-file".to_string(),
                    parsed.fleet_file.display().to_string(),
                ],
                HostedFleetTenantAccountLifecycleMode::Upsert,
            )
            .is_err()
        );
        let invalid_account = parse_hosted_fleet_tenant_account_lifecycle_args(
            vec![
                "bad secret value".to_string(),
                "--fleet-file".to_string(),
                parsed.fleet_file.display().to_string(),
                "--dry-run".to_string(),
            ],
            HostedFleetTenantAccountLifecycleMode::Upsert,
        )
        .expect_err("invalid account should fail closed");
        assert!(!invalid_account.contains("bad secret value"));

        let dry_report = hosted_fleet_tenant_account_lifecycle_report(&parsed)
            .expect("hosted fleet tenant account upsert dry-run report");
        assert!(dry_report.dry_run);
        assert_eq!(dry_report.totals.relays, 2);
        assert_eq!(dry_report.totals.tenant_sources, 1);
        assert_eq!(dry_report.totals.tenants, 0);
        assert!(!tenants_file.exists());

        let confirmed =
            hosted_fleet_tenant_account_lifecycle_report(&HostedFleetTenantAccountLifecycleArgs {
                dry_run: false,
                json: true,
                ..parsed.clone()
            })
            .expect("hosted fleet tenant account upsert confirmed report");
        assert!(!confirmed.dry_run);
        assert_eq!(confirmed.totals.tenant_sources, 1);
        assert_eq!(confirmed.totals.tenants, 1);
        assert_eq!(confirmed.totals.active_tenants, 1);
        let confirmed_audit =
            audit_hosted_tenants_file_with_node(&tenants_file, Some("account.prod"), None)
                .expect("tenant audit after account upsert");
        assert_eq!(confirmed_audit.active_tenants, 1);

        upsert_hosted_tenant_node_in_file(
            &tenants_file,
            "account.prod",
            "node.prod",
            HostedTenantPermissions {
                messages: true,
                streams: true,
                rooms: false,
                files: false,
                mailbox: true,
            },
            Some(signing_key_id.to_string()),
            Some(exchange_key_id.to_string()),
        )
        .expect("hosted tenant node upserts");

        let revoke_parsed = parse_hosted_fleet_tenant_account_lifecycle_args(
            vec![
                "account.prod".to_string(),
                "--fleet-file".to_string(),
                parsed.fleet_file.display().to_string(),
                "--dry-run".to_string(),
                "--json".to_string(),
            ],
            HostedFleetTenantAccountLifecycleMode::Revoke,
        )
        .expect("hosted fleet tenant account revoke args parse");
        assert_eq!(
            revoke_parsed.mode,
            HostedFleetTenantAccountLifecycleMode::Revoke
        );
        let revoke_dry = hosted_fleet_tenant_account_lifecycle_report(&revoke_parsed)
            .expect("hosted fleet tenant account revoke dry-run report");
        assert!(revoke_dry.dry_run);
        assert_eq!(revoke_dry.totals.active_tenants, 1);
        assert_eq!(revoke_dry.totals.active_nodes, 1);

        let revoke_confirmed =
            hosted_fleet_tenant_account_lifecycle_report(&HostedFleetTenantAccountLifecycleArgs {
                dry_run: false,
                json: true,
                ..revoke_parsed.clone()
            })
            .expect("hosted fleet tenant account revoke confirmed report");
        assert_eq!(revoke_confirmed.totals.active_tenants, 0);
        assert_eq!(revoke_confirmed.totals.revoked_tenants, 1);
        assert_eq!(revoke_confirmed.totals.active_nodes, 1);

        let outputs = [
            render_hosted_fleet_tenant_account_lifecycle_text(&dry_report),
            render_hosted_fleet_tenant_account_lifecycle_json(&dry_report),
            render_hosted_fleet_tenant_account_lifecycle_text(&confirmed),
            render_hosted_fleet_tenant_account_lifecycle_json(&confirmed),
            render_hosted_fleet_tenant_account_lifecycle_text(&revoke_dry),
            render_hosted_fleet_tenant_account_lifecycle_json(&revoke_dry),
            render_hosted_fleet_tenant_account_lifecycle_text(&revoke_confirmed),
            render_hosted_fleet_tenant_account_lifecycle_json(&revoke_confirmed),
        ];
        for output in outputs {
            assert!(output.contains("tenant"));
            assert!(output.contains("account.prod"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(signing_key_id));
            assert!(!output.contains(exchange_key_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let no_tenants_fleet = write_hosted_fleet_dashboard_file(
            &hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.credentials\"\ncredentials_file = \"credentials.toml\"\n",
            ),
        );
        let no_tenants_error =
            hosted_fleet_tenant_account_lifecycle_report(&HostedFleetTenantAccountLifecycleArgs {
                account_id: "account.prod".to_string(),
                fleet_file: no_tenants_fleet,
                dry_run: true,
                json: false,
                mode: HostedFleetTenantAccountLifecycleMode::Upsert,
            })
            .expect_err("tenant account lifecycle should require tenant sources");
        assert!(no_tenants_error.contains("tenants_file"));

        let missing_revoke_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.missing\"\ntenants_file = \"tenants.toml\"\n",
            ));
        let missing_revoke_error =
            hosted_fleet_tenant_account_lifecycle_report(&HostedFleetTenantAccountLifecycleArgs {
                account_id: "account.prod".to_string(),
                fleet_file: missing_revoke_fleet,
                dry_run: true,
                json: false,
                mode: HostedFleetTenantAccountLifecycleMode::Revoke,
            })
            .expect_err("tenant account revoke should require existing account");
        assert!(missing_revoke_error.contains("account was not found"));
        assert!(!missing_revoke_error.contains(secret_token));
        assert!(!missing_revoke_error.contains(secret_hash));
    }

    #[test]
    fn hosted_fleet_tenant_node_lifecycle_parser_report_and_renderers_are_metadata_only() {
        let fleet_file = write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
            "[[relay]]\nname = \"relay.a\"\ntenants_file = \"tenants.toml\"\n\n[[relay]]\nname = \"relay.metrics\"\nabuse_dir = \"abuse\"\n",
        ));
        let base_dir = fleet_file.parent().expect("fleet file parent");
        let tenants_file = base_dir.join("tenants.toml");
        let secret_token = "raw-hosted-tenant-node-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let signing_key_id = "signing.secret";
        let exchange_key_id = "exchange.secret";

        upsert_hosted_tenant_in_file(&tenants_file, "account.prod").expect("hosted tenant upserts");

        let parsed = parse_hosted_fleet_tenant_node_lifecycle_args(
            vec![
                "account.prod".to_string(),
                "node.prod".to_string(),
                "--fleet-file".to_string(),
                fleet_file.display().to_string(),
                "--messages".to_string(),
                "true".to_string(),
                "--streams".to_string(),
                "true".to_string(),
                "--mailbox".to_string(),
                "true".to_string(),
                "--signing-key-id".to_string(),
                signing_key_id.to_string(),
                "--exchange-key-id".to_string(),
                exchange_key_id.to_string(),
                "--dry-run".to_string(),
                "--json".to_string(),
            ],
            HostedFleetTenantNodeLifecycleMode::Upsert,
        )
        .expect("hosted fleet tenant node upsert args parse");
        assert_eq!(parsed.account_id, "account.prod");
        assert_eq!(parsed.node_id, "node.prod");
        assert_eq!(parsed.fleet_file, fleet_file);
        assert!(parsed.permissions.messages);
        assert!(parsed.permissions.streams);
        assert!(!parsed.permissions.rooms);
        assert!(!parsed.permissions.files);
        assert!(parsed.permissions.mailbox);
        assert!(parsed.signing_key_id.is_some());
        assert!(parsed.exchange_key_id.is_some());
        assert!(parsed.dry_run);
        assert!(parsed.json);
        assert!(
            parse_hosted_fleet_tenant_node_lifecycle_args(
                Vec::new(),
                HostedFleetTenantNodeLifecycleMode::Upsert,
            )
            .is_err()
        );
        let invalid_account = parse_hosted_fleet_tenant_node_lifecycle_args(
            vec![
                "bad secret value".to_string(),
                "node.prod".to_string(),
                "--fleet-file".to_string(),
                parsed.fleet_file.display().to_string(),
                "--dry-run".to_string(),
            ],
            HostedFleetTenantNodeLifecycleMode::Upsert,
        )
        .expect_err("invalid account should fail closed");
        assert!(!invalid_account.contains("bad secret value"));

        let dry_report = hosted_fleet_tenant_node_lifecycle_report(&parsed)
            .expect("hosted fleet tenant node upsert dry-run report");
        assert!(dry_report.dry_run);
        assert_eq!(dry_report.totals.relays, 2);
        assert_eq!(dry_report.totals.tenant_sources, 1);
        assert_eq!(dry_report.totals.active_tenants, 1);
        assert_eq!(dry_report.totals.nodes, 0);
        let dry_node_audit = audit_hosted_tenants_file_with_node(
            &tenants_file,
            Some("account.prod"),
            Some("node.prod"),
        )
        .expect("tenant node audit after dry-run");
        assert_eq!(dry_node_audit.nodes, 0);

        let confirmed =
            hosted_fleet_tenant_node_lifecycle_report(&HostedFleetTenantNodeLifecycleArgs {
                dry_run: false,
                json: true,
                ..parsed.clone()
            })
            .expect("hosted fleet tenant node upsert confirmed report");
        assert!(!confirmed.dry_run);
        assert_eq!(confirmed.totals.tenant_sources, 1);
        assert_eq!(confirmed.totals.active_tenants, 1);
        assert_eq!(confirmed.totals.nodes, 1);
        assert_eq!(confirmed.totals.active_nodes, 1);
        assert_eq!(confirmed.totals.tenant_policies, 1);

        let upsert_outputs = [
            render_hosted_fleet_tenant_node_lifecycle_text(&dry_report),
            render_hosted_fleet_tenant_node_lifecycle_json(&dry_report),
            render_hosted_fleet_tenant_node_lifecycle_text(&confirmed),
            render_hosted_fleet_tenant_node_lifecycle_json(&confirmed),
        ];
        for output in upsert_outputs {
            assert!(output.contains("tenant"));
            assert!(output.contains("account.prod"));
            assert!(output.contains("node.prod"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(signing_key_id));
            assert!(!output.contains(exchange_key_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let revoke_parsed = parse_hosted_fleet_tenant_node_lifecycle_args(
            vec![
                "account.prod".to_string(),
                "node.prod".to_string(),
                "--fleet-file".to_string(),
                fleet_file.display().to_string(),
                "--dry-run".to_string(),
                "--json".to_string(),
            ],
            HostedFleetTenantNodeLifecycleMode::Revoke,
        )
        .expect("hosted fleet tenant node revoke args parse");
        assert_eq!(
            revoke_parsed.mode,
            HostedFleetTenantNodeLifecycleMode::Revoke
        );
        let revoke_dry = hosted_fleet_tenant_node_lifecycle_report(&revoke_parsed)
            .expect("hosted fleet tenant node revoke dry-run report");
        assert!(revoke_dry.dry_run);
        assert_eq!(revoke_dry.totals.active_nodes, 1);

        let revoke_confirmed =
            hosted_fleet_tenant_node_lifecycle_report(&HostedFleetTenantNodeLifecycleArgs {
                dry_run: false,
                json: true,
                ..revoke_parsed.clone()
            })
            .expect("hosted fleet tenant node revoke confirmed report");
        assert_eq!(revoke_confirmed.totals.active_nodes, 0);
        assert_eq!(revoke_confirmed.totals.revoked_nodes, 1);

        let revoke_outputs = [
            render_hosted_fleet_tenant_node_lifecycle_text(&revoke_dry),
            render_hosted_fleet_tenant_node_lifecycle_json(&revoke_dry),
            render_hosted_fleet_tenant_node_lifecycle_text(&revoke_confirmed),
            render_hosted_fleet_tenant_node_lifecycle_json(&revoke_confirmed),
        ];
        for output in revoke_outputs {
            assert!(output.contains("revoke"));
            assert!(output.contains("node.prod"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(signing_key_id));
            assert!(!output.contains(exchange_key_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }

        let no_tenants_fleet = write_hosted_fleet_dashboard_file(
            &hosted_fleet_dashboard_file_contents(
                "[[relay]]\nname = \"relay.credentials\"\ncredentials_file = \"credentials.toml\"\n",
            ),
        );
        let no_tenants_error =
            hosted_fleet_tenant_node_lifecycle_report(&HostedFleetTenantNodeLifecycleArgs {
                account_id: "account.prod".to_string(),
                node_id: "node.prod".to_string(),
                fleet_file: no_tenants_fleet,
                permissions: HostedTenantPermissions::default(),
                signing_key_id: None,
                exchange_key_id: None,
                dry_run: true,
                json: false,
                mode: HostedFleetTenantNodeLifecycleMode::Upsert,
            })
            .expect_err("tenant node lifecycle should require tenant sources");
        assert!(no_tenants_error.contains("tenants_file"));

        upsert_hosted_tenant_in_file(&tenants_file, "account.other")
            .expect("other hosted tenant upserts");
        upsert_hosted_tenant_node_in_file(
            &tenants_file,
            "account.other",
            "node.shared",
            HostedTenantPermissions::default(),
            None,
            None,
        )
        .expect("other hosted tenant node upserts");
        let collision_error =
            hosted_fleet_tenant_node_lifecycle_report(&HostedFleetTenantNodeLifecycleArgs {
                account_id: "account.prod".to_string(),
                node_id: "node.shared".to_string(),
                fleet_file: parsed.fleet_file.clone(),
                permissions: HostedTenantPermissions::default(),
                signing_key_id: None,
                exchange_key_id: None,
                dry_run: true,
                json: false,
                mode: HostedFleetTenantNodeLifecycleMode::Upsert,
            })
            .expect_err("node owned by a different account should fail preflight");
        assert!(collision_error.contains("different account"));
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
    fn session_audit_parser_and_renderers_are_metadata_only() {
        let parsed = parse_session_audit_args(vec![
            "--session-state-dir".to_string(),
            "sessions".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--json".to_string(),
        ])
        .expect("session audit args parse");
        assert_eq!(parsed.session_state_dir, PathBuf::from("sessions"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert!(parsed.json);

        let audit = RelaySessionAudit {
            node_id: Some("node.hosted".to_string()),
            records: 2,
            active_records: 1,
            expired_records: 1,
            invalid_records: 1,
            oldest_created_unix_millis: Some(1_763_596_800_000),
            newest_last_seen_unix_millis: Some(1_763_596_900_000),
            next_expires_unix_millis: Some(1_763_597_000_000),
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
            render_session_audit_text(&audit, Path::new("sessions")),
            render_session_audit_json(&audit, Path::new("sessions")),
        ];

        for output in outputs {
            assert!(output.contains("session"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("BEGIN PRIVATE KEY"));
            assert!(!output.contains("payload-body"));
            assert!(!output.contains("ciphertext_body"));
        }
        assert!(parse_session_audit_args(Vec::new()).is_err());
        assert!(
            parse_session_audit_args(vec![
                "--session-state-dir".to_string(),
                "sessions".to_string(),
                "--node".to_string(),
                "bad node secret".to_string(),
            ])
            .is_err()
        );
    }

    #[test]
    fn abuse_threshold_policy_file_parser_is_metadata_only() {
        let policy = abuse_threshold_policy_contents(
            "max_admin_unauthorized = 5\nmax_rate_limited_sessions = 10\n",
        );
        let thresholds =
            parse_abuse_threshold_policy_file(&policy).expect("threshold policy parses");
        assert_eq!(thresholds.admin_unauthorized, Some(5));
        assert_eq!(thresholds.rate_limited_sessions, Some(10));

        let displayed_policy = policy.replace("token_displayed = false", "token_displayed = true");
        assert!(
            parse_abuse_threshold_policy_file(&displayed_policy)
                .expect_err("displayed guard true should fail")
                .contains("token_displayed must be false")
        );
        assert!(
            parse_abuse_threshold_policy_file(
                "version = \"1\"\nmax_admin_unauthorized = 0\npayload_displayed = false\n"
            )
            .expect_err("missing display guards should fail")
            .contains("token_displayed = false")
        );
        assert!(
            parse_abuse_threshold_policy_file(&abuse_threshold_policy_contents(
                "unexpected_key = 1\n"
            ))
            .expect_err("unknown key should fail")
            .contains("unsupported key unexpected_key")
        );

        let secret_value = "relay-secret-token";
        let invalid_threshold =
            parse_abuse_threshold_policy_file(&abuse_threshold_policy_contents(&format!(
                "max_admin_unauthorized = \"{secret_value}\"\n"
            )))
            .expect_err("invalid threshold should fail");
        assert!(invalid_threshold.contains("unsigned integer"));
        assert!(!invalid_threshold.contains(secret_value));

        let unknown_secret = parse_abuse_threshold_policy_file(&abuse_threshold_policy_contents(
            &format!("token = \"{secret_value}\"\n"),
        ))
        .expect_err("secret-bearing unknown key should fail");
        assert!(unknown_secret.contains("unsupported key token"));
        assert!(!unknown_secret.contains(secret_value));
    }

    #[test]
    fn abuse_threshold_report_parser_and_renderers_are_metadata_only() {
        let parsed = parse_abuse_threshold_report_args(vec![
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--max-admin-unauthorized".to_string(),
            "0".to_string(),
            "--max-credential-denied-sessions".to_string(),
            "1".to_string(),
            "--max-mailbox-rejected-forwards".to_string(),
            "2".to_string(),
            "--json".to_string(),
            "--fail-on-threshold".to_string(),
        ])
        .expect("abuse threshold report args parse");
        assert_eq!(parsed.abuse_dir, PathBuf::from("abuse"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.thresholds.admin_unauthorized, Some(0));
        assert_eq!(parsed.thresholds.credential_denied_sessions, Some(1));
        assert_eq!(parsed.thresholds.mailbox_rejected_forwards, Some(2));
        assert!(parsed.json);
        assert!(parsed.fail_on_threshold);

        let policy = abuse_threshold_policy_contents(
            "max_admin_unauthorized = 5\nmax_rate_limited_sessions = 10\n",
        );
        let policy_path = write_abuse_threshold_policy_file(&policy);
        let policy_arg = policy_path.to_string_lossy().to_string();
        let parsed_from_file = parse_abuse_threshold_report_args(vec![
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--thresholds-file".to_string(),
            policy_arg,
            "--max-admin-unauthorized".to_string(),
            "0".to_string(),
        ])
        .expect("abuse threshold policy args parse");
        assert_eq!(
            parsed_from_file.thresholds_file.as_deref(),
            Some(policy_path.as_path())
        );
        assert_eq!(parsed_from_file.thresholds.admin_unauthorized, Some(0));
        assert_eq!(parsed_from_file.thresholds.rate_limited_sessions, Some(10));
        let _ = fs::remove_file(&policy_path);
        assert!(
            parse_abuse_threshold_report_args(vec![
                "--abuse-dir".to_string(),
                "abuse".to_string(),
                "--thresholds-file".to_string(),
                "".to_string(),
            ])
            .is_err()
        );

        assert!(parse_abuse_threshold_report_args(Vec::new()).is_err());
        assert!(
            parse_abuse_threshold_report_args(
                vec!["--abuse-dir".to_string(), "abuse".to_string(),]
            )
            .is_err()
        );
        let invalid_filter = parse_abuse_threshold_report_args(vec![
            "--abuse-dir".to_string(),
            "abuse".to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
            "--max-admin-unauthorized".to_string(),
            "0".to_string(),
        ])
        .expect_err("invalid node filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));
        assert!(
            parse_abuse_threshold_report_args(vec![
                "--abuse-dir".to_string(),
                "abuse".to_string(),
                "--max-admin-unauthorized".to_string(),
                "not-a-number".to_string(),
            ])
            .expect_err("invalid threshold should fail")
            .contains("unsigned integer")
        );

        let audit = RelayAbuseAudit {
            node_id: Some("node.hosted".to_string()),
            records: 3,
            window_started_unix: Some(1_763_596_800),
            admin_unauthorized: 1,
            admin_failed: 0,
            unauthorized_sessions: 0,
            credential_denied_sessions: 1,
            tenant_denied_sessions: 0,
            rate_limited_sessions: 0,
            session_expired: 0,
            quota_denied_forwards: 0,
            undelivered_forwards: 0,
            mailbox_rejected_forwards: 1,
            malformed_client_frames: 0,
            payload_displayed: false,
            token_displayed: false,
            token_hash_displayed: false,
            key_material_displayed: false,
            session_id_displayed: false,
            ciphertext_displayed: false,
            contents_displayed: false,
        };
        let report =
            abuse_threshold_report_from_audit(&audit, parsed.thresholds, parsed.abuse_dir.clone());
        assert_eq!(report.source, "local");
        assert_eq!(report.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(report.abuse_dir.as_deref(), Some(Path::new("abuse")));
        assert_eq!(report.threshold_checks, 3);
        assert_eq!(report.threshold_exceeded, 1);
        assert_eq!(abuse_threshold_status(&report), "threshold_exceeded");
        assert_eq!(
            abuse_threshold_report_exit(&report, true),
            AbuseThresholdReportExit::ThresholdExceeded
        );
        assert_eq!(
            abuse_threshold_report_exit(&report, false),
            AbuseThresholdReportExit::Success
        );
        let mut report_within_thresholds = report.clone();
        report_within_thresholds.threshold_exceeded = 0;
        assert_eq!(
            abuse_threshold_report_exit(&report_within_thresholds, true),
            AbuseThresholdReportExit::Success
        );

        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";
        let outputs = [
            render_abuse_threshold_report_text(&report),
            render_abuse_threshold_report_json(&report),
        ];

        for output in outputs {
            assert!(output.contains("threshold_exceeded"));
            assert!(output.contains("admin unauthorized") || output.contains("adminUnauthorized"));
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
    fn mailbox_retention_policy_file_parser_is_metadata_only() {
        let policy =
            mailbox_retention_policy_contents("ttl_seconds = 3600\nnode_id = \"node.hosted\"\n");
        let parsed = parse_mailbox_retention_policy_file(&policy).expect("retention policy parses");
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.ttl, Some(Duration::from_secs(3600)));

        let displayed_policy = policy.replace(
            "ciphertext_displayed = false",
            "ciphertext_displayed = true",
        );
        assert!(
            parse_mailbox_retention_policy_file(&displayed_policy)
                .expect_err("displayed guard true should fail")
                .contains("ciphertext_displayed must be false")
        );
        assert!(
            parse_mailbox_retention_policy_file("version = \"1\"\nttl_seconds = 3600\n")
                .expect_err("missing display guards should fail")
                .contains("payload_displayed = false")
        );
        assert!(
            parse_mailbox_retention_policy_file(&mailbox_retention_policy_contents(
                "unexpected_key = 1\n"
            ))
            .expect_err("unknown key should fail")
            .contains("unsupported key unexpected_key")
        );

        let secret_value = "relay-secret-token";
        let invalid_ttl = parse_mailbox_retention_policy_file(&mailbox_retention_policy_contents(
            &format!("ttl_seconds = \"{secret_value}\"\n"),
        ))
        .expect_err("invalid ttl should fail");
        assert!(invalid_ttl.contains("unsigned integer"));
        assert!(!invalid_ttl.contains(secret_value));

        let invalid_node = parse_mailbox_retention_policy_file(&mailbox_retention_policy_contents(
            &format!("node_id = \"bad {secret_value}\"\n"),
        ))
        .expect_err("invalid node id should fail");
        assert!(invalid_node.contains("node id"));
        assert!(!invalid_node.contains(secret_value));
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

        let policy =
            mailbox_retention_policy_contents("ttl_seconds = 7200\nnode_id = \"node.from-file\"\n");
        let policy_path = write_mailbox_retention_policy_file(&policy);
        let policy_arg = policy_path.to_string_lossy().to_string();
        let parsed_from_file = parse_mailbox_audit_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--retention-policy-file".to_string(),
            policy_arg,
            "--ttl-seconds".to_string(),
            "60".to_string(),
        ])
        .expect("mailbox audit policy args parse");
        assert_eq!(
            parsed_from_file.retention_policy_file.as_deref(),
            Some(policy_path.as_path())
        );
        assert_eq!(parsed_from_file.node_id.as_deref(), Some("node.from-file"));
        assert_eq!(parsed_from_file.ttl, Some(Duration::from_secs(60)));
        let _ = fs::remove_file(&policy_path);
        assert!(
            parse_mailbox_audit_args(vec![
                "--mailbox-dir".to_string(),
                "mailbox".to_string(),
                "--retention-policy-file".to_string(),
                "".to_string(),
            ])
            .is_err()
        );

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

        let policy =
            mailbox_retention_policy_contents("ttl_seconds = 7200\nnode_id = \"node.from-file\"\n");
        let policy_path = write_mailbox_retention_policy_file(&policy);
        let policy_arg = policy_path.to_string_lossy().to_string();
        let parsed_from_file = parse_mailbox_purge_args(vec![
            "--mailbox-dir".to_string(),
            "mailbox".to_string(),
            "--retention-policy-file".to_string(),
            policy_arg,
            "--dry-run".to_string(),
        ])
        .expect("mailbox purge policy args parse");
        assert_eq!(
            parsed_from_file.retention_policy_file.as_deref(),
            Some(policy_path.as_path())
        );
        assert_eq!(parsed_from_file.node_id.as_deref(), Some("node.from-file"));
        assert_eq!(parsed_from_file.ttl, Duration::from_secs(7200));
        let _ = fs::remove_file(&policy_path);
        assert!(
            parse_mailbox_purge_args(vec![
                "--mailbox-dir".to_string(),
                "mailbox".to_string(),
                "--retention-policy-file".to_string(),
                "".to_string(),
                "--dry-run".to_string(),
            ])
            .is_err()
        );

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
    fn admin_session_audit_parser_and_renderers_are_metadata_only() {
        let parsed = parse_admin_session_audit_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--json".to_string(),
        ])
        .expect("admin session audit args parse");
        assert_eq!(parsed.relay, "ws://127.0.0.1:8787");
        assert!(parsed.admin_token_stdin);
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert!(parsed.json);
        assert!(parse_admin_session_audit_args(Vec::new()).is_err());
        assert!(
            parse_admin_session_audit_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
            ])
            .expect_err("admin token stdin required")
            .contains("--admin-token-stdin")
        );

        let result = RelayAdminResult {
            node_id: Some("node.hosted".to_string()),
            session_state_records: 2,
            session_state_active_records: 1,
            session_state_expired_records: 1,
            session_state_invalid_records: 1,
            session_state_oldest_created_unix_millis: Some(1_763_596_800_000),
            session_state_newest_last_seen_unix_millis: Some(1_763_596_900_000),
            session_state_next_expires_unix_millis: Some(1_763_597_000_000),
            ..RelayAdminResult::new(conu_core::relay::RelayAdminAction::SessionAudit, "audited")
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_admin_session_audit_text(&result, "ws://127.0.0.1:8787"),
            render_admin_session_audit_json(&result, "ws://127.0.0.1:8787"),
        ];

        for output in outputs {
            assert!(output.contains("session"));
            assert!(output.contains("records"));
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
    fn admin_abuse_threshold_report_parser_and_renderers_are_metadata_only() {
        let parsed = parse_admin_abuse_threshold_report_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--account".to_string(),
            "account.prod".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--max-admin-failed".to_string(),
            "0".to_string(),
            "--max-rate-limited-sessions".to_string(),
            "4".to_string(),
            "--json".to_string(),
            "--fail-on-threshold".to_string(),
        ])
        .expect("admin abuse threshold report args parse");
        assert_eq!(parsed.relay, "ws://127.0.0.1:8787");
        assert!(parsed.admin_token_stdin);
        assert_eq!(parsed.account_id.as_deref(), Some("account.prod"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(parsed.thresholds.admin_failed, Some(0));
        assert_eq!(parsed.thresholds.rate_limited_sessions, Some(4));
        assert!(parsed.json);
        assert!(parsed.fail_on_threshold);

        let policy = abuse_threshold_policy_contents(
            "max_admin_failed = 2\nmax_rate_limited_sessions = 8\n",
        );
        let policy_path = write_abuse_threshold_policy_file(&policy);
        let policy_arg = policy_path.to_string_lossy().to_string();
        let parsed_from_file = parse_admin_abuse_threshold_report_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--thresholds-file".to_string(),
            policy_arg,
        ])
        .expect("admin abuse threshold policy args parse");
        assert_eq!(
            parsed_from_file.thresholds_file.as_deref(),
            Some(policy_path.as_path())
        );
        assert_eq!(parsed_from_file.thresholds.admin_failed, Some(2));
        assert_eq!(parsed_from_file.thresholds.rate_limited_sessions, Some(8));
        let _ = fs::remove_file(&policy_path);
        assert!(
            parse_admin_abuse_threshold_report_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--thresholds-file".to_string(),
                "".to_string(),
            ])
            .is_err()
        );

        assert!(parse_admin_abuse_threshold_report_args(Vec::new()).is_err());
        assert!(
            parse_admin_abuse_threshold_report_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--max-admin-failed".to_string(),
                "0".to_string(),
            ])
            .expect_err("admin token stdin required")
            .contains("--admin-token-stdin")
        );
        assert!(
            parse_admin_abuse_threshold_report_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
            ])
            .is_err()
        );
        let invalid_filter = parse_admin_abuse_threshold_report_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--account".to_string(),
            "bad secret value".to_string(),
            "--max-admin-failed".to_string(),
            "0".to_string(),
        ])
        .expect_err("invalid account filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));

        let result = RelayAdminResult {
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            abuse_records: 1,
            abuse_window_started_unix: Some(1_763_596_800),
            admin_failed: 1,
            rate_limited_sessions: 3,
            payload_displayed: false,
            token_displayed: false,
            token_hash_displayed: false,
            key_material_displayed: false,
            session_id_displayed: false,
            ciphertext_displayed: false,
            contents_displayed: false,
            ..RelayAdminResult::new(conu_core::relay::RelayAdminAction::Dashboard, "snapshotted")
        };
        let report = abuse_threshold_report_from_admin_result(
            &result,
            parsed.thresholds,
            parsed.relay.clone(),
        );
        assert_eq!(report.source, "admin");
        assert_eq!(report.relay.as_deref(), Some("ws://127.0.0.1:8787"));
        assert_eq!(report.account_id.as_deref(), Some("account.prod"));
        assert_eq!(report.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(report.threshold_checks, 2);
        assert_eq!(report.threshold_exceeded, 1);
        assert_eq!(abuse_threshold_status(&report), "threshold_exceeded");
        assert_eq!(
            abuse_threshold_report_exit(&report, true),
            AbuseThresholdReportExit::ThresholdExceeded
        );
        assert_eq!(
            abuse_threshold_report_exit(&report, false),
            AbuseThresholdReportExit::Success
        );

        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";
        let outputs = [
            render_abuse_threshold_report_text(&report),
            render_abuse_threshold_report_json(&report),
        ];

        for output in outputs {
            assert!(output.contains("threshold_exceeded"));
            assert!(output.contains("admin failed") || output.contains("adminFailed"));
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
    fn admin_tenant_lifecycle_parsers_and_renderers_are_metadata_only() {
        let parsed_account = parse_admin_tenant_account_args(
            vec![
                "account.prod".to_string(),
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--json".to_string(),
            ],
            AdminTenantAccountMode::Upsert,
        )
        .expect("admin tenant account args parse");
        assert_eq!(parsed_account.account_id, "account.prod");
        assert_eq!(parsed_account.relay, "ws://127.0.0.1:8787");
        assert!(parsed_account.admin_token_stdin);
        assert!(parsed_account.json);
        assert!(
            parse_admin_tenant_account_args(Vec::new(), AdminTenantAccountMode::Upsert).is_err()
        );
        assert!(
            parse_admin_tenant_account_args(
                vec![
                    "account.prod".to_string(),
                    "--relay".to_string(),
                    "ws://127.0.0.1:8787".to_string(),
                ],
                AdminTenantAccountMode::Revoke,
            )
            .expect_err("admin token stdin required")
            .contains("--admin-token-stdin")
        );

        let parsed_node = parse_admin_tenant_node_upsert_args(vec![
            "account.prod".to_string(),
            "node.hosted".to_string(),
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--messages".to_string(),
            "true".to_string(),
            "--streams".to_string(),
            "true".to_string(),
            "--mailbox".to_string(),
            "false".to_string(),
            "--signing-key-id".to_string(),
            "signing.key.1".to_string(),
            "--exchange-key-id".to_string(),
            "exchange.key.1".to_string(),
            "--json".to_string(),
        ])
        .expect("admin tenant node args parse");
        assert_eq!(parsed_node.account_id, "account.prod");
        assert_eq!(parsed_node.node_id, "node.hosted");
        assert_eq!(parsed_node.relay, "ws://127.0.0.1:8787");
        assert!(parsed_node.admin_token_stdin);
        assert!(parsed_node.permissions.messages);
        assert!(parsed_node.permissions.streams);
        assert!(!parsed_node.permissions.rooms);
        assert!(!parsed_node.permissions.files);
        assert!(!parsed_node.permissions.mailbox);
        assert_eq!(parsed_node.signing_key_id.as_deref(), Some("signing.key.1"));
        assert_eq!(
            parsed_node.exchange_key_id.as_deref(),
            Some("exchange.key.1")
        );
        assert!(parsed_node.json);
        assert!(
            parse_admin_tenant_node_upsert_args(vec![
                "account.prod".to_string(),
                "node.hosted".to_string(),
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--messages".to_string(),
                "yes".to_string(),
            ])
            .expect_err("invalid bool should fail")
            .contains("must be true or false")
        );

        let parsed_revoke = parse_admin_tenant_node_revoke_args(vec![
            "account.prod".to_string(),
            "node.hosted".to_string(),
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
        ])
        .expect("admin tenant node revoke args parse");
        assert_eq!(parsed_revoke.account_id, "account.prod");
        assert_eq!(parsed_revoke.node_id, "node.hosted");
        assert!(parsed_revoke.admin_token_stdin);

        let parsed_audit = parse_admin_tenant_audit_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--account".to_string(),
            "account.prod".to_string(),
            "--json".to_string(),
        ])
        .expect("admin tenant audit args parse");
        assert_eq!(parsed_audit.account_id.as_deref(), Some("account.prod"));
        assert_eq!(parsed_audit.relay, "ws://127.0.0.1:8787");
        assert!(parsed_audit.admin_token_stdin);
        assert!(parsed_audit.json);

        let parsed_suspend = parse_admin_account_suspend_args(vec![
            "account.prod".to_string(),
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--json".to_string(),
        ])
        .expect("admin account suspend args parse");
        assert_eq!(parsed_suspend.account_id, "account.prod");
        assert_eq!(parsed_suspend.relay, "ws://127.0.0.1:8787");
        assert!(parsed_suspend.admin_token_stdin);
        assert!(parsed_suspend.json);
        assert!(parse_admin_account_suspend_args(Vec::new()).is_err());
        assert!(
            parse_admin_account_suspend_args(vec![
                "account.prod".to_string(),
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
            ])
            .expect_err("admin token stdin required")
            .contains("--admin-token-stdin")
        );

        let result = RelayAdminResult {
            action: conu_core::relay::RelayAdminAction::TenantNodeUpsert,
            status: "upserted".to_string(),
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            tenants: 1,
            active_tenants: 1,
            nodes: 1,
            active_nodes: 1,
            tenant_policies: 1,
            ..RelayAdminResult::new(
                conu_core::relay::RelayAdminAction::TenantNodeUpsert,
                "upserted",
            )
        };
        let suspension_result = RelayAdminResult {
            action: conu_core::relay::RelayAdminAction::AccountSuspend,
            status: "suspended".to_string(),
            account_id: Some("account.prod".to_string()),
            credentials: 2,
            active: 0,
            revoked: 2,
            accounts: 1,
            tenants: 1,
            active_tenants: 0,
            revoked_tenants: 1,
            nodes: 1,
            active_nodes: 1,
            tenant_policies: 1,
            ..RelayAdminResult::new(
                conu_core::relay::RelayAdminAction::AccountSuspend,
                "suspended",
            )
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_admin_tenant_text(&result, "ws://127.0.0.1:8787"),
            render_admin_tenant_json(&result, "ws://127.0.0.1:8787"),
            render_admin_account_suspend_text(&suspension_result, "ws://127.0.0.1:8787"),
            render_admin_account_suspend_json(&suspension_result, "ws://127.0.0.1:8787"),
        ];

        for output in outputs {
            assert!(output.contains("tenant") || output.contains("suspension"));
            assert!(output.contains("upserted") || output.contains("suspended"));
            assert!(output.contains("token"));
            assert!(output.contains("contents"));
            assert!(!output.contains(secret_token));
            assert!(!output.contains(secret_hash));
            assert!(!output.contains(session_id));
            assert!(!output.contains("signing.key.1"));
            assert!(!output.contains("exchange.key.1"));
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

        let policy =
            mailbox_retention_policy_contents("ttl_seconds = 7200\nnode_id = \"node.from-file\"\n");
        let policy_path = write_mailbox_retention_policy_file(&policy);
        let policy_arg = policy_path.to_string_lossy().to_string();
        let parsed_from_file = parse_admin_mailbox_audit_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--retention-policy-file".to_string(),
            policy_arg,
            "--node".to_string(),
            "node.cli".to_string(),
        ])
        .expect("admin mailbox audit policy args parse");
        assert_eq!(
            parsed_from_file.retention_policy_file.as_deref(),
            Some(policy_path.as_path())
        );
        assert_eq!(parsed_from_file.node_id.as_deref(), Some("node.cli"));
        assert_eq!(parsed_from_file.ttl, Some(Duration::from_secs(7200)));
        let _ = fs::remove_file(&policy_path);
        assert!(
            parse_admin_mailbox_audit_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--retention-policy-file".to_string(),
                "".to_string(),
            ])
            .is_err()
        );

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

        let policy =
            mailbox_retention_policy_contents("ttl_seconds = 7200\nnode_id = \"node.from-file\"\n");
        let policy_path = write_mailbox_retention_policy_file(&policy);
        let policy_arg = policy_path.to_string_lossy().to_string();
        let parsed_from_file = parse_admin_mailbox_purge_args(vec![
            "--relay".to_string(),
            "ws://127.0.0.1:8787".to_string(),
            "--admin-token-stdin".to_string(),
            "--retention-policy-file".to_string(),
            policy_arg,
            "--dry-run".to_string(),
        ])
        .expect("admin mailbox purge policy args parse");
        assert_eq!(
            parsed_from_file.retention_policy_file.as_deref(),
            Some(policy_path.as_path())
        );
        assert_eq!(parsed_from_file.node_id.as_deref(), Some("node.from-file"));
        assert_eq!(parsed_from_file.ttl, Duration::from_secs(7200));
        let _ = fs::remove_file(&policy_path);
        assert!(
            parse_admin_mailbox_purge_args(vec![
                "--relay".to_string(),
                "ws://127.0.0.1:8787".to_string(),
                "--admin-token-stdin".to_string(),
                "--retention-policy-file".to_string(),
                "".to_string(),
                "--dry-run".to_string(),
            ])
            .is_err()
        );

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
    fn hosted_fleet_mailbox_purge_parser_and_renderers_are_metadata_only() {
        let retention_policy =
            write_mailbox_retention_policy_file(&mailbox_retention_policy_contents(
                "ttl_seconds = 7200\nnode_id = \"node.from-policy\"\n",
            ));
        let parsed = parse_hosted_fleet_mailbox_purge_args(vec![
            "--fleet-file".to_string(),
            "fleet.toml".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--retention-policy-file".to_string(),
            retention_policy.display().to_string(),
            "--json".to_string(),
            "--dry-run".to_string(),
        ])
        .expect("hosted fleet mailbox purge args parse");
        assert_eq!(parsed.fleet_file.as_path(), Path::new("fleet.toml"));
        assert_eq!(
            parsed.retention_policy_file.as_deref(),
            Some(retention_policy.as_path())
        );
        assert_eq!(
            parsed.mailbox_retention_policy.node_id.as_deref(),
            Some("node.hosted")
        );
        assert_eq!(
            parsed.mailbox_retention_policy.ttl,
            Some(Duration::from_secs(7200))
        );
        assert!(parsed.dry_run);
        assert!(parsed.json);
        assert!(parse_hosted_fleet_mailbox_purge_args(Vec::new()).is_err());
        assert!(
            parse_hosted_fleet_mailbox_purge_args(vec![
                "--fleet-file".to_string(),
                "fleet.toml".to_string(),
                "--ttl-seconds".to_string(),
                "3600".to_string(),
            ])
            .expect_err("mode is required")
            .contains("exactly one")
        );
        let invalid_filter = parse_hosted_fleet_mailbox_purge_args(vec![
            "--fleet-file".to_string(),
            "fleet.toml".to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
            "--dry-run".to_string(),
        ])
        .expect_err("invalid node filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));

        let no_mailbox_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                r#"
[[relay]]
name = "relay-east"
abuse_dir = "abuse"
"#,
            ));
        let no_mailbox_args = HostedFleetMailboxPurgeArgs {
            fleet_file: no_mailbox_fleet,
            retention_policy_file: None,
            mailbox_retention_policy: MailboxRetentionPolicy {
                node_id: None,
                ttl: Some(Duration::from_secs(3600)),
            },
            mailbox_ttl: None,
            dry_run: true,
            json: false,
        };
        let no_mailbox_error = hosted_fleet_mailbox_purge_report(&no_mailbox_args)
            .expect_err("purge should require a fleet mailbox source");
        assert!(no_mailbox_error.contains("mailbox_dir"));

        let no_ttl_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                r#"
[[relay]]
name = "relay-east"
mailbox_dir = "mailbox"
"#,
            ));
        let no_ttl_args = HostedFleetMailboxPurgeArgs {
            fleet_file: no_ttl_fleet,
            retention_policy_file: None,
            mailbox_retention_policy: MailboxRetentionPolicy::default(),
            mailbox_ttl: None,
            dry_run: true,
            json: false,
        };
        let no_ttl_error = hosted_fleet_mailbox_purge_report(&no_ttl_args)
            .expect_err("purge should require a retention ttl");
        assert!(no_ttl_error.contains("ttl_seconds"));

        let mixed_ttl_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                r#"
[[relay]]
name = "relay-east"
mailbox_dir = "missing-east"
mailbox_ttl_seconds = 3600

[[relay]]
name = "relay-west"
mailbox_dir = "missing-west"
"#,
            ));
        let mixed_ttl_error = hosted_fleet_mailbox_purge_report(&HostedFleetMailboxPurgeArgs {
            fleet_file: mixed_ttl_fleet,
            retention_policy_file: None,
            mailbox_retention_policy: MailboxRetentionPolicy::default(),
            mailbox_ttl: None,
            dry_run: false,
            json: false,
        })
        .expect_err("purge should validate all TTLs before scanning mailbox dirs");
        assert!(mixed_ttl_error.contains("relay-west"));
        assert!(mixed_ttl_error.contains("ttl_seconds"));

        let fleet_file = write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
            r#"
[[relay]]
name = "relay-east"
mailbox_dir = "mailbox"
mailbox_ttl_seconds = 3600
"#,
        ));
        let base_dir = fleet_file.parent().expect("fleet file parent");
        fs::create_dir_all(base_dir.join("mailbox")).expect("create mailbox dir");
        let report = hosted_fleet_mailbox_purge_report(&HostedFleetMailboxPurgeArgs {
            fleet_file: fleet_file.clone(),
            retention_policy_file: None,
            mailbox_retention_policy: MailboxRetentionPolicy::default(),
            mailbox_ttl: None,
            dry_run: true,
            json: false,
        })
        .expect("fleet mailbox purge report builds");
        assert_eq!(report.totals.relays, 1);
        assert_eq!(report.totals.mailbox_sources, 1);
        assert!(report.dry_run);

        let relay = HostedFleetMailboxPurgeRelayReport {
            name: "relay-east".to_string(),
            mailbox_dir: PathBuf::from("mailbox"),
            report: RelayMailboxPurgeReport {
                node_id: Some("node.hosted".to_string()),
                retention_ttl_seconds: 3600,
                dry_run: false,
                confirmed: true,
                nodes: 1,
                records: 2,
                invalid_records: 1,
                bytes: 512,
                expired_records: 1,
                expired_bytes: 256,
                purged_records: 1,
                purged_bytes: 256,
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            },
        };
        let mut totals = HostedFleetMailboxPurgeTotals {
            relays: 1,
            ..HostedFleetMailboxPurgeTotals::default()
        };
        totals.add(&relay);
        let render_report = HostedFleetMailboxPurgeReport {
            fleet_file: PathBuf::from("fleet.toml"),
            node_id: Some("node.hosted".to_string()),
            retention_policy_file: Some(PathBuf::from("mailbox-retention.toml")),
            mailbox_ttl: Some(Duration::from_secs(7200)),
            dry_run: false,
            relays: vec![relay],
            totals,
        };
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_hosted_fleet_mailbox_purge_text(&render_report),
            render_hosted_fleet_mailbox_purge_json(&render_report),
        ];

        for output in outputs {
            assert!(output.contains("fleet"));
            assert!(output.contains("mailbox"));
            assert!(output.contains("purge") || output.contains("purged"));
            assert!(output.contains("relay-east"));
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
    fn hosted_fleet_abuse_response_plan_parser_and_renderers_are_metadata_only() {
        let threshold_policy = write_abuse_threshold_policy_file(&abuse_threshold_policy_contents(
            "max_admin_failed = 0\nmax_rate_limited_sessions = 0\n",
        ));
        let parsed = parse_hosted_fleet_abuse_response_plan_args(vec![
            "--fleet-file".to_string(),
            "fleet.toml".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--thresholds-file".to_string(),
            threshold_policy.display().to_string(),
            "--max-mailbox-rejected-forwards".to_string(),
            "0".to_string(),
            "--json".to_string(),
            "--fail-on-action".to_string(),
        ])
        .expect("hosted fleet abuse response plan args parse");
        assert_eq!(parsed.fleet_file.as_path(), Path::new("fleet.toml"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(
            parsed.thresholds_file.as_deref(),
            Some(threshold_policy.as_path())
        );
        assert_eq!(parsed.abuse_thresholds.admin_failed, Some(0));
        assert_eq!(parsed.abuse_thresholds.rate_limited_sessions, Some(0));
        assert_eq!(parsed.abuse_thresholds.mailbox_rejected_forwards, Some(0));
        assert!(parsed.json);
        assert!(parsed.fail_on_action);
        assert!(parse_hosted_fleet_abuse_response_plan_args(Vec::new()).is_err());
        assert!(
            parse_hosted_fleet_abuse_response_plan_args(vec![
                "--fleet-file".to_string(),
                "fleet.toml".to_string(),
            ])
            .is_err()
        );
        let invalid_filter = parse_hosted_fleet_abuse_response_plan_args(vec![
            "--fleet-file".to_string(),
            "fleet.toml".to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
            "--max-admin-failed".to_string(),
            "0".to_string(),
        ])
        .expect_err("invalid node filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));

        let no_abuse_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                r#"
[[relay]]
name = "relay-east"
credentials_file = "credentials.toml"
"#,
            ));
        let no_abuse_error = hosted_fleet_abuse_response_plan(&HostedFleetAbuseResponsePlanArgs {
            fleet_file: no_abuse_fleet,
            node_id: None,
            thresholds_file: None,
            abuse_thresholds: AbuseThresholds {
                admin_failed: Some(0),
                ..AbuseThresholds::default()
            },
            json: false,
            fail_on_action: false,
        })
        .expect_err("abuse response plan should require a fleet abuse source");
        assert!(no_abuse_error.contains("abuse_dir"));

        let empty_abuse_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                r#"
[[relay]]
name = "relay-east"
abuse_dir = "abuse"
"#,
            ));
        let empty_plan = hosted_fleet_abuse_response_plan(&HostedFleetAbuseResponsePlanArgs {
            fleet_file: empty_abuse_fleet,
            node_id: Some("node.hosted".to_string()),
            thresholds_file: None,
            abuse_thresholds: AbuseThresholds {
                admin_failed: Some(0),
                ..AbuseThresholds::default()
            },
            json: false,
            fail_on_action: false,
        })
        .expect("empty abuse source still builds a plan");
        assert_eq!(empty_plan.actions.len(), 0);
        assert_eq!(
            hosted_fleet_abuse_response_plan_exit(&empty_plan, true),
            HostedFleetAbuseResponsePlanExit::Success
        );

        let audit = RelayAbuseAudit {
            node_id: Some("node.hosted".to_string()),
            records: 1,
            window_started_unix: Some(1_763_596_800),
            admin_unauthorized: 0,
            admin_failed: 1,
            unauthorized_sessions: 0,
            credential_denied_sessions: 1,
            tenant_denied_sessions: 1,
            rate_limited_sessions: 2,
            session_expired: 1,
            quota_denied_forwards: 0,
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
        let relay = HostedFleetAbuseRelayPlan {
            name: "relay-east".to_string(),
            abuse_dir: PathBuf::from("abuse"),
            audit: audit.clone(),
        };
        let mut totals = HostedFleetAbuseResponsePlanTotals {
            relays: 1,
            ..HostedFleetAbuseResponsePlanTotals::default()
        };
        totals.add(&audit);
        let threshold_report = abuse_threshold_report_from_fleet_abuse_totals(
            &totals,
            AbuseThresholds {
                admin_failed: Some(0),
                credential_denied_sessions: Some(0),
                rate_limited_sessions: Some(0),
                session_expired: Some(0),
                mailbox_rejected_forwards: Some(0),
                malformed_client_frames: Some(0),
                ..AbuseThresholds::default()
            },
            Some("node.hosted".to_string()),
        );
        let actions = abuse_response_actions(&threshold_report);
        assert_eq!(threshold_report.threshold_exceeded, 6);
        assert_eq!(actions.len(), 5);
        assert!(
            actions
                .iter()
                .any(|action| action.category == "admin_access")
        );
        assert!(
            actions
                .iter()
                .any(|action| action.category == "credential_tenant_access")
        );
        assert!(
            actions
                .iter()
                .any(|action| action.category == "traffic_pressure")
        );
        assert!(
            actions
                .iter()
                .any(|action| action.category == "delivery_health")
        );
        assert!(
            actions
                .iter()
                .any(|action| action.category == "mailbox_pressure")
        );

        let plan = HostedFleetAbuseResponsePlan {
            fleet_file: PathBuf::from("fleet.toml"),
            node_id: Some("node.hosted".to_string()),
            thresholds_file: Some(PathBuf::from("abuse-thresholds.toml")),
            relays: vec![relay],
            totals,
            threshold_report,
            actions,
        };
        assert_eq!(
            hosted_fleet_abuse_response_plan_exit(&plan, true),
            HostedFleetAbuseResponsePlanExit::ActionRecommended
        );
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_hosted_fleet_abuse_response_plan_text(&plan),
            render_hosted_fleet_abuse_response_plan_json(&plan),
        ];

        for output in outputs {
            assert!(output.contains("abuse"));
            assert!(output.contains("response") || output.contains("action_recommended"));
            assert!(output.contains("relay-east"));
            assert!(output.contains("admin_access"));
            assert!(output.contains("traffic_pressure"));
            assert!(output.contains("mailbox_pressure"));
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
    fn hosted_fleet_dashboard_parser_and_renderers_are_metadata_only() {
        let retention_policy =
            write_mailbox_retention_policy_file(&mailbox_retention_policy_contents(
                "ttl_seconds = 7200\nnode_id = \"node.from-policy\"\n",
            ));
        let threshold_policy = write_abuse_threshold_policy_file(&abuse_threshold_policy_contents(
            "max_admin_failed = 0\nmax_rate_limited_sessions = 0\n",
        ));
        let parsed = parse_hosted_fleet_dashboard_args(vec![
            "--fleet-file".to_string(),
            "fleet.toml".to_string(),
            "--account".to_string(),
            "account.prod".to_string(),
            "--node".to_string(),
            "node.hosted".to_string(),
            "--retention-policy-file".to_string(),
            retention_policy.display().to_string(),
            "--thresholds-file".to_string(),
            threshold_policy.display().to_string(),
            "--max-mailbox-rejected-forwards".to_string(),
            "0".to_string(),
            "--json".to_string(),
            "--fail-on-threshold".to_string(),
            "--fail-on-retention".to_string(),
        ])
        .expect("hosted fleet dashboard args parse");
        assert_eq!(parsed.fleet_file.as_path(), Path::new("fleet.toml"));
        assert_eq!(parsed.account_id.as_deref(), Some("account.prod"));
        assert_eq!(parsed.node_id.as_deref(), Some("node.hosted"));
        assert_eq!(
            parsed.retention_policy_file.as_deref(),
            Some(retention_policy.as_path())
        );
        assert_eq!(
            parsed.mailbox_retention_policy.node_id.as_deref(),
            Some("node.from-policy")
        );
        assert_eq!(
            parsed.mailbox_retention_policy.ttl,
            Some(Duration::from_secs(7200))
        );
        assert_eq!(
            parsed.thresholds_file.as_deref(),
            Some(threshold_policy.as_path())
        );
        assert_eq!(parsed.abuse_thresholds.admin_failed, Some(0));
        assert_eq!(parsed.abuse_thresholds.rate_limited_sessions, Some(0));
        assert_eq!(parsed.abuse_thresholds.mailbox_rejected_forwards, Some(0));
        assert!(parsed.json);
        assert!(parsed.fail_on_threshold);
        assert!(parsed.fail_on_retention);
        assert!(parse_hosted_fleet_dashboard_args(Vec::new()).is_err());
        let invalid_filter = parse_hosted_fleet_dashboard_args(vec![
            "--fleet-file".to_string(),
            "fleet.toml".to_string(),
            "--node".to_string(),
            "bad secret value".to_string(),
        ])
        .expect_err("invalid node filter should fail closed");
        assert!(!invalid_filter.contains("bad secret value"));

        let fleet_file = write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
            r#"
[[relay]]
name = "relay-east"
credentials_file = "credentials.toml"
tenants_file = "tenants.toml"
session_state_dir = "sessions"
mailbox_dir = "mailbox"
mailbox_ttl_seconds = 3600
accounting_dir = "accounting"
abuse_dir = "abuse"
"#,
        ));
        let configs =
            parse_hosted_fleet_dashboard_file(&fleet_file).expect("hosted fleet file parses");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "relay-east");
        let base_dir = fleet_file.parent().expect("fleet file parent");
        let expected_credentials = base_dir.join("credentials.toml");
        assert_eq!(
            configs[0].credentials_file.as_deref(),
            Some(expected_credentials.as_path())
        );
        assert_eq!(configs[0].mailbox_ttl_seconds, Some(3600));
        let no_abuse_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                r#"
[[relay]]
name = "relay-east"
credentials_file = "credentials.toml"
"#,
            ));
        let no_abuse_args = HostedFleetDashboardArgs {
            fleet_file: no_abuse_fleet,
            account_id: None,
            node_id: None,
            retention_policy_file: None,
            mailbox_retention_policy: MailboxRetentionPolicy::default(),
            mailbox_ttl: None,
            thresholds_file: Some(threshold_policy.clone()),
            abuse_thresholds: AbuseThresholds {
                admin_failed: Some(0),
                ..AbuseThresholds::default()
            },
            json: false,
            fail_on_threshold: false,
            fail_on_retention: false,
        };
        let no_abuse_error = hosted_fleet_dashboard_snapshot(&no_abuse_args)
            .expect_err("thresholds should require a fleet abuse source");
        assert!(no_abuse_error.contains("abuse_dir"));

        let no_mailbox_fleet =
            write_hosted_fleet_dashboard_file(&hosted_fleet_dashboard_file_contents(
                r#"
[[relay]]
name = "relay-east"
abuse_dir = "abuse"
"#,
            ));
        let no_mailbox_args = HostedFleetDashboardArgs {
            fleet_file: no_mailbox_fleet,
            account_id: None,
            node_id: None,
            retention_policy_file: Some(retention_policy.clone()),
            mailbox_retention_policy: MailboxRetentionPolicy {
                node_id: None,
                ttl: Some(Duration::from_secs(3600)),
            },
            mailbox_ttl: None,
            thresholds_file: None,
            abuse_thresholds: AbuseThresholds::default(),
            json: false,
            fail_on_threshold: false,
            fail_on_retention: true,
        };
        let no_mailbox_error = hosted_fleet_dashboard_snapshot(&no_mailbox_args)
            .expect_err("retention policy should require a fleet mailbox source");
        assert!(no_mailbox_error.contains("mailbox_dir"));

        let missing_guard = write_hosted_fleet_dashboard_file(
            "version = \"1\"\npayload_displayed = false\n[[relay]]\nname = \"relay-east\"\nabuse_dir = \"abuse\"\n",
        );
        let error = parse_hosted_fleet_dashboard_file(&missing_guard)
            .expect_err("missing guards should fail closed");
        assert!(error.contains("requires"));
        assert!(!error.contains("relay-secret-token"));

        let relay = HostedFleetRelaySnapshot {
            config: HostedFleetRelayConfig {
                name: "relay-east".to_string(),
                credentials_file: Some(PathBuf::from("credentials.toml")),
                tenants_file: Some(PathBuf::from("tenants.toml")),
                session_state_dir: Some(PathBuf::from("sessions")),
                mailbox_dir: Some(PathBuf::from("mailbox")),
                mailbox_ttl_seconds: Some(3600),
                accounting_dir: Some(PathBuf::from("accounting")),
                abuse_dir: Some(PathBuf::from("abuse")),
            },
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
            session_state: Some(RelaySessionAudit {
                node_id: Some("node.hosted".to_string()),
                records: 2,
                active_records: 1,
                expired_records: 1,
                invalid_records: 0,
                oldest_created_unix_millis: Some(1_763_596_800_000),
                newest_last_seen_unix_millis: Some(1_763_596_900_000),
                next_expires_unix_millis: Some(1_763_597_000_000),
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
                contents_displayed: false,
            }),
            mailbox: Some(RelayMailboxAudit {
                node_id: Some("node.hosted".to_string()),
                retention_ttl_seconds: Some(3600),
                nodes: 1,
                records: 2,
                invalid_records: 1,
                bytes: 512,
                oldest_queued_unix_millis: Some(1_763_596_700_000),
                newest_queued_unix_millis: Some(1_763_596_800_000),
                expired_records: Some(1),
                expired_bytes: Some(256),
                payload_displayed: false,
                token_displayed: false,
                token_hash_displayed: false,
                key_material_displayed: false,
                session_id_displayed: false,
                ciphertext_displayed: false,
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
        let mut totals = HostedFleetDashboardTotals::default();
        totals.add(&relay);
        assert_eq!(totals.mailbox_retention_checks, 1);
        assert_eq!(totals.mailbox_retention_exceeded, 1);
        let threshold_report = abuse_threshold_report_from_fleet_totals(
            &totals,
            AbuseThresholds {
                admin_failed: Some(0),
                rate_limited_sessions: Some(0),
                mailbox_rejected_forwards: Some(0),
                ..AbuseThresholds::default()
            },
            Some("account.prod".to_string()),
            Some("node.hosted".to_string()),
        );
        assert_eq!(threshold_report.threshold_checks, 3);
        assert_eq!(threshold_report.threshold_exceeded, 3);
        let snapshot = HostedFleetDashboardSnapshot {
            fleet_file: PathBuf::from("fleet.toml"),
            account_id: Some("account.prod".to_string()),
            node_id: Some("node.hosted".to_string()),
            mailbox_node_id: Some("node.hosted".to_string()),
            retention_policy_file: Some(PathBuf::from("mailbox-retention.toml")),
            mailbox_ttl: Some(Duration::from_secs(7200)),
            thresholds_file: Some(PathBuf::from("thresholds.toml")),
            relays: vec![relay],
            totals,
            abuse_threshold_report: Some(threshold_report),
        };
        assert_eq!(
            hosted_fleet_dashboard_exit(&snapshot, true, false),
            HostedFleetDashboardExit::PolicyExceeded
        );
        assert_eq!(
            hosted_fleet_dashboard_exit(&snapshot, false, true),
            HostedFleetDashboardExit::PolicyExceeded
        );
        assert_eq!(
            hosted_fleet_dashboard_exit(&snapshot, false, false),
            HostedFleetDashboardExit::Success
        );
        let secret_token = "relay-secret-token";
        let secret_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let session_id = "relay_node.hosted_123456789";

        let outputs = [
            render_hosted_fleet_dashboard_text(&snapshot),
            render_hosted_fleet_dashboard_json(&snapshot),
        ];

        for output in outputs {
            assert!(output.contains("fleet") || output.contains("snapshotted"));
            assert!(output.contains("relay-east"));
            assert!(output.contains("credentials"));
            assert!(output.contains("session"));
            assert!(output.contains("threshold"));
            assert!(output.contains("retention"));
            assert!(output.contains("threshold_exceeded"));
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
