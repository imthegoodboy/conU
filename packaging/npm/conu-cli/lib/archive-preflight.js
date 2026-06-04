"use strict";

const path = require("node:path");
const { spawnSync } = require("node:child_process");

const MAX_ARCHIVE_LIST_BYTES = 2 * 1024 * 1024;
const MAX_ARCHIVE_MEMBERS = 10000;
const SUPPORTED_MEMBER_TYPES = new Set(["file", "directory"]);
const FORBIDDEN_PARTS = new Set([
  ".conu",
  ".git",
  "logs",
  "messages",
  "node_modules",
  "routes",
  "runtime",
  "security",
  "sessions",
  "streams",
  "target",
  "vendor"
]);
const FORBIDDEN_NAMES = new Set(["node.toml", "runtime.toml", "trust.toml"]);

function validateArchiveMembers(archivePath) {
  const archiveLabel = displayArchiveLabel(archivePath);
  const members = listArchiveMembers(archivePath, archiveLabel);
  assertSafeArchiveMemberList(members, archiveLabel);
}

function assertSafeArchiveMemberList(members, archiveLabel = "archive") {
  if (!Array.isArray(members) || members.length === 0) {
    throw new Error(`${archiveLabel} did not contain any extractable members`);
  }
  if (members.length > MAX_ARCHIVE_MEMBERS) {
    throw new Error(`${archiveLabel} contains more than ${MAX_ARCHIVE_MEMBERS} entries`);
  }

  const paths = new Set();
  for (const member of members) {
    const name = typeof member === "string" ? member : member.name;
    const type = typeof member === "string" ? "file" : member.type || "unknown";
    if (!SUPPORTED_MEMBER_TYPES.has(type)) {
      throw new Error(`${archiveLabel} contains unsupported ${type} member: ${name}`);
    }
    const normalized = validateArchiveMemberName(name, archiveLabel);
    if (paths.has(normalized)) {
      throw new Error(`${archiveLabel} contains duplicate archive path: ${normalized}`);
    }
    paths.add(normalized);
    rejectForbiddenArchivePath(normalized, archiveLabel);
  }
}

function validateArchiveMemberName(name, archiveLabel) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error(`${archiveLabel} contains an empty archive member path`);
  }
  if (name.includes("\0") || name.includes("\r") || name.includes("\n")) {
    throw new Error(`${archiveLabel} contains an unsafe archive path: ${name}`);
  }

  const normalized = name.replace(/\\/g, "/");
  const hasWindowsDrive = /^[A-Za-z]:/.test(normalized);
  if (path.posix.isAbsolute(normalized) || hasWindowsDrive || normalized.startsWith("//")) {
    throw new Error(`${archiveLabel} contains an absolute archive path: ${name}`);
  }

  const parts = normalized.split("/").filter((part) => part !== "" && part !== ".");
  if (parts.length === 0) {
    throw new Error(`${archiveLabel} contains an empty archive member path`);
  }
  if (parts.includes("..")) {
    throw new Error(`${archiveLabel} contains a parent-traversal archive path: ${name}`);
  }
  return parts.join("/");
}

function rejectForbiddenArchivePath(normalized, archiveLabel) {
  const parts = normalized.split("/");
  const lowerParts = new Set(parts.map((part) => part.toLowerCase()));
  for (const forbidden of FORBIDDEN_PARTS) {
    if (lowerParts.has(forbidden)) {
      throw new Error(`${archiveLabel} contains forbidden state path: ${normalized}`);
    }
  }

  const fileName = parts[parts.length - 1].toLowerCase();
  if (FORBIDDEN_NAMES.has(fileName)) {
    throw new Error(`${archiveLabel} contains forbidden state path: ${normalized}`);
  }
}

function listArchiveMembers(archivePath, archiveLabel) {
  const tarMembers = listArchiveMembersWithTar(archivePath, archiveLabel);
  if (tarMembers) {
    return tarMembers;
  }

  if (process.platform === "win32" && archivePath.endsWith(".zip")) {
    return listZipMembersWithPowerShell(archivePath, archiveLabel);
  }

  throw new Error(
    `could not inspect archive members before extraction: ${archiveLabel}; pathDisplayed=false`
  );
}

function listArchiveMembersWithTar(archivePath, archiveLabel) {
  const names = runTool("tar", ["-tf", archivePath]);
  if (names.status !== 0) {
    return null;
  }

  const verbose = runTool("tar", ["-tvf", archivePath]);
  if (verbose.status !== 0) {
    throw new Error(
      `could not inspect archive member types before extraction: ${archiveLabel}; pathDisplayed=false`
    );
  }

  const nameLines = splitToolLines(names.stdout);
  const typeLines = splitToolLines(verbose.stdout);
  return nameLines.map((name, index) => ({
    name,
    type: parseTarMemberType(typeLines[index] || "")
  }));
}

function parseTarMemberType(line) {
  const marker = line.trimStart()[0];
  if (marker === "l") {
    return "symlink";
  }
  if (marker === "h") {
    return "hardlink";
  }
  if (marker === "d") {
    return "directory";
  }
  if (marker === "-" || marker === "r") {
    return "file";
  }
  return marker ? "other" : "unknown";
}

function listZipMembersWithPowerShell(archivePath, archiveLabel) {
  const script = [
    "Add-Type -AssemblyName System.IO.Compression.FileSystem",
    "$zip = [System.IO.Compression.ZipFile]::OpenRead($args[0])",
    "try {",
    "  $zip.Entries | ForEach-Object {",
    "    $mode = ($_.ExternalAttributes -shr 16) -band 61440",
    "    $type = if ($_.FullName.EndsWith('/') -or $_.FullName.EndsWith('\\')) { 'directory' } elseif ($mode -eq 40960) { 'symlink' } elseif ($mode -eq 32768 -or $mode -eq 0) { 'file' } else { 'other' }",
    "    [pscustomobject]@{ name = $_.FullName; type = $type }",
    "  } | ConvertTo-Json -Compress",
    "} finally {",
    "  $zip.Dispose()",
    "}"
  ].join("; ");

  const result = runTool("powershell", [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script,
    archivePath
  ]);
  if (result.status !== 0) {
    throw new Error(
      `could not inspect zip archive members before extraction: ${archiveLabel}; pathDisplayed=false`
    );
  }

  const output = result.stdout.trim();
  if (!output) {
    return [];
  }
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed : [parsed];
}

function displayArchiveLabel(archivePath) {
  const baseName = path.basename(String(archivePath || ""));
  return baseName || "archive";
}

function runTool(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    maxBuffer: MAX_ARCHIVE_LIST_BYTES
  });
  return {
    status: result.status === null ? 1 : result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    error: result.error
  };
}

function splitToolLines(output) {
  return output.split(/\r?\n/).filter((line) => line.length > 0);
}

module.exports = {
  MAX_ARCHIVE_MEMBERS,
  assertSafeArchiveMemberList,
  validateArchiveMembers
};
