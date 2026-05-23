"use strict";

const path = require("node:path");
const { spawnSync } = require("node:child_process");

const MAX_ARCHIVE_LIST_BYTES = 2 * 1024 * 1024;
const UNSUPPORTED_MEMBER_TYPES = new Set(["symlink", "hardlink", "other"]);

function validateArchiveMembers(archivePath) {
  const members = listArchiveMembers(archivePath);
  assertSafeArchiveMemberList(members, archivePath);
}

function assertSafeArchiveMemberList(members, archiveLabel = "archive") {
  if (!Array.isArray(members) || members.length === 0) {
    throw new Error(`${archiveLabel} did not contain any extractable members`);
  }

  for (const member of members) {
    const name = typeof member === "string" ? member : member.name;
    const type = typeof member === "string" ? "unknown" : member.type || "unknown";
    if (UNSUPPORTED_MEMBER_TYPES.has(type)) {
      throw new Error(`${archiveLabel} contains unsupported ${type} member: ${name}`);
    }
    validateArchiveMemberName(name, archiveLabel);
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
  if (parts.includes("..")) {
    throw new Error(`${archiveLabel} contains a parent-traversal archive path: ${name}`);
  }
}

function listArchiveMembers(archivePath) {
  const tarMembers = listArchiveMembersWithTar(archivePath);
  if (tarMembers) {
    return tarMembers;
  }

  if (process.platform === "win32" && archivePath.endsWith(".zip")) {
    return listZipMembersWithPowerShell(archivePath);
  }

  throw new Error(`could not inspect archive members before extraction: ${archivePath}`);
}

function listArchiveMembersWithTar(archivePath) {
  const names = runTool("tar", ["-tf", archivePath]);
  if (names.status !== 0) {
    return null;
  }

  const verbose = runTool("tar", ["-tvf", archivePath]);
  if (verbose.status !== 0) {
    throw new Error(`could not inspect archive member types before extraction: ${archivePath}`);
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

function listZipMembersWithPowerShell(archivePath) {
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
    throw new Error(`could not inspect zip archive members before extraction: ${archivePath}`);
  }

  const output = result.stdout.trim();
  if (!output) {
    return [];
  }
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed : [parsed];
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
  assertSafeArchiveMemberList,
  validateArchiveMembers
};
