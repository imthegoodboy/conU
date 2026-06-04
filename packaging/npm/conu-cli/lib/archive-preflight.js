"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { buildChildEnv } = require("./child-env");

const MAX_ARCHIVE_LIST_BYTES = 2 * 1024 * 1024;
const MAX_ARCHIVE_MEMBERS = 10000;
const MAX_ZIP_EOCD_SEARCH_BYTES = 22 + 65535;
const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const ZIP64_ENTRY_COUNT = 0xffff;
const ZIP64_FIELD = 0xffffffff;
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
  if (archivePath.endsWith(".zip")) {
    return listZipMembersWithNode(archivePath, archiveLabel);
  }

  const tarMembers = listArchiveMembersWithTar(archivePath, archiveLabel);
  if (tarMembers) {
    return tarMembers;
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

function listZipMembersWithNode(archivePath, archiveLabel) {
  let fd = null;
  try {
    fd = fs.openSync(archivePath, "r");
    const size = fs.fstatSync(fd).size;
    const { centralDirectory, entryCount } = readZipCentralDirectory(fd, size, archiveLabel);
    return parseZipCentralDirectory(centralDirectory, entryCount, archiveLabel);
  } catch (error) {
    if (error && error.zipInspectionError) {
      throw error;
    }
    throw zipInspectionError(archiveLabel);
  } finally {
    if (fd !== null) {
      fs.closeSync(fd);
    }
  }
}

function readZipCentralDirectory(fd, size, archiveLabel) {
  if (!Number.isSafeInteger(size) || size < 22) {
    throw zipInspectionError(archiveLabel);
  }

  const searchLength = Math.min(size, MAX_ZIP_EOCD_SEARCH_BYTES);
  const searchStart = size - searchLength;
  const eocd = Buffer.alloc(searchLength);
  if (fs.readSync(fd, eocd, 0, searchLength, searchStart) !== searchLength) {
    throw zipInspectionError(archiveLabel);
  }

  for (let offset = searchLength - 22; offset >= 0; offset -= 1) {
    if (eocd.readUInt32LE(offset) !== ZIP_EOCD_SIGNATURE) {
      continue;
    }

    const commentLength = eocd.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength !== searchLength) {
      continue;
    }

    const diskNumber = eocd.readUInt16LE(offset + 4);
    const centralDisk = eocd.readUInt16LE(offset + 6);
    const diskEntries = eocd.readUInt16LE(offset + 8);
    const entryCount = eocd.readUInt16LE(offset + 10);
    const centralSize = eocd.readUInt32LE(offset + 12);
    const centralOffset = eocd.readUInt32LE(offset + 16);

    if (diskNumber !== 0 || centralDisk !== 0 || diskEntries !== entryCount) {
      throw zipInspectionError(archiveLabel);
    }
    if (
      entryCount === ZIP64_ENTRY_COUNT ||
      centralSize === ZIP64_FIELD ||
      centralOffset === ZIP64_FIELD
    ) {
      throw zipInspectionError(archiveLabel);
    }
    if (entryCount > MAX_ARCHIVE_MEMBERS) {
      throw new Error(`${archiveLabel} contains more than ${MAX_ARCHIVE_MEMBERS} entries`);
    }
    if (centralSize > MAX_ARCHIVE_LIST_BYTES) {
      throw zipInspectionError(archiveLabel);
    }
    if (centralOffset + centralSize > size) {
      throw zipInspectionError(archiveLabel);
    }

    const centralDirectory = Buffer.alloc(centralSize);
    if (fs.readSync(fd, centralDirectory, 0, centralSize, centralOffset) !== centralSize) {
      throw zipInspectionError(archiveLabel);
    }
    return { centralDirectory, entryCount };
  }

  throw zipInspectionError(archiveLabel);
}

function parseZipCentralDirectory(centralDirectory, entryCount, archiveLabel) {
  const members = [];
  let offset = 0;
  while (offset < centralDirectory.length) {
    if (
      offset + 46 > centralDirectory.length ||
      centralDirectory.readUInt32LE(offset) !== ZIP_CENTRAL_DIRECTORY_SIGNATURE
    ) {
      throw zipInspectionError(archiveLabel);
    }

    const flags = centralDirectory.readUInt16LE(offset + 8);
    const nameLength = centralDirectory.readUInt16LE(offset + 28);
    const extraLength = centralDirectory.readUInt16LE(offset + 30);
    const commentLength = centralDirectory.readUInt16LE(offset + 32);
    const externalAttributes = centralDirectory.readUInt32LE(offset + 38);
    const entryLength = 46 + nameLength + extraLength + commentLength;
    if (offset + entryLength > centralDirectory.length) {
      throw zipInspectionError(archiveLabel);
    }

    const name = centralDirectory.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    members.push({
      name,
      type: zipMemberType(name, flags, externalAttributes)
    });
    offset += entryLength;
  }
  if (members.length !== entryCount) {
    throw zipInspectionError(archiveLabel);
  }
  return members;
}

function zipMemberType(name, flags, externalAttributes) {
  if (name.endsWith("/") || name.endsWith("\\")) {
    return "directory";
  }
  if ((flags & 1) !== 0) {
    return "encrypted";
  }
  const mode = (externalAttributes >>> 16) & 0xf000;
  if (mode === 0xa000) {
    return "symlink";
  }
  if (mode === 0x8000 || mode === 0) {
    return "file";
  }
  return "other";
}

function zipInspectionError(archiveLabel) {
  const error = new Error(
    `could not inspect zip archive members before extraction: ${archiveLabel}; pathDisplayed=false`
  );
  error.zipInspectionError = true;
  return error;
}

function displayArchiveLabel(archivePath) {
  const baseName = path.basename(String(archivePath || ""));
  return baseName || "archive";
}

function runTool(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: buildChildEnv(),
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
