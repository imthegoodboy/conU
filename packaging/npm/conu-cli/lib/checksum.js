"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const HASH_CHUNK_BYTES = 1024 * 1024;
const CHECKSUM_RE = /^([0-9a-fA-F]{64})[ \t]+([^\x00-\x20\x7F]+)(?:\r?\n)?$/u;

function parseSha256Checksum(checksumText, expectedArchiveName) {
  if (typeof checksumText !== "string") {
    throw new Error(`checksum file has invalid format for ${expectedArchiveName}`);
  }
  const match = CHECKSUM_RE.exec(checksumText);
  if (!match) {
    throw new Error(`checksum file has invalid format for ${expectedArchiveName}`);
  }

  const archiveName = match[2];
  if (archiveName !== expectedArchiveName) {
    throw new Error(`checksum file for ${expectedArchiveName} names wrong archive: ${archiveName}`);
  }

  return match[1].toLowerCase();
}

function sha256File(filePath) {
  const digest = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
  const fd = fs.openSync(filePath, "r");
  try {
    while (true) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) {
        break;
      }
      digest.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
  return digest.digest("hex");
}

function verifySha256File(filePath, checksumText, expectedArchiveName = path.basename(filePath)) {
  const expected = parseSha256Checksum(checksumText, expectedArchiveName);
  const actual = sha256File(filePath);
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${expectedArchiveName}`);
  }
}

module.exports = {
  HASH_CHUNK_BYTES,
  parseSha256Checksum,
  sha256File,
  verifySha256File
};
