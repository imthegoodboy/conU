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
    throw new Error(
      "checksum file names wrong archive; checksumTargetDisplayed=false contentsDisplayed=false"
    );
  }

  return match[1].toLowerCase();
}

function sha256File(filePath) {
  const digest = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
  let fd = null;
  let readFailed = false;
  try {
    fd = fs.openSync(filePath, "r");
    while (true) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) {
        break;
      }
      digest.update(buffer.subarray(0, bytesRead));
    }
  } catch (error) {
    readFailed = true;
    throw checksumTargetReadError(error);
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch (error) {
        if (!readFailed) {
          throw checksumTargetReadError(error);
        }
      }
    }
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

function checksumTargetReadError(error) {
  return new Error(
    `checksum target could not be read; errorCode=${runtimeErrorCode(error)} pathDisplayed=false contentsDisplayed=false`
  );
}

function runtimeErrorCode(error) {
  const code = error && typeof error.code === "string" ? error.code : "";
  if (/^[A-Z0-9_]+$/.test(code)) {
    return code;
  }
  return "UNKNOWN";
}

module.exports = {
  HASH_CHUNK_BYTES,
  parseSha256Checksum,
  sha256File,
  verifySha256File
};
