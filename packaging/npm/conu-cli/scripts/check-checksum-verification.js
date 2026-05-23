"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  parseSha256Checksum,
  verifySha256File
} = require("../lib/checksum");

const ARCHIVE_NAME = "conu-0.1.0-test.zip";

function main() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "conu-npm-checksum-"));
  try {
    const archivePath = path.join(tempDir, ARCHIVE_NAME);
    fs.writeFileSync(archivePath, Buffer.alloc(1024 * 1024 + 17, "a"));
    const digest = crypto.createHash("sha256").update(fs.readFileSync(archivePath)).digest("hex");

    expectEqual(
      parseSha256Checksum(`${digest}  ${ARCHIVE_NAME}\n`, ARCHIVE_NAME),
      digest,
      "strict checksum line"
    );
    expectEqual(
      parseSha256Checksum(`${digest}\t${ARCHIVE_NAME}\r\n`, ARCHIVE_NAME),
      digest,
      "strict checksum line with tab and CRLF"
    );

    expectFailure(`${digest}\n`, "invalid format", "missing archive name");
    expectFailure(`${digest}  ${ARCHIVE_NAME}\nextra\n`, "invalid format", "extra checksum content");
    expectFailure(`${digest}  ${ARCHIVE_NAME} extra\n`, "invalid format", "extra checksum fields");
    expectFailure(`${digest}  other.zip\n`, "names wrong archive", "wrong archive name");
    expectFailure(`not-a-sha256  ${ARCHIVE_NAME}\n`, "invalid format", "bad digest");

    const originalReadFileSync = fs.readFileSync;
    fs.readFileSync = () => {
      throw new Error("verifySha256File must not call readFileSync");
    };
    try {
      verifySha256File(archivePath, `${digest}  ${ARCHIVE_NAME}\n`, ARCHIVE_NAME);
      expectVerifyFailure(
        archivePath,
        `${"0".repeat(64)}  ${ARCHIVE_NAME}\n`,
        ARCHIVE_NAME,
        "checksum mismatch",
        "mismatched digest"
      );
    } finally {
      fs.readFileSync = originalReadFileSync;
    }
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
  console.log("checksum verification check passed");
}

function expectFailure(checksumText, expectedMessage, label) {
  try {
    parseSha256Checksum(checksumText, ARCHIVE_NAME);
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`expected ${label} to fail with ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`expected ${label} to fail`);
}

function expectVerifyFailure(archivePath, checksumText, archiveName, expectedMessage, label) {
  try {
    verifySha256File(archivePath, checksumText, archiveName);
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`expected ${label} to fail with ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`expected ${label} to fail`);
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`expected ${label} to be ${expected}, got ${actual}`);
  }
}

main();
