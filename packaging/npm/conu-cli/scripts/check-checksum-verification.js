"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  parseSha256Checksum,
  sha256File,
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
    const maliciousChecksumTarget = "secret-npm-checksum-target-should-not-print.zip";
    expectFailure(
      `${digest}  ${maliciousChecksumTarget}\n`,
      "names wrong archive",
      "wrong archive name",
      {
        forbidden: [maliciousChecksumTarget],
        required: ["checksumTargetDisplayed=false", "contentsDisplayed=false"]
      }
    );
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
      const missingSecretPath = path.join(tempDir, "secret-checksum-target-path.zip");
      expectHashFailure(
        () => sha256File(missingSecretPath),
        "checksum target could not be read",
        "direct checksum target read failure",
        {
          forbidden: [tempDir, missingSecretPath, "secret-checksum-target-path"],
          required: ["errorCode=ENOENT", "pathDisplayed=false", "contentsDisplayed=false"]
        }
      );
      expectHashFailure(
        () => verifySha256File(missingSecretPath, `${digest}  ${ARCHIVE_NAME}\n`, ARCHIVE_NAME),
        "checksum target could not be read",
        "verify checksum target read failure",
        {
          forbidden: [tempDir, missingSecretPath, "secret-checksum-target-path"],
          required: ["errorCode=ENOENT", "pathDisplayed=false", "contentsDisplayed=false"]
        }
      );
    } finally {
      fs.readFileSync = originalReadFileSync;
    }
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
  console.log("checksum verification check passed");
}

function expectFailure(checksumText, expectedMessage, label, options = {}) {
  try {
    parseSha256Checksum(checksumText, ARCHIVE_NAME);
  } catch (error) {
    if (!error.message.includes(expectedMessage)) {
      throw new Error(`expected ${label} to fail with ${expectedMessage}, got: ${error.message}`);
    }
    for (const value of options.required || []) {
      if (!error.message.includes(value)) {
        throw new Error(`expected ${label} failure to include ${value}, got: ${error.message}`);
      }
    }
    for (const value of options.forbidden || []) {
      if (error.message.includes(value)) {
        throw new Error(`expected ${label} failure to redact ${value}, got: ${error.message}`);
      }
    }
    return;
  }
  throw new Error(`expected ${label} to fail`);
}

function expectHashFailure(callback, expectedMessage, label, options = {}) {
  try {
    callback();
  } catch (error) {
    if (!error.message.includes(expectedMessage)) {
      throw new Error(`expected ${label} to fail with ${expectedMessage}, got: ${error.message}`);
    }
    for (const value of options.required || []) {
      if (!error.message.includes(value)) {
        throw new Error(`expected ${label} failure to include ${value}, got: ${error.message}`);
      }
    }
    for (const value of options.forbidden || []) {
      if (error.message.includes(value)) {
        throw new Error(`expected ${label} failure to redact ${value}, got: ${error.message}`);
      }
    }
    return;
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
