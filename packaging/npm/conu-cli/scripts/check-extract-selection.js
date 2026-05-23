"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  expectedReleaseRootName,
  resolveExtractedBinaries
} = require("../lib/extract-selection");

const ARCHIVE_NAME = "conu-0.1.0-linux-x64.tar.gz";
const ROOT_NAME = "conu-0.1.0-linux-x64";
const BINARIES = ["conu", "conud", "conu-relay", "conu-mcp"];

function main() {
  expectEqual(expectedReleaseRootName("conu-0.1.0-linux-x64.tar.gz"), ROOT_NAME);
  expectEqual(expectedReleaseRootName("conu-0.1.0-windows-x64.zip"), "conu-0.1.0-windows-x64");

  withFixture((root) => {
    writeReleaseLayout(root);
    expectResolved(root, root, "rootless release layout");
  });

  withFixture((root) => {
    const releaseRoot = path.join(root, ROOT_NAME);
    writeReleaseLayout(releaseRoot);
    expectResolved(root, releaseRoot, "rooted release layout");
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    writeReleaseLayout(path.join(root, ROOT_NAME));
    expectFailure(root, "multiple release roots", "ambiguous release root");
  });

  withFixture((root) => {
    writeBinaries(path.join(root, "bin"));
    expectFailure(root, "missing manifest.toml", "missing manifest");
  });

  withFixture((root) => {
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, "manifest.toml"), "payload_contents_included = false\n");
    writeFile(path.join(root, "other", "bin", "conu"), "wrong");
    for (const name of BINARIES.slice(1)) {
      writeFile(path.join(root, "bin", name), name);
    }
    expectFailure(root, "missing expected binary", "misplaced required binary");
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    writeFile(path.join(root, "docs", "conu"), "duplicate");
    expectFailure(root, "unexpected conu path", "duplicate binary outside expected bin");
  });

  console.log("extract selection check passed");
}

function withFixture(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-extract-selection-"));
  try {
    callback(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function writeReleaseLayout(root) {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "manifest.toml"), "payload_contents_included = false\n");
  writeBinaries(path.join(root, "bin"));
}

function writeBinaries(binDir) {
  for (const name of BINARIES) {
    writeFile(path.join(binDir, name), name);
  }
}

function writeFile(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function expectResolved(root, expectedRoot, label) {
  const resolved = resolveExtractedBinaries(root, {
    archiveName: ARCHIVE_NAME,
    binaryNames: BINARIES,
    binarySuffix: ""
  });
  for (const name of BINARIES) {
    expectEqual(resolved[name], path.join(expectedRoot, "bin", name), label);
  }
}

function expectFailure(root, expectedMessage, label) {
  try {
    resolveExtractedBinaries(root, {
      archiveName: ARCHIVE_NAME,
      binaryNames: BINARIES,
      binarySuffix: ""
    });
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`${label}: expected ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`${label}: expected extract selection failure`);
}

function expectEqual(actual, expected, label = "value") {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

main();
