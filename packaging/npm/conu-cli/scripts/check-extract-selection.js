"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  DEFAULT_MAX_EXTRACTED_DEPTH,
  DEFAULT_MAX_EXTRACTED_ENTRIES,
  expectedReleaseRootName,
  resolveExtractedBinaries
} = require("../lib/extract-selection");

const ARCHIVE_NAME = "conu-0.1.0-linux-x64.tar.gz";
const ROOT_NAME = "conu-0.1.0-linux-x64";
const BINARIES = ["conu", "conud", "conu-relay", "conu-mcp"];

function main() {
  expectEqual(expectedReleaseRootName("conu-0.1.0-linux-x64.tar.gz"), ROOT_NAME);
  expectEqual(expectedReleaseRootName("conu-0.1.0-windows-x64.zip"), "conu-0.1.0-windows-x64");
  if (DEFAULT_MAX_EXTRACTED_ENTRIES < 6) {
    throw new Error("default extracted entry limit must fit the release layout");
  }
  if (DEFAULT_MAX_EXTRACTED_DEPTH < 2) {
    throw new Error("default extracted depth limit must fit the release layout");
  }

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
    const secretPath = path.join(root, "docs", "secret-token-fragment", "conu");
    writeFile(secretPath, "duplicate");
    expectRedactedFailure(
      root,
      "unexpected conu path",
      "docs/secret-token-fragment/conu",
      "duplicate binary outside expected bin"
    );
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    withPatchedFs({ statSync: () => failWithPath(root) }, () => {
      expectRedactedFailure(
        root,
        "failed to inspect extracted tree",
        root,
        "redacted extracted stat failure"
      );
    });
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    withPatchedFs({ opendirSync: () => failWithPath(root) }, () => {
      expectRedactedFailure(
        root,
        "failed to inspect extracted tree",
        root,
        "redacted extracted directory open failure"
      );
    });
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    expectFailure(
      root,
      "exceeds maximum entry count",
      "extracted entry count bound",
      { maxExtractedEntries: 5 }
    );
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    expectFailure(
      root,
      "exceeds maximum depth",
      "extracted directory depth bound",
      { maxExtractedDepth: 1 }
    );
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    expectFailure(root, "invalid maxExtractedEntries", "invalid extracted entry bound", {
      maxExtractedEntries: 0
    });
  });

  withFixture((root) => {
    writeReleaseLayout(root);
    expectFailure(root, "invalid maxExtractedDepth", "invalid extracted depth bound", {
      maxExtractedDepth: 0
    });
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

function withPatchedFs(patches, callback) {
  const originals = {};
  for (const name of Object.keys(patches)) {
    originals[name] = fs[name];
    fs[name] = patches[name];
  }
  try {
    callback();
  } finally {
    for (const name of Object.keys(originals)) {
      fs[name] = originals[name];
    }
  }
}

function failWithPath(root) {
  throw new Error(`simulated filesystem failure at ${root}`);
}

function expectResolved(root, expectedRoot, label) {
  const resolved = resolveExtractedBinaries(root, resolveOptions());
  for (const name of BINARIES) {
    expectEqual(resolved[name], path.join(expectedRoot, "bin", name), label);
  }
}

function expectFailure(root, expectedMessage, label, overrides = {}) {
  try {
    resolveExtractedBinaries(root, resolveOptions(overrides));
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`${label}: expected ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`${label}: expected extract selection failure`);
}

function expectRedactedFailure(root, expectedMessage, forbiddenPath, label, overrides = {}) {
  try {
    resolveExtractedBinaries(root, resolveOptions(overrides));
  } catch (error) {
    const message = error.message;
    if (!message.includes(expectedMessage)) {
      throw new Error(`${label}: expected ${expectedMessage}, got: ${message}`);
    }
    if (!message.includes("pathDisplayed=false")) {
      throw new Error(`${label}: missing path display guard: ${message}`);
    }
    if (!message.includes("contentsDisplayed=false")) {
      throw new Error(`${label}: missing contents display guard: ${message}`);
    }
    if (message.includes(forbiddenPath)) {
      throw new Error(`${label}: displayed filesystem path: ${message}`);
    }
    return;
  }
  throw new Error(`${label}: expected redacted extract selection failure`);
}

function resolveOptions(overrides = {}) {
  return {
    archiveName: ARCHIVE_NAME,
    binaryNames: BINARIES,
    binarySuffix: "",
    ...overrides
  };
}

function expectEqual(actual, expected, label = "value") {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

main();
