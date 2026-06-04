"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { resolveLocalBinaries } = require("../lib/local-binary-dir");

const BINARIES = ["conu", "conud", "conu-relay", "conu-mcp"];

function main() {
  withFixture((root) => {
    writeBinaries(root);
    const resolved = resolve(root);
    for (const name of BINARIES) {
      expectEqual(resolved[name], path.join(root, name), `resolved ${name}`);
    }
  });

  withFixture((root) => {
    expectFailure(path.join(root, "missing"), "existing directory", "missing source directory");
  });

  withFixture((root) => {
    const source = path.join(root, "not-a-directory");
    fs.writeFileSync(source, "not a directory");
    expectFailure(source, "existing directory", "file source path");
  });

  withFixture((root) => {
    const realDir = path.join(root, "real-binaries");
    const linkDir = path.join(root, "linked-binaries");
    fs.mkdirSync(realDir);
    if (!trySymlink(linkDir, realDir, "dir")) {
      return;
    }
    expectFailure(linkDir, "must not be a symlink", "symlink source directory");
  });

  withFixture((root) => {
    writeBinaries(root, { skip: "conud" });
    expectFailure(root, "missing required binary: conud", "missing binary");
  });

  withFixture((root) => {
    writeBinaries(root, { skip: "conu-relay" });
    fs.mkdirSync(path.join(root, "conu-relay"));
    expectFailure(root, "not a regular file: conu-relay", "directory named as binary");
  });

  withFixture((root) => {
    writeBinaries(root);
    expectFailure("", "existing directory", "empty source directory");
  });

  console.log("local binary dir check passed");
}

function withFixture(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-local-binary-dir-"));
  try {
    callback(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function writeBinaries(root, options = {}) {
  fs.mkdirSync(root, { recursive: true });
  for (const name of BINARIES) {
    if (name === options.skip) {
      continue;
    }
    fs.writeFileSync(path.join(root, name), name);
  }
}

function trySymlink(link, target, type) {
  try {
    fs.symlinkSync(target, link, type);
    return true;
  } catch (error) {
    if (
      error &&
      ["EPERM", "EACCES", "ENOSYS", "EINVAL"].includes(error.code)
    ) {
      return false;
    }
    throw error;
  }
}

function resolve(sourceDir) {
  return resolveLocalBinaries(sourceDir, {
    binaryNames: BINARIES,
    binarySuffix: ""
  });
}

function expectFailure(sourceDir, expectedMessage, label) {
  try {
    resolve(sourceDir);
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`${label}: expected ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`${label}: expected local binary dir failure`);
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

main();
