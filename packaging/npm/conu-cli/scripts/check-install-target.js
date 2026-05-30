"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { installFile } = require("../lib/install-target");

function main() {
  withFixture((root) => {
    const source = writeSource(root, "conu");
    const target = path.join(root, "vendor", "linux-x64", "conu");
    install(root, source, target);
    expectEqual(fs.readFileSync(target, "utf8"), "conu\n", "installed binary contents");
  });

  withFixture((root) => {
    const source = writeSource(root, "new conu");
    const target = path.join(root, "vendor", "linux-x64", "conu");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "old conu\n");
    install(root, source, target);
    expectEqual(fs.readFileSync(target, "utf8"), "new conu\n", "replaced binary contents");
  });

  withFixture((root) => {
    const source = writeSource(root, "conu");
    const target = path.join(root, "vendor", "linux-x64", "conu");
    fs.mkdirSync(target, { recursive: true });
    expectFailure(
      () => install(root, source, target),
      "install target must be a regular file",
      "directory install target"
    );
  });

  withFixture((root) => {
    const realSource = writeSource(root, "real conu");
    const source = path.join(root, "source-link");
    if (!trySymlink(source, realSource, "file")) {
      return;
    }
    const target = path.join(root, "vendor", "linux-x64", "conu");
    expectFailure(
      () => install(root, source, target),
      "source must not be a symlink",
      "symlink source"
    );
  });

  withFixture((root) => {
    const source = writeSource(root, "conu");
    const target = path.join(root, "vendor", "linux-x64", "conu");
    const outside = path.join(root, "outside-target");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(outside, "outside\n");
    if (!trySymlink(target, outside, "file")) {
      return;
    }
    expectFailure(
      () => install(root, source, target),
      "install target must not be a symlink",
      "symlink install target"
    );
    expectEqual(fs.readFileSync(outside, "utf8"), "outside\n", "symlink target untouched");
  });

  withFixture((root) => {
    const source = writeSource(root, "conu");
    const realVendor = path.join(root, "real-vendor");
    const vendor = path.join(root, "vendor");
    fs.mkdirSync(realVendor);
    if (!trySymlink(vendor, realVendor, "dir")) {
      return;
    }
    const target = path.join(vendor, "linux-x64", "conu");
    expectFailure(
      () => install(root, source, target),
      "install directory must not be a symlink",
      "symlink vendor directory"
    );
  });

  console.log("install target check passed");
}

function install(root, source, target) {
  installFile(source, target, "test binary", { trustedRoot: root });
}

function withFixture(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-install-target-"));
  try {
    callback(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function writeSource(root, contents) {
  const source = path.join(root, "source-binary");
  fs.writeFileSync(source, `${contents}\n`);
  return source;
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

function expectFailure(action, expectedMessage, label) {
  try {
    action();
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`${label}: expected ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`${label}: expected install target failure`);
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

main();
