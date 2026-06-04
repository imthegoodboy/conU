"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  MAX_ARCHIVE_MEMBERS,
  assertSafeArchiveMemberList,
  validateArchiveMembers
} = require("../lib/archive-preflight");

const SAFE_MEMBERS = [
  { name: "conu-0.1.0/bin/conu", type: "file" },
  { name: "conu-0.1.0/bin/conud", type: "file" },
  { name: "conu-0.1.0/manifest.toml", type: "file" },
  { name: "conu-0.1.0/docs/", type: "directory" }
];

function main() {
  expectPass(SAFE_MEMBERS, "safe release archive layout");
  expectFail([{ name: "/tmp/conu", type: "file" }], "absolute archive path");
  expectFail([{ name: "C:\\temp\\conu.exe", type: "file" }], "absolute archive path");
  expectFail([{ name: "C:conu.exe", type: "file" }], "absolute archive path");
  expectFail([{ name: "conu-0.1.0/../conu.exe", type: "file" }], "parent-traversal archive path");
  expectFail([{ name: "conu-0.1.0/bin/conu\nsecret", type: "file" }], "unsafe archive path");
  expectFail([{ name: "conu-0.1.0/bin/conu", type: "symlink" }], "unsupported symlink member");
  expectFail([{ name: "conu-0.1.0/bin/conu", type: "hardlink" }], "unsupported hardlink member");
  expectFail([{ name: "conu-0.1.0/bin/conu", type: "other" }], "unsupported other member");
  expectFail([{ name: "conu-0.1.0/bin/conu", type: "unknown" }], "unsupported unknown member");
  expectFail(
    [
      { name: "conu-0.1.0/bin/conu", type: "file" },
      { name: "conu-0.1.0/bin/./conu", type: "file" }
    ],
    "duplicate archive path"
  );
  expectFail([{ name: "conu-0.1.0/.conu/state.toml", type: "file" }], "forbidden state path");
  expectFail([{ name: "conu-0.1.0/security/identity.key", type: "file" }], "forbidden state path");
  expectFail([{ name: "conu-0.1.0/runtime/node.toml", type: "file" }], "forbidden state path");
  expectFail(makeMemberList(MAX_ARCHIVE_MEMBERS + 1), `more than ${MAX_ARCHIVE_MEMBERS} entries`);
  expectArchiveInspectionPathRedacted();
  expectArchiveInspectionFailurePathGuard();
  console.log("archive member preflight check passed");
}

function expectPass(members, label) {
  assertSafeArchiveMemberList(members, label);
}

function expectFail(members, expectedMessage) {
  try {
    assertSafeArchiveMemberList(members, "fixture");
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`expected ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`expected archive preflight failure: ${expectedMessage}`);
}

function makeMemberList(count) {
  return Array.from({ length: count }, (_value, index) => ({
    name: `conu-0.1.0/docs/file-${index}.txt`,
    type: "file"
  }));
}

function expectArchiveInspectionPathRedacted() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-secret-local-path-"));
  try {
    const archive = path.join(root, "conu-0.1.0-windows-x64.zip");
    fs.writeFileSync(archive, "not a zip archive\n", "utf8");
    try {
      validateArchiveMembers(archive);
    } catch (error) {
      if (!error.message.includes(path.basename(archive))) {
        throw new Error(`expected archive filename in error, got: ${error.message}`);
      }
      if (error.message.includes(root) || error.message.includes(archive)) {
        throw new Error(`archive preflight leaked local path: ${error.message}`);
      }
      return;
    }
    throw new Error("expected invalid archive inspection failure");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function expectArchiveInspectionFailurePathGuard() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-secret-inspect-path-"));
  try {
    const archive = path.join(root, "conu-0.1.0.invalid");
    fs.writeFileSync(archive, "not an archive\n", "utf8");
    try {
      validateArchiveMembers(archive);
    } catch (error) {
      if (!error.message.includes("pathDisplayed=false")) {
        throw new Error(`expected path display guard, got: ${error.message}`);
      }
      if (!error.message.includes(path.basename(archive))) {
        throw new Error(`expected archive filename in error, got: ${error.message}`);
      }
      if (error.message.includes(root) || error.message.includes(archive)) {
        throw new Error(`archive inspection failure leaked local path: ${error.message}`);
      }
      return;
    }
    throw new Error("expected archive inspection failure");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main();
