"use strict";

const {
  MAX_ARCHIVE_MEMBERS,
  assertSafeArchiveMemberList
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

main();
