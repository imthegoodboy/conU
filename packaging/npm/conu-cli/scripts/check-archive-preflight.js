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
  expectNativeZipInspection();
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

function expectNativeZipInspection() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-native-zip-preflight-"));
  try {
    const safeArchive = path.join(root, "conu-0.1.0-windows-x64.zip");
    writeZipFixture(safeArchive, [
      { name: "conu-0.1.0-windows-x64/bin/conu.exe", mode: 0o100644 },
      { name: "conu-0.1.0-windows-x64/docs/", mode: 0o040755 }
    ]);
    validateArchiveMembers(safeArchive);

    const traversalArchive = path.join(root, "conu-0.1.0-windows-x64-traversal.zip");
    writeZipFixture(traversalArchive, [
      { name: "conu-0.1.0-windows-x64/../conu.exe", mode: 0o100644 }
    ]);
    expectValidateArchiveFail(traversalArchive, "parent-traversal archive path");

    const symlinkArchive = path.join(root, "conu-0.1.0-windows-x64-symlink.zip");
    writeZipFixture(symlinkArchive, [
      { name: "conu-0.1.0-windows-x64/bin/conu.exe", mode: 0o120777 }
    ]);
    expectValidateArchiveFail(symlinkArchive, "unsupported symlink member");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function expectValidateArchiveFail(archive, expectedMessage) {
  try {
    validateArchiveMembers(archive);
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`expected ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`expected archive inspection failure: ${expectedMessage}`);
}

function writeZipFixture(archive, entries) {
  const localHeaders = [];
  const centralHeaders = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const localHeader = zipLocalHeader(name);
    localHeaders.push(localHeader);
    centralHeaders.push(zipCentralHeader(name, localOffset, entry));
    localOffset += localHeader.length;
  }

  const centralDirectory = Buffer.concat(centralHeaders);
  const eocd = zipEndOfCentralDirectory(entries.length, centralDirectory.length, localOffset);
  fs.writeFileSync(archive, Buffer.concat([...localHeaders, centralDirectory, eocd]));
}

function zipLocalHeader(name) {
  const header = Buffer.alloc(30 + name.length);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0x0800, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt32LE(0, 10);
  header.writeUInt32LE(0, 14);
  header.writeUInt32LE(0, 18);
  header.writeUInt32LE(0, 22);
  header.writeUInt16LE(name.length, 26);
  header.writeUInt16LE(0, 28);
  name.copy(header, 30);
  return header;
}

function zipCentralHeader(name, localOffset, entry) {
  const header = Buffer.alloc(46 + name.length);
  const mode = entry.mode === undefined ? 0o100644 : entry.mode;
  const externalAttributes = (mode << 16) >>> 0;
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(0x0314, 4);
  header.writeUInt16LE(20, 6);
  header.writeUInt16LE(0x0800, 8);
  header.writeUInt16LE(0, 10);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt16LE(name.length, 28);
  header.writeUInt16LE(0, 30);
  header.writeUInt16LE(0, 32);
  header.writeUInt16LE(0, 34);
  header.writeUInt16LE(0, 36);
  header.writeUInt32LE(externalAttributes, 38);
  header.writeUInt32LE(localOffset, 42);
  name.copy(header, 46);
  return header;
}

function zipEndOfCentralDirectory(entryCount, centralSize, centralOffset) {
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entryCount, 8);
  eocd.writeUInt16LE(entryCount, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  eocd.writeUInt16LE(0, 20);
  return eocd;
}

function expectArchiveInspectionPathRedacted() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-secret-local-path-"));
  try {
    const archive = path.join(root, "conu-invalid-archive-fixture.zip");
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
