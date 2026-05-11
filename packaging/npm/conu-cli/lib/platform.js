"use strict";

const fs = require("node:fs");
const path = require("node:path");

const BINARIES = ["conu", "conud", "conu-relay", "conu-mcp"];

function packageRoot() {
  return path.resolve(__dirname, "..");
}

function packageVersion() {
  const raw = fs.readFileSync(path.join(packageRoot(), "package.json"), "utf8");
  return JSON.parse(raw).version;
}

function binarySuffix() {
  return process.platform === "win32" ? ".exe" : "";
}

function platformKey() {
  const platforms = {
    win32: "windows",
    linux: "linux",
    darwin: "macos"
  };
  const arches = {
    x64: "x64",
    arm64: "arm64"
  };
  const platform = platforms[process.platform];
  const arch = arches[process.arch];
  if (!platform || !arch) {
    throw new Error(`unsupported conU platform: ${process.platform}-${process.arch}`);
  }
  if (platform === "windows" && arch !== "x64") {
    throw new Error("the npm package currently ships Windows x64 binaries only");
  }
  return `${platform}-${arch}`;
}

function archiveExtension() {
  return process.platform === "win32" ? ".zip" : ".tar.gz";
}

function assetName(version = packageVersion()) {
  return `conu-${version}-${platformKey()}${archiveExtension()}`;
}

function vendorDir() {
  return path.join(packageRoot(), "vendor", platformKey());
}

function binaryPath(name) {
  if (!BINARIES.includes(name)) {
    throw new Error(`unsupported conU binary: ${name}`);
  }
  return path.join(vendorDir(), `${name}${binarySuffix()}`);
}

module.exports = {
  BINARIES,
  archiveExtension,
  assetName,
  binaryPath,
  binarySuffix,
  packageRoot,
  packageVersion,
  platformKey,
  vendorDir
};
