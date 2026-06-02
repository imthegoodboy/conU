"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { BINARIES, binarySuffix, vendorDir } = require("../lib/platform");

const packageRoot = path.resolve(__dirname, "..");

function main() {
  const checkOnly = runNode([path.join(packageRoot, "scripts", "install.js"), "--check-only"]);
  expectNoLocalPath(checkOnly, packageRoot, "check-only package root");
  expectNoLocalPath(checkOnly, vendorDir(), "check-only vendor dir");
  expectIncludes(checkOnly, "pathDisplayed=false", "check-only path display guard");

  withFixture((root) => {
    const packageCopy = path.join(root, "package");
    const binaryDir = path.join(root, "override-binaries");
    copyPackage(packageRoot, packageCopy);
    writeBinaries(binaryDir);

    const output = runNode([path.join(packageCopy, "scripts", "install.js")], {
      CONU_NPM_BINARY_DIR: binaryDir,
      CONU_NPM_SKIP_DOWNLOAD: "",
      CONU_NPM_DIST_BASE: "",
      CONU_NPM_ALLOW_UNVERIFIED: ""
    });

    expectNoLocalPath(output, root, "local install temp root");
    expectNoLocalPath(output, binaryDir, "local install source dir");
    expectNoLocalPath(output, path.join(packageCopy, "vendor"), "local install vendor dir");
    expectIncludes(output, "sourcePathDisplayed=false", "local install source path guard");
  });

  console.log("install output privacy check passed");
}

function runNode(args, envOverrides = {}) {
  const env = { ...process.env, ...envOverrides };
  for (const [name, value] of Object.entries(envOverrides)) {
    if (value === "") {
      delete env[name];
    }
  }
  const result = spawnSync(process.execPath, args, {
    cwd: packageRoot,
    env,
    encoding: "utf8",
    errors: "replace",
    stdout: "pipe",
    stderr: "pipe"
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  if (result.status !== 0) {
    throw new Error(`node command failed with ${result.status}: ${output}`);
  }
  return output;
}

function withFixture(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "conu-install-output-privacy-"));
  try {
    callback(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function copyPackage(source, destination) {
  fs.cpSync(source, destination, {
    recursive: true,
    filter: (entry) => {
      const relative = path.relative(source, entry);
      if (!relative) {
        return true;
      }
      const firstPart = relative.split(path.sep)[0];
      return !["node_modules", "vendor"].includes(firstPart);
    }
  });
}

function writeBinaries(binaryDir) {
  fs.mkdirSync(binaryDir, { recursive: true });
  const suffix = binarySuffix();
  for (const name of BINARIES) {
    fs.writeFileSync(path.join(binaryDir, `${name}${suffix}`), `${name}\n`);
  }
}

function expectNoLocalPath(output, value, label) {
  const normalized = String(value);
  if (normalized && output.includes(normalized)) {
    throw new Error(`${label}: output displayed local path ${normalized}`);
  }
}

function expectIncludes(output, value, label) {
  if (!output.includes(value)) {
    throw new Error(`${label}: expected output to include ${value}`);
  }
}

main();
