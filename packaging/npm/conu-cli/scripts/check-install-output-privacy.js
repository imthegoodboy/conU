"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { buildChildEnv } = require("../lib/child-env");
const { BINARIES, binarySuffix, platformKey, vendorDir } = require("../lib/platform");

const packageRoot = path.resolve(__dirname, "..");

function main() {
  const installScript = fs.readFileSync(path.join(packageRoot, "scripts", "install.js"), "utf8");
  const archivePreflight = fs.readFileSync(path.join(packageRoot, "lib", "archive-preflight.js"), "utf8");
  expectNotIncludes(installScript, 'stdio: "inherit"', "installer child output privacy guard");
  expectIncludes(
    installScript,
    'const { buildChildEnv } = require("../lib/child-env");',
    "installer child env scrub import"
  );
  expectOccurrenceCount(
    installScript,
    "env: buildChildEnv()",
    2,
    "installer extraction tool env scrub guard"
  );
  expectIncludes(
    installScript,
    "const EXTRACT_TOOL_TIMEOUT_MS =",
    "installer extraction timeout constant"
  );
  expectOccurrenceCount(
    installScript,
    "timeout: EXTRACT_TOOL_TIMEOUT_MS",
    2,
    "installer extraction tool timeout guard"
  );
  expectIncludes(
    archivePreflight,
    'const { buildChildEnv } = require("./child-env");',
    "archive preflight child env scrub import"
  );
  expectOccurrenceCount(
    archivePreflight,
    "env: buildChildEnv()",
    1,
    "archive preflight tool env scrub guard"
  );
  expectIncludes(
    archivePreflight,
    "const MAX_ARCHIVE_TOOL_TIMEOUT_MS =",
    "archive preflight tool timeout constant"
  );
  expectOccurrenceCount(
    archivePreflight,
    "timeout: MAX_ARCHIVE_TOOL_TIMEOUT_MS",
    1,
    "archive preflight tool timeout guard"
  );

  expectChildEnvScrubsWrapperSelector();

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

  expectLocalBinaryDirFailureIsRedacted();
  expectLauncherMissingBinaryIsRedacted();
  expectLauncherInvalidBinaryIsRedacted();
  expectLauncherNonFileBinaryIsRedacted();
  expectLauncherSymlinkBinaryIsRedacted();

  console.log("install and launcher output privacy check passed");
}

function runNode(args, envOverrides = {}) {
  const env = buildEnv(envOverrides);
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

function runNodeFailure(args, envOverrides = {}, cwd = packageRoot) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    env: buildEnv(envOverrides),
    encoding: "utf8",
    errors: "replace",
    stdout: "pipe",
    stderr: "pipe"
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  if (result.status === 0) {
    throw new Error(`expected node command to fail, but it passed: ${output}`);
  }
  return output;
}

function buildEnv(envOverrides = {}) {
  const env = { ...process.env, ...envOverrides };
  for (const [name, value] of Object.entries(envOverrides)) {
    if (value === "") {
      delete env[name];
    }
  }
  return env;
}

function expectChildEnvScrubsWrapperSelector() {
  const sourceEnv = {
    CONU_BIN_NAME: "conu",
    CONU_HOME: "runtime-state",
    CONU_NPM_ALLOW_UNVERIFIED: "1",
    CONU_NPM_BINARY_DIR: "local-binary-dir",
    CONU_NPM_DIST_BASE: "https://example.invalid/conu",
    CONU_NPM_DOWNLOAD_TIMEOUT_MS: "5000",
    CONU_NPM_MAX_ARCHIVE_BYTES: "1024",
    CONU_NPM_MAX_CHECKSUM_BYTES: "512",
    CONU_RELAY_TOKEN: "relay-token",
    NODE_AUTH_TOKEN: "node-auth-token",
    NPM_CONFIG_USERCONFIG: "npm-user-config",
    NPM_PACKAGE_NAME: "@conu/cli",
    NPM_TOKEN: "npm-token",
    npm_command: "exec",
    npm_config_cache: "npm-cache",
    "npm_config_//registry.npmjs.org/:_authToken": "registry-auth-token",
    npm_lifecycle_event: "start"
  };
  const childEnv = buildChildEnv(sourceEnv);
  if ("CONU_BIN_NAME" in childEnv) {
    throw new Error("launcher child env included wrapper-only CONU_BIN_NAME");
  }
  for (const name of [
    "CONU_NPM_ALLOW_UNVERIFIED",
    "CONU_NPM_BINARY_DIR",
    "CONU_NPM_DIST_BASE",
    "CONU_NPM_DOWNLOAD_TIMEOUT_MS",
    "CONU_NPM_MAX_ARCHIVE_BYTES",
    "CONU_NPM_MAX_CHECKSUM_BYTES",
    "NODE_AUTH_TOKEN",
    "NPM_CONFIG_USERCONFIG",
    "NPM_PACKAGE_NAME",
    "NPM_TOKEN",
    "npm_command",
    "npm_config_cache",
    "npm_config_//registry.npmjs.org/:_authToken",
    "npm_lifecycle_event"
  ]) {
    if (name in childEnv) {
      throw new Error(`launcher child env included package-manager env ${name}`);
    }
  }
  expectEqual(childEnv.CONU_HOME, "runtime-state", "child env keeps conU runtime env");
  expectEqual(childEnv.CONU_RELAY_TOKEN, "relay-token", "child env keeps conU relay env");
  if (!("CONU_BIN_NAME" in sourceEnv)) {
    throw new Error("launcher child env builder mutated source env");
  }
  if (!("CONU_NPM_BINARY_DIR" in sourceEnv)) {
    throw new Error("launcher child env builder mutated installer env source");
  }
}

function expectLocalBinaryDirFailureIsRedacted() {
  withFixture((root) => {
    const packageCopy = path.join(root, "package");
    const missingBinaryDir = path.join(root, "secret-local-binary-dir");
    copyPackage(packageRoot, packageCopy);

    const output = runNodeFailure([path.join(packageCopy, "scripts", "install.js")], {
      CONU_NPM_BINARY_DIR: missingBinaryDir,
      CONU_NPM_SKIP_DOWNLOAD: "",
      CONU_NPM_DIST_BASE: "",
      CONU_NPM_ALLOW_UNVERIFIED: ""
    }, packageCopy);

    expectNoLocalPath(output, root, "local binary dir failure temp root");
    expectNotIncludes(output, missingBinaryDir, "local binary dir failure override path guard");
    expectIncludes(output, "CONU_NPM_BINARY_DIR must point to an existing directory", "local binary dir failure reason");
  });
}

function expectLauncherMissingBinaryIsRedacted() {
  withFixture((root) => {
    const packageCopy = path.join(root, "package");
    copyPackage(packageRoot, packageCopy);

    const output = runNodeFailure([path.join(packageCopy, "bin", "conu.js")], {}, packageCopy);

    expectNoLocalPath(output, root, "launcher missing temp root");
    expectNoLocalPath(output, path.join(packageCopy, "vendor"), "launcher missing vendor dir");
    expectIncludes(output, "pathDisplayed=false", "launcher missing path display guard");
    expectIncludes(output, "contentsDisplayed=false", "launcher missing content display guard");
  });
}

function expectLauncherInvalidBinaryIsRedacted() {
  withFixture((root) => {
    const packageCopy = path.join(root, "package");
    const poisonedBinaryName = path.join(root, "env-secret-binary");
    copyPackage(packageRoot, packageCopy);

    const output = runNodeFailure([path.join(packageCopy, "lib", "run.js")], {
      CONU_BIN_NAME: poisonedBinaryName
    }, packageCopy);

    expectNoLocalPath(output, root, "launcher invalid env temp root");
    expectNotIncludes(output, poisonedBinaryName, "launcher invalid env value guard");
    expectIncludes(output, "contentsDisplayed=false", "launcher invalid env content display guard");
  });
}

function expectLauncherNonFileBinaryIsRedacted() {
  withFixture((root) => {
    const packageCopy = path.join(root, "package");
    copyPackage(packageRoot, packageCopy);

    const executable = path.join(packageCopy, "vendor", platformKey(), `conu${binarySuffix()}`);
    fs.mkdirSync(executable, { recursive: true });

    const output = runNodeFailure([path.join(packageCopy, "bin", "conu.js")], {}, packageCopy);

    expectNoLocalPath(output, root, "launcher non-file temp root");
    expectIncludes(output, "not a regular file", "launcher non-file target guard");
    expectIncludes(output, "pathDisplayed=false", "launcher non-file path display guard");
    expectIncludes(output, "contentsDisplayed=false", "launcher non-file content display guard");
  });
}

function expectLauncherSymlinkBinaryIsRedacted() {
  withFixture((root) => {
    const packageCopy = path.join(root, "package");
    const outside = path.join(root, "outside-binary");
    copyPackage(packageRoot, packageCopy);
    fs.writeFileSync(outside, "do not run\n");

    const executable = path.join(packageCopy, "vendor", platformKey(), `conu${binarySuffix()}`);
    fs.mkdirSync(path.dirname(executable), { recursive: true });
    if (!trySymlink(executable, outside, "file")) {
      return;
    }

    const output = runNodeFailure([path.join(packageCopy, "bin", "conu.js")], {}, packageCopy);

    expectNoLocalPath(output, root, "launcher symlink temp root");
    expectIncludes(output, "binary is unsafe", "launcher symlink target guard");
    expectIncludes(output, "pathDisplayed=false", "launcher symlink path display guard");
    expectIncludes(output, "contentsDisplayed=false", "launcher symlink content display guard");
  });
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

function expectNotIncludes(output, value, label) {
  if (output.includes(value)) {
    throw new Error(`${label}: expected output not to include ${value}`);
  }
}

function expectOccurrenceCount(output, value, expectedCount, label) {
  const actualCount = output.split(value).length - 1;
  if (actualCount !== expectedCount) {
    throw new Error(`${label}: expected ${expectedCount} occurrence(s), got ${actualCount}`);
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

main();
