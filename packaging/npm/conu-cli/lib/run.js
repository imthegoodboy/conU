"use strict";

const fs = require("node:fs");
const { spawn } = require("node:child_process");
const { BINARIES, binaryPath } = require("./platform");

const binaryName = readBinaryName(process.env.CONU_BIN_NAME);
const executable = resolveExecutable(binaryName);

assertSafeExecutable(binaryName, executable);

const child = launchExecutable(binaryName, executable);

child.on("error", (error) => {
  reportLaunchError(binaryName, error);
});

child.on("exit", (code, signal) => {
  if (signal) {
    try {
      process.kill(process.pid, signal);
    } catch (_error) {
      process.exit(1);
    }
    return;
  }
  process.exit(code === null ? 1 : code);
});

function readBinaryName(name) {
  if (BINARIES.includes(name)) {
    return name;
  }
  console.error("conU binary selection is invalid; pathDisplayed=false contentsDisplayed=false");
  process.exit(127);
}

function resolveExecutable(name) {
  try {
    return binaryPath(name);
  } catch (error) {
    console.error(
      `conU binary is unavailable for this platform: ${platformErrorMessage(error)}; pathDisplayed=false contentsDisplayed=false`
    );
    process.exit(127);
  }
}

function assertSafeExecutable(name, executable) {
  let stat;
  try {
    stat = fs.lstatSync(executable);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      failInstallState(name, "conU binary is missing");
    } else {
      failInstallState(
        name,
        `conU binary could not be inspected; errorCode=${runtimeErrorCode(error)}`
      );
    }
  }

  if (stat.isSymbolicLink()) {
    failInstallState(name, "conU binary is unsafe");
  }

  if (!stat.isFile()) {
    failInstallState(name, "conU binary is not a regular file");
  }
}

function failInstallState(name, message) {
  console.error(`${message} for ${name}; pathDisplayed=false contentsDisplayed=false`);
  console.error("Run npm install again, or set CONU_NPM_BINARY_DIR during install.");
  process.exit(127);
}

function launchExecutable(name, executable) {
  try {
    return spawn(executable, process.argv.slice(2), {
      stdio: "inherit",
      env: process.env
    });
  } catch (error) {
    reportLaunchError(name, error);
  }
}

function reportLaunchError(name, error) {
  console.error(
    `failed to launch ${name}; errorCode=${runtimeErrorCode(error)} pathDisplayed=false contentsDisplayed=false`
  );
  process.exit(1);
}

function platformErrorMessage(error) {
  const message = error && typeof error.message === "string" ? error.message : "";
  if (message.startsWith("unsupported conU platform: ")) {
    return message;
  }
  if (message === "the npm package currently ships Windows x64 binaries only") {
    return message;
  }
  return "runtime configuration error";
}

function runtimeErrorCode(error) {
  const code = error && typeof error.code === "string" ? error.code : "";
  if (/^[A-Z0-9_]+$/.test(code)) {
    return code;
  }
  return "UNKNOWN";
}
