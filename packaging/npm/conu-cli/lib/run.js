"use strict";

const fs = require("node:fs");
const { spawn } = require("node:child_process");
const { binaryPath } = require("./platform");

const binaryName = process.env.CONU_BIN_NAME;
const executable = binaryPath(binaryName);

if (!fs.existsSync(executable)) {
  console.error(`conU binary is missing: ${executable}`);
  console.error("Run npm install again, or set CONU_NPM_BINARY_DIR during install.");
  process.exit(127);
}

const child = spawn(executable, process.argv.slice(2), {
  stdio: "inherit",
  env: process.env
});

child.on("error", (error) => {
  console.error(`failed to launch ${binaryName}: ${error.message}`);
  process.exit(1);
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
