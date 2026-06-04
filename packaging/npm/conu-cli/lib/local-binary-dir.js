"use strict";

const fs = require("node:fs");
const path = require("node:path");

function resolveLocalBinaries(sourceDir, { binaryNames, binarySuffix }) {
  if (typeof sourceDir !== "string" || sourceDir.trim() === "") {
    throw new Error("CONU_NPM_BINARY_DIR must point to an existing directory");
  }

  const resolvedDir = path.resolve(sourceDir);
  const dirStat = lstatMaybe(resolvedDir);
  if (!dirStat) {
    throw new Error("CONU_NPM_BINARY_DIR must point to an existing directory");
  }
  if (dirStat.isSymbolicLink()) {
    throw new Error("CONU_NPM_BINARY_DIR must not be a symlink");
  }
  if (!dirStat.isDirectory()) {
    throw new Error("CONU_NPM_BINARY_DIR must point to an existing directory");
  }

  const binaries = {};
  for (const name of binaryNames) {
    const fileName = `${name}${binarySuffix}`;
    const source = path.join(resolvedDir, fileName);
    const stat = lstatMaybe(source);
    if (!stat) {
      throw new Error(`CONU_NPM_BINARY_DIR missing required binary: ${fileName}`);
    }
    if (!stat.isFile()) {
      throw new Error(`CONU_NPM_BINARY_DIR required binary is not a regular file: ${fileName}`);
    }
    binaries[name] = source;
  }
  return binaries;
}

function lstatMaybe(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

module.exports = {
  resolveLocalBinaries
};
