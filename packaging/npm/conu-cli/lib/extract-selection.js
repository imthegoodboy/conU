"use strict";

const fs = require("node:fs");
const path = require("node:path");

function expectedReleaseRootName(assetName) {
  if (assetName.endsWith(".tar.gz")) {
    return assetName.slice(0, -".tar.gz".length);
  }
  return path.basename(assetName, path.extname(assetName));
}

function resolveExtractedBinaries(
  extractDir,
  { archiveName, binaryNames, binarySuffix, expectedRootName = expectedReleaseRootName(archiveName) }
) {
  const root = resolveReleaseRoot(extractDir, archiveName, expectedRootName);
  const resolved = {};
  for (const name of binaryNames) {
    const expectedPath = path.join(root, "bin", `${name}${binarySuffix}`);
    if (!isFile(expectedPath)) {
      throw new Error(`archive ${archiveName} missing expected binary: bin/${name}${binarySuffix}`);
    }

    const matches = findBinaryMatches(extractDir, `${name}${binarySuffix}`);
    const unexpected = matches.filter((candidate) => !samePath(candidate, expectedPath));
    if (unexpected.length > 0) {
      throw new Error(
        `archive ${archiveName} contains unexpected ${name}${binarySuffix} path: ${relativePath(
          extractDir,
          unexpected[0]
        )}`
      );
    }

    resolved[name] = expectedPath;
  }
  return resolved;
}

function resolveReleaseRoot(extractDir, archiveName, expectedRootName) {
  const rootlessManifest = path.join(extractDir, "manifest.toml");
  const rootedDir = path.join(extractDir, expectedRootName);
  const rootedManifest = path.join(rootedDir, "manifest.toml");
  const hasRootless = isFile(rootlessManifest);
  const hasRooted = isFile(rootedManifest);

  if (hasRootless && hasRooted) {
    throw new Error(`archive ${archiveName} contains multiple release roots`);
  }
  if (hasRooted) {
    return rootedDir;
  }
  if (hasRootless) {
    return extractDir;
  }
  throw new Error(
    `archive ${archiveName} missing manifest.toml at expected release root ${expectedRootName}`
  );
}

function findBinaryMatches(root, fileName) {
  const matches = [];
  visit(root, (entryPath, entry) => {
    if (entry.isFile() && entry.name === fileName) {
      matches.push(entryPath);
    }
  });
  return matches;
}

function visit(root, onEntry) {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(root, entry.name);
    onEntry(entryPath, entry);
    if (entry.isDirectory()) {
      visit(entryPath, onEntry);
    }
  }
}

function isFile(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function samePath(left, right) {
  const leftResolved = path.resolve(left);
  const rightResolved = path.resolve(right);
  if (process.platform === "win32") {
    return leftResolved.toLowerCase() === rightResolved.toLowerCase();
  }
  return leftResolved === rightResolved;
}

function relativePath(root, target) {
  return path.relative(root, target).replace(/\\/g, "/");
}

module.exports = {
  expectedReleaseRootName,
  resolveExtractedBinaries
};
