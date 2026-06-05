"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_MAX_EXTRACTED_ENTRIES = 10000;
const DEFAULT_MAX_EXTRACTED_DEPTH = 64;

function expectedReleaseRootName(assetName) {
  if (assetName.endsWith(".tar.gz")) {
    return assetName.slice(0, -".tar.gz".length);
  }
  return path.basename(assetName, path.extname(assetName));
}

function resolveExtractedBinaries(
  extractDir,
  {
    archiveName,
    binaryNames,
    binarySuffix,
    expectedRootName = expectedReleaseRootName(archiveName),
    maxExtractedEntries = DEFAULT_MAX_EXTRACTED_ENTRIES,
    maxExtractedDepth = DEFAULT_MAX_EXTRACTED_DEPTH
  }
) {
  const maxEntries = parsePositiveInteger(maxExtractedEntries, "maxExtractedEntries", archiveName);
  const maxDepth = parsePositiveInteger(maxExtractedDepth, "maxExtractedDepth", archiveName);
  const root = resolveReleaseRoot(extractDir, archiveName, expectedRootName);
  const binaryFileNames = new Set(binaryNames.map((name) => `${name}${binarySuffix}`));
  const matches = collectBinaryMatches(extractDir, binaryFileNames, archiveName, {
    maxEntries,
    maxDepth
  });
  const resolved = {};
  for (const name of binaryNames) {
    const fileName = `${name}${binarySuffix}`;
    const expectedPath = path.join(root, "bin", fileName);
    if (!isFile(expectedPath, archiveName)) {
      throw new Error(`archive ${archiveName} missing expected binary: bin/${fileName}`);
    }

    const unexpected = matches.get(fileName).filter((candidate) => !samePath(candidate, expectedPath));
    if (unexpected.length > 0) {
      throw new Error(
        `archive ${archiveName} contains unexpected ${fileName} path; pathDisplayed=false contentsDisplayed=false`
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
  const hasRootless = isFile(rootlessManifest, archiveName);
  const hasRooted = isFile(rootedManifest, archiveName);

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

function collectBinaryMatches(root, fileNames, archiveName, limits) {
  const matches = new Map(Array.from(fileNames, (fileName) => [fileName, []]));
  visit(root, archiveName, limits, (entryPath, entry) => {
    const fileMatches = matches.get(entry.name);
    if (entry.isFile() && fileMatches) {
      fileMatches.push(entryPath);
    }
  });
  return matches;
}

function visit(root, archiveName, limits, onEntry, depth = 0, state = { entries: 0 }) {
  const dir = openExtractedTreeDirectory(root, archiveName);
  let visitFailed = false;
  try {
    let entry = readExtractedTreeDirectory(dir, archiveName);
    while (entry !== null) {
      state.entries += 1;
      if (state.entries > limits.maxEntries) {
        throw new Error(
          `archive ${archiveName} extracted tree exceeds maximum entry count ${limits.maxEntries}`
        );
      }

      const entryDepth = depth + 1;
      if (entryDepth > limits.maxDepth) {
        throw new Error(
          `archive ${archiveName} extracted tree exceeds maximum depth ${limits.maxDepth}`
        );
      }

      const entryPath = path.join(root, entry.name);
      onEntry(entryPath, entry);
      if (entry.isDirectory()) {
        visit(entryPath, archiveName, limits, onEntry, entryDepth, state);
      }
      entry = readExtractedTreeDirectory(dir, archiveName);
    }
  } catch (error) {
    visitFailed = true;
    throw error;
  } finally {
    try {
      dir.closeSync();
    } catch (_error) {
      if (!visitFailed) {
        throw extractedTreeInspectionError(archiveName);
      }
    }
  }
}

function parsePositiveInteger(value, label, archiveName) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`archive ${archiveName} has invalid ${label}`);
  }
  return value;
}

function isFile(filePath, archiveName) {
  try {
    return fs.statSync(filePath).isFile();
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return false;
    }
    throw extractedTreeInspectionError(archiveName);
  }
}

function openExtractedTreeDirectory(root, archiveName) {
  try {
    return fs.opendirSync(root);
  } catch (_error) {
    throw extractedTreeInspectionError(archiveName);
  }
}

function readExtractedTreeDirectory(dir, archiveName) {
  try {
    return dir.readSync();
  } catch (_error) {
    throw extractedTreeInspectionError(archiveName);
  }
}

function extractedTreeInspectionError(archiveName) {
  return new Error(
    `failed to inspect extracted tree for archive ${archiveName}; pathDisplayed=false contentsDisplayed=false`
  );
}

function samePath(left, right) {
  const leftResolved = path.resolve(left);
  const rightResolved = path.resolve(right);
  if (process.platform === "win32") {
    return leftResolved.toLowerCase() === rightResolved.toLowerCase();
  }
  return leftResolved === rightResolved;
}

module.exports = {
  DEFAULT_MAX_EXTRACTED_DEPTH,
  DEFAULT_MAX_EXTRACTED_ENTRIES,
  expectedReleaseRootName,
  resolveExtractedBinaries
};
