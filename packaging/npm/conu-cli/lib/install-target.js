"use strict";

const fs = require("node:fs");
const path = require("node:path");

const { binaryPath, packageRoot, vendorDir } = require("./platform");

function installBinary(source, name) {
  installFile(source, binaryPath(name), `conU binary ${name}`, {
    trustedRoot: packageRoot(),
    vendorRoot: vendorDir()
  });
}

function installFile(source, target, label, options = {}) {
  const sourcePath = path.resolve(source);
  const targetPath = path.resolve(target);
  const installDir = path.dirname(targetPath);
  const trustedRoot = path.resolve(options.trustedRoot || installDir);

  assertPathUnderRoot(targetPath, trustedRoot, label);
  assertRegularSource(sourcePath, label);
  assertExistingInstallAncestors(trustedRoot, installDir, label);
  createInstallDirectory(installDir, label);
  assertInstallDirectoryTree(trustedRoot, installDir, label);
  if (options.vendorRoot) {
    assertInstallDirectoryTree(trustedRoot, path.resolve(options.vendorRoot), label);
  }
  assertSafeInstallTarget(targetPath, label);

  const tempTarget = temporarySiblingPath(targetPath);
  let tempCreated = false;
  let renamed = false;
  try {
    copyTemporaryInstallTarget(sourcePath, tempTarget, label);
    tempCreated = true;
    if (process.platform !== "win32") {
      setTemporaryInstallTargetPermissions(tempTarget, label);
    }
    assertRegularTempTarget(tempTarget, label);
    replaceInstallTarget(tempTarget, targetPath, label);
    renamed = true;
    assertSafeInstallTarget(targetPath, label);
  } finally {
    if (tempCreated && !renamed) {
      removeTemporaryInstallTarget(tempTarget);
    }
  }
}

function assertRegularSource(source, label) {
  const stat = lstatRequired(source, `${label} source`);
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} source must not be a symlink: ${path.basename(source)}`);
  }
  if (!stat.isFile()) {
    throw new Error(`${label} source must be a regular file: ${path.basename(source)}`);
  }
}

function assertSafeInstallTarget(target, label) {
  const stat = lstatMaybe(target, `${label} install target`);
  if (!stat) {
    return;
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} install target must not be a symlink: ${path.basename(target)}`);
  }
  if (!stat.isFile()) {
    throw new Error(`${label} install target must be a regular file: ${path.basename(target)}`);
  }
}

function assertRegularTempTarget(target, label) {
  const stat = lstatRequired(target, `${label} temporary install target`);
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} temporary install target must not be a symlink`);
  }
  if (!stat.isFile()) {
    throw new Error(`${label} temporary install target must be a regular file`);
  }
}

function assertExistingInstallAncestors(root, targetDir, label) {
  for (const current of pathComponents(root, targetDir, { includeMissing: false })) {
    const stat = lstatMaybe(current, `${label} install directory`);
    if (!stat) {
      return;
    }
    assertSafeDirectoryComponent(current, stat, label);
  }
}

function assertInstallDirectoryTree(root, targetDir, label) {
  for (const current of pathComponents(root, targetDir, { includeMissing: true })) {
    const stat = lstatRequired(current, `${label} install directory`);
    assertSafeDirectoryComponent(current, stat, label);
  }
}

function assertSafeDirectoryComponent(current, stat, label) {
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} install directory must not be a symlink: ${path.basename(current)}`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`${label} install directory must be a directory: ${path.basename(current)}`);
  }
}

function pathComponents(root, targetDir, { includeMissing }) {
  const rootPath = path.resolve(root);
  const targetPath = path.resolve(targetDir);
  assertPathUnderRoot(targetPath, rootPath, "install target");

  const relative = path.relative(rootPath, targetPath);
  if (!relative) {
    return [rootPath];
  }

  const components = [rootPath];
  let current = rootPath;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    if (!includeMissing && !lstatMaybe(current, "install target directory")) {
      break;
    }
    components.push(current);
  }
  return components;
}

function assertPathUnderRoot(target, root, label) {
  const relative = path.relative(root, target);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`${label} install target must stay inside the package directory`);
  }
}

function createInstallDirectory(installDir, label) {
  try {
    fs.mkdirSync(installDir, { recursive: true });
  } catch (_error) {
    throw installTargetIoError(label, "create install directory");
  }
}

function copyTemporaryInstallTarget(source, target, label) {
  try {
    fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
  } catch (_error) {
    throw installTargetIoError(label, "copy temporary install target");
  }
}

function setTemporaryInstallTargetPermissions(target, label) {
  try {
    fs.chmodSync(target, 0o755);
  } catch (_error) {
    throw installTargetIoError(label, "set temporary install target permissions");
  }
}

function replaceInstallTarget(source, target, label) {
  try {
    fs.renameSync(source, target);
  } catch (_error) {
    throw installTargetIoError(label, "replace install target");
  }
}

function removeTemporaryInstallTarget(target) {
  try {
    fs.rmSync(target, { force: true });
  } catch (_error) {
    // Preserve the original redacted install failure.
  }
}

function installTargetIoError(label, action) {
  return new Error(
    `failed to ${action} for ${label}; pathDisplayed=false contentsDisplayed=false`
  );
}

function temporarySiblingPath(target) {
  const dir = path.dirname(target);
  const base = path.basename(target);
  for (let index = 0; index < 100; index += 1) {
    const candidate = path.join(
      dir,
      `.${base}.${process.pid}.${Date.now()}.${index}.tmp`
    );
    if (!lstatMaybe(candidate, `${base} temporary install target`)) {
      return candidate;
    }
  }
  throw new Error(`${base} temporary install target could not be allocated`);
}

function lstatRequired(target, label) {
  const stat = lstatMaybe(target, label);
  if (!stat) {
    throw new Error(`missing ${label}: ${path.basename(target)}`);
  }
  return stat;
}

function lstatMaybe(target, label) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw installTargetInspectionError(label);
  }
}

function installTargetInspectionError(label) {
  return new Error(
    `failed to inspect ${label}; pathDisplayed=false contentsDisplayed=false`
  );
}

module.exports = {
  installBinary,
  installFile
};
