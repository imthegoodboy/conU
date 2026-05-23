"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { validateArchiveMembers } = require("../lib/archive-preflight");
const {
  formatDownloadUrlForError,
  validateDownloadUrl
} = require("../lib/download-policy");
const {
  BINARIES,
  assetName,
  binaryPath,
  binarySuffix,
  packageVersion,
  vendorDir
} = require("../lib/platform");

const checkOnly = process.argv.includes("--check-only");
const skipDownload = process.env.CONU_NPM_SKIP_DOWNLOAD === "1";
const allowUnverified = process.env.CONU_NPM_ALLOW_UNVERIFIED === "1";
const localBinaryDir = process.env.CONU_NPM_BINARY_DIR;
const version = packageVersion();
const asset = assetName(version);
const releaseBase =
  process.env.CONU_NPM_DIST_BASE ||
  `https://github.com/imthegoodboy/conU/releases/download/v${version}`;

main().catch((error) => {
  console.error(`conU install failed: ${error.message}`);
  process.exit(1);
});

async function main() {
  if (checkOnly) {
    console.log(`conU npm package ${version}`);
    console.log(`platform asset: ${asset}`);
    console.log(`vendor dir: ${vendorDir()}`);
    return;
  }

  if (skipDownload) {
    console.log("CONU_NPM_SKIP_DOWNLOAD=1; skipping native binary download.");
    return;
  }

  fs.mkdirSync(vendorDir(), { recursive: true });

  if (localBinaryDir) {
    installFromLocalDir(localBinaryDir);
    return;
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "conu-npm-"));
  try {
    const archivePath = path.join(tempDir, asset);
    const checksumPath = `${archivePath}.sha256`;
    await downloadFile(`${releaseBase}/${asset}`, archivePath);

    const checksum = await downloadOptionalText(`${releaseBase}/${asset}.sha256`);
    if (checksum) {
      fs.writeFileSync(checksumPath, checksum, "utf8");
      verifySha256(archivePath, checksum);
    } else if (!allowUnverified) {
      throw new Error(
        `missing checksum ${asset}.sha256; set CONU_NPM_ALLOW_UNVERIFIED=1 only for trusted local testing`
      );
    } else {
      console.warn("checksum file unavailable; continuing because CONU_NPM_ALLOW_UNVERIFIED=1");
    }

    const extractDir = path.join(tempDir, "extract");
    fs.mkdirSync(extractDir, { recursive: true });
    extractArchive(archivePath, extractDir);
    installFromExtractedArchive(extractDir);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function installFromLocalDir(sourceDir) {
  for (const name of BINARIES) {
    const source = path.join(sourceDir, `${name}${binarySuffix()}`);
    if (!fs.existsSync(source)) {
      throw new Error(`missing ${source}`);
    }
    installBinary(source, name);
  }
  console.log(`installed conU binaries from ${sourceDir}`);
}

function installFromExtractedArchive(root) {
  for (const name of BINARIES) {
    const found = findFile(root, `${name}${binarySuffix()}`);
    if (!found) {
      throw new Error(`archive ${asset} did not contain ${name}${binarySuffix()}`);
    }
    installBinary(found, name);
  }
  console.log(`installed conU native binaries for ${asset}`);
}

function installBinary(source, name) {
  const target = binaryPath(name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
  if (process.platform !== "win32") {
    fs.chmodSync(target, 0o755);
  }
}

function extractArchive(archivePath, destination) {
  validateArchiveMembers(archivePath);

  const tar = spawnSync("tar", ["-xf", archivePath, "-C", destination], { stdio: "inherit" });
  if (tar.status === 0) {
    return;
  }

  if (process.platform === "win32" && archivePath.endsWith(".zip")) {
    const ps = spawnSync(
      "powershell",
      [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force",
        archivePath,
        destination
      ],
      { stdio: "inherit" }
    );
    if (ps.status === 0) {
      return;
    }
  }

  throw new Error(`failed to extract ${archivePath}`);
}

function findFile(root, fileName) {
  const entries = fs.readdirSync(root, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      const found = findFile(fullPath, fileName);
      if (found) {
        return found;
      }
    } else if (entry.isFile() && entry.name === fileName) {
      return fullPath;
    }
  }
  return null;
}

function verifySha256(filePath, checksumText) {
  const expected = checksumText.match(/\b[a-fA-F0-9]{64}\b/);
  if (!expected) {
    throw new Error("checksum file did not contain a SHA-256 hash");
  }
  const actual = crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  if (actual.toLowerCase() !== expected[0].toLowerCase()) {
    throw new Error(`checksum mismatch for ${path.basename(filePath)}`);
  }
}

function downloadOptionalText(url) {
  return new Promise((resolve, reject) => {
    request(url, reject, (response) => {
      if (response.statusCode === 404) {
        response.resume();
        resolve(null);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(
          new Error(`download failed ${formatDownloadUrlForError(url)}: HTTP ${response.statusCode}`)
        );
        return;
      }
      response.setEncoding("utf8");
      let body = "";
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => resolve(body));
    }).on("error", reject);
  });
}

function downloadFile(url, target) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(target);
    request(url, reject, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        file.close(() => {
          fs.rmSync(target, { force: true });
          reject(
            new Error(`download failed ${formatDownloadUrlForError(url)}: HTTP ${response.statusCode}`)
          );
        });
        return;
      }
      response.pipe(file);
      file.on("finish", () => file.close(resolve));
    }).on("error", (error) => {
      file.close(() => {
        fs.rmSync(target, { force: true });
        reject(error);
      });
    });
  });
}

function request(url, onError, handler, redirects = 0) {
  const parsedUrl = validateDownloadUrl(url);
  const client = parsedUrl.protocol === "https:" ? https : http;
  return client.get(parsedUrl, (response) => {
    if (
      response.statusCode >= 300 &&
      response.statusCode < 400 &&
      response.headers.location &&
      redirects < 5
    ) {
      response.resume();
      request(new URL(response.headers.location, url).toString(), onError, handler, redirects + 1).on(
        "error",
        onError
      );
      return;
    }
    handler(response);
  });
}
