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
  downloadLimitError,
  getDownloadLimits,
  parseContentLength
} = require("../lib/download-limits");
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
const downloadLimits = getDownloadLimits();
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
    await downloadFile(`${releaseBase}/${asset}`, archivePath, downloadLimits.maxArchiveBytes);

    const checksum = await downloadOptionalText(
      `${releaseBase}/${asset}.sha256`,
      downloadLimits.maxChecksumBytes
    );
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

function downloadOptionalText(url, maxBytes) {
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

      const contentLength = parseContentLength(response.headers["content-length"]);
      if (contentLength !== null && contentLength > maxBytes) {
        response.resume();
        reject(downloadLimitError("checksum", url, contentLength, maxBytes, formatDownloadUrlForError));
        return;
      }

      response.setEncoding("utf8");
      let body = "";
      let bytes = 0;
      let settled = false;
      const fail = (error) => {
        if (settled) {
          return;
        }
        settled = true;
        response.destroy();
        reject(error);
      };

      response.on("data", (chunk) => {
        if (settled) {
          return;
        }
        bytes += Buffer.byteLength(chunk, "utf8");
        if (bytes > maxBytes) {
          fail(downloadLimitError("checksum", url, bytes, maxBytes, formatDownloadUrlForError));
          return;
        }
        body += chunk;
      });
      response.on("end", () => {
        if (!settled) {
          settled = true;
          resolve(body);
        }
      });
      response.on("error", fail);
    }).on("error", reject);
  });
}

function downloadFile(url, target, maxBytes) {
  return new Promise((resolve, reject) => {
    let file = null;
    let activeRequest = null;
    let settled = false;

    const fail = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      if (activeRequest) {
        activeRequest.destroy();
      }
      if (file) {
        file.destroy();
      }
      fs.rmSync(target, { force: true });
      reject(error);
    };

    activeRequest = request(url, fail, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        fail(new Error(`download failed ${formatDownloadUrlForError(url)}: HTTP ${response.statusCode}`));
        return;
      }

      const contentLength = parseContentLength(response.headers["content-length"]);
      if (contentLength !== null && contentLength > maxBytes) {
        response.resume();
        fail(downloadLimitError("archive", url, contentLength, maxBytes, formatDownloadUrlForError));
        return;
      }

      file = fs.createWriteStream(target);
      let bytes = 0;

      response.on("data", (chunk) => {
        if (settled) {
          return;
        }
        bytes += chunk.length;
        if (bytes > maxBytes) {
          fail(downloadLimitError("archive", url, bytes, maxBytes, formatDownloadUrlForError));
          return;
        }
        if (!file.write(chunk)) {
          response.pause();
        }
      });
      response.on("end", () => {
        if (settled) {
          return;
        }
        file.end(() => {
          if (!settled) {
            settled = true;
            resolve();
          }
        });
      });
      response.on("error", fail);
      file.on("drain", () => response.resume());
      file.on("error", fail);
    });
    activeRequest.on("error", fail);
  });
}

function request(url, onError, handler, redirects = 0) {
  const parsedUrl = validateDownloadUrl(url);
  const client = parsedUrl.protocol === "https:" ? https : http;
  const requestHandle = client.get(parsedUrl, (response) => {
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
  requestHandle.setTimeout(downloadLimits.timeoutMs, () => {
    requestHandle.destroy(
      new Error(
        `download timed out after ${downloadLimits.timeoutMs} ms: ${formatDownloadUrlForError(url)}`
      )
    );
  });
  return requestHandle;
}
