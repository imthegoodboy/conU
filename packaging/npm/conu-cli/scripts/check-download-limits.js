"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");

const {
  DEFAULT_DOWNLOAD_TIMEOUT_MS,
  DEFAULT_MAX_ARCHIVE_BYTES,
  DEFAULT_MAX_CHECKSUM_BYTES,
  getDownloadLimits,
  parseContentLength,
  readPositiveIntegerEnv
} = require("../lib/download-limits");
const { assetName } = require("../lib/platform");

const packageRoot = path.resolve(__dirname, "..");
const installScript = path.join(__dirname, "install.js");

async function main() {
  expectExclusiveDownloadArtifactCreation();
  expectDefaultLimits();
  expectOverrideLimits();
  expectInvalidLimit("CONU_NPM_MAX_ARCHIVE_BYTES", "0");
  expectInvalidLimit("CONU_NPM_MAX_CHECKSUM_BYTES", "-1");
  expectInvalidLimit("CONU_NPM_DOWNLOAD_TIMEOUT_MS", "1.5");
  expectContentLengthParsing();
  await expectUnverifiedPublicBaseFailure();
  await expectLoopbackRedirectToPublicFailure();
  await expectArchiveLimitFailure();
  await expectChecksumLimitFailure();
  await expectChecksumArchiveNameFailure();
  await expectInvalidArchiveUsesNeutralTempLabel();
  await expectTimeoutFailure();
  console.log("download limit check passed");
}

function expectExclusiveDownloadArtifactCreation() {
  const source = fs.readFileSync(installScript, "utf8");
  expectIncludes(
    source,
    'fs.writeFileSync(checksumPath, checksum, { encoding: "utf8", flag: "wx" })',
    "exclusive checksum artifact creation"
  );
  expectIncludes(
    source,
    'fs.createWriteStream(target, { flags: "wx" })',
    "exclusive archive artifact creation"
  );
  expectIncludes(
    source,
    'throw downloadArtifactWriteError("checksum");',
    "redacted checksum artifact write failure"
  );
  expectIncludes(
    source,
    'file.on("error", () => fail(downloadArtifactWriteError("archive")));',
    "redacted archive artifact write failure"
  );
  expectIncludes(
    source,
    "function removeDownloadArtifact(target)",
    "redacted archive cleanup failure guard"
  );
  expectIncludes(
    source,
    "const tempDir = createTempInstallDir();",
    "redacted temp install dir creation"
  );
  expectIncludes(
    source,
    "removeTempInstallDir(tempDir, { preserveFailure: installFailed });",
    "redacted temp install dir cleanup"
  );
  expectIncludes(
    source,
    'throw tempInstallDirError("create");',
    "redacted temp install dir creation failure"
  );
  expectIncludes(
    source,
    'throw tempInstallDirError("remove");',
    "redacted temp install dir cleanup failure"
  );
  expectIncludes(
    source,
    "createExtractDir(extractDir);",
    "redacted temp extraction dir creation"
  );
  expectIncludes(
    source,
    "function createExtractDir(extractDir)",
    "redacted temp extraction dir helper"
  );
  expectIncludes(
    source,
    "failed to create temporary extraction directory; pathDisplayed=false contentsDisplayed=false",
    "redacted temp extraction dir failure"
  );
}

function expectDefaultLimits() {
  const limits = getDownloadLimits({});
  expectEqual(limits.maxArchiveBytes, DEFAULT_MAX_ARCHIVE_BYTES, "default archive byte limit");
  expectEqual(limits.maxChecksumBytes, DEFAULT_MAX_CHECKSUM_BYTES, "default checksum byte limit");
  expectEqual(limits.timeoutMs, DEFAULT_DOWNLOAD_TIMEOUT_MS, "default timeout");
}

function expectOverrideLimits() {
  const limits = getDownloadLimits({
    CONU_NPM_MAX_ARCHIVE_BYTES: "123",
    CONU_NPM_MAX_CHECKSUM_BYTES: "456",
    CONU_NPM_DOWNLOAD_TIMEOUT_MS: "789"
  });
  expectEqual(limits.maxArchiveBytes, 123, "archive byte override");
  expectEqual(limits.maxChecksumBytes, 456, "checksum byte override");
  expectEqual(limits.timeoutMs, 789, "timeout override");
}

function expectInvalidLimit(name, value) {
  try {
    readPositiveIntegerEnv({ [name]: value }, name, 1);
  } catch (error) {
    if (error.message.includes(name)) {
      return;
    }
    throw new Error(`expected ${name} parse failure, got: ${error.message}`);
  }
  throw new Error(`expected ${name} parse failure`);
}

function expectContentLengthParsing() {
  expectEqual(parseContentLength(undefined), null, "missing content length");
  expectEqual(parseContentLength("15"), 15, "string content length");
  expectEqual(parseContentLength(["16"]), 16, "array content length");
  expectEqual(parseContentLength("not-a-number"), null, "invalid content length");
}

async function expectArchiveLimitFailure() {
  await withServer((_request, response) => {
    response.writeHead(200, { "Content-Length": "9" });
    response.end("123456789");
  }, async (baseUrl) => {
    const result = await runInstall({
      CONU_NPM_ALLOW_UNVERIFIED: "1",
      CONU_NPM_DIST_BASE: `${baseUrl}/secret-download-path?token=secret`,
      CONU_NPM_MAX_ARCHIVE_BYTES: "8"
    });
    expectFailedWith(result, "archive download exceeded maximum size");
    expectNoSecretDisplay(result);
  });
}

async function expectUnverifiedPublicBaseFailure() {
  const result = await runInstall({
    CONU_NPM_ALLOW_UNVERIFIED: "1",
    CONU_NPM_DIST_BASE: "https://example.com/secret-download-path?token=secret"
  });
  expectFailedWith(result, "only allowed for loopback testing downloads");
  expectNoSecretDisplay(result);
}

async function expectLoopbackRedirectToPublicFailure() {
  await withServer((_request, response) => {
    response.writeHead(302, { Location: "https://example.com/conu.zip?token=secret" });
    response.end();
  }, async (baseUrl) => {
    const result = await runInstall({
      CONU_NPM_ALLOW_UNVERIFIED: "1",
      CONU_NPM_DIST_BASE: `${baseUrl}/secret-download-path?token=secret`,
      CONU_NPM_MAX_ARCHIVE_BYTES: "1024"
    });
    expectFailedWith(result, "download redirect must not cross public and loopback boundaries");
    expectNoSecretDisplay(result);
  });
}

async function expectChecksumLimitFailure() {
  await withServer((request, response) => {
    if (request.url.includes(".sha256")) {
      response.writeHead(200, { "Content-Length": "9" });
      response.end("123456789");
      return;
    }
    response.writeHead(200, { "Content-Length": "4" });
    response.end("tiny");
  }, async (baseUrl) => {
    const result = await runInstall({
      CONU_NPM_DIST_BASE: `${baseUrl}/secret-download-path?token=secret`,
      CONU_NPM_MAX_ARCHIVE_BYTES: "1024",
      CONU_NPM_MAX_CHECKSUM_BYTES: "8"
    });
    expectFailedWith(result, "checksum download exceeded maximum size");
    expectNoSecretDisplay(result);
  });
}

async function expectChecksumArchiveNameFailure() {
  const body = Buffer.from("tiny");
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  await withServer((request, response) => {
    if (request.url.includes(".sha256")) {
      response.writeHead(200, { "Content-Length": String(digest.length + 12) });
      response.end(`${digest}  other.zip\n`);
      return;
    }
    response.writeHead(200, { "Content-Length": String(body.length) });
    response.end(body);
  }, async (baseUrl) => {
    const result = await runInstall({
      CONU_NPM_DIST_BASE: `${baseUrl}/secret-download-path?token=secret`,
      CONU_NPM_MAX_ARCHIVE_BYTES: "1024"
    });
    expectFailedWith(result, "names wrong archive");
    expectNoSecretDisplay(result);
  });
}

async function expectInvalidArchiveUsesNeutralTempLabel() {
  const body = Buffer.from("not a release archive");
  await withServer((request, response) => {
    if (request.url.includes(".sha256")) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { "Content-Length": String(body.length) });
    response.end(body);
  }, async (baseUrl) => {
    const result = await runInstall({
      CONU_NPM_ALLOW_UNVERIFIED: "1",
      CONU_NPM_DIST_BASE: baseUrl,
      CONU_NPM_MAX_ARCHIVE_BYTES: "1024"
    });
    expectFailedWith(result, "conu-native-archive");
    expectFailedWithout(result, assetName());
    expectNoSecretDisplay(result);
  });
}

async function expectTimeoutFailure() {
  await withServer((_request, _response) => {}, async (baseUrl) => {
    const result = await runInstall({
      CONU_NPM_ALLOW_UNVERIFIED: "1",
      CONU_NPM_DIST_BASE: `${baseUrl}/secret-download-path?token=secret`,
      CONU_NPM_DOWNLOAD_TIMEOUT_MS: "100",
      CONU_NPM_MAX_ARCHIVE_BYTES: "1024"
    });
    expectFailedWith(result, "download timed out after 100 ms");
    expectNoSecretDisplay(result);
  });
}

function runInstall(extraEnv) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [installScript], {
      cwd: packageRoot,
      env: {
        ...process.env,
        CONU_NPM_MAX_CHECKSUM_BYTES: "16384",
        CONU_NPM_DOWNLOAD_TIMEOUT_MS: "5000",
        ...extraEnv
      },
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("installer child process timed out during download limit check"));
    }, 10000);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (status, signal) => {
      clearTimeout(timer);
      resolve({ signal, status, stderr, stdout });
    });
  });
}

function expectFailedWith(result, expectedMessage) {
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  if (result.status === 0) {
    throw new Error(`expected installer to fail with ${expectedMessage}, but it passed`);
  }
  if (!output.includes(expectedMessage)) {
    throw new Error(`expected installer output to include ${expectedMessage}, got: ${output}`);
  }
}

function expectFailedWithout(result, unexpectedMessage) {
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  if (result.status === 0) {
    throw new Error(`expected installer to fail without ${unexpectedMessage}, but it passed`);
  }
  if (output.includes(unexpectedMessage)) {
    throw new Error(`installer output included ${unexpectedMessage}: ${output}`);
  }
}

function expectNoSecretDisplay(result) {
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  if (output.includes("token=secret")) {
    throw new Error(`installer output displayed URL query material: ${output}`);
  }
  if (output.includes("secret-download-path")) {
    throw new Error(`installer output displayed URL path material: ${output}`);
  }
}

function expectIncludes(output, value, label) {
  if (!output.includes(value)) {
    throw new Error(`expected ${label} to include ${value}`);
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`expected ${label} to be ${expected}, got ${actual}`);
  }
}

function withServer(handler, fn) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.on("error", reject);
    server.listen(0, "127.0.0.1", async () => {
      const address = server.address();
      try {
        await fn(`http://127.0.0.1:${address.port}`);
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      } catch (error) {
        server.close(() => reject(error));
      }
    });
  });
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
