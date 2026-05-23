"use strict";

const { formatDownloadUrlForError, validateDownloadUrl } = require("../lib/download-policy");

function main() {
  expectPass("https://github.com/imthegoodboy/conU/releases/download/v0.1.0/conu.zip");
  expectPass("http://127.0.0.1:50123/conu.zip");
  expectPass("http://localhost:50123/conu.zip");
  expectPass("http://[::1]:50123/conu.zip");
  expectFail("http://example.com/conu.zip", "download URL must use HTTPS");
  expectFail("ftp://example.com/conu.zip", "unsupported download URL protocol");
  expectFail("https://user:pass@example.com/conu.zip", "embedded credentials");
  expectFail("http://localhost.evil.test/conu.zip", "download URL must use HTTPS");
  expectFail("not a url", "invalid download URL");
  expectDisplayUrl("https://example.com/conu.zip?token=secret#fragment", "https://example.com/conu.zip");
  console.log("download URL policy check passed");
}

function expectPass(url) {
  validateDownloadUrl(url);
}

function expectFail(url, expectedMessage) {
  try {
    validateDownloadUrl(url);
  } catch (error) {
    if (error.message.includes(expectedMessage)) {
      return;
    }
    throw new Error(`expected ${expectedMessage}, got: ${error.message}`);
  }
  throw new Error(`expected download URL policy failure: ${expectedMessage}`);
}

function expectDisplayUrl(url, expected) {
  const actual = formatDownloadUrlForError(url);
  if (actual !== expected) {
    throw new Error(`expected sanitized display URL ${expected}, got ${actual}`);
  }
}

main();
