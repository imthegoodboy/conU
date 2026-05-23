"use strict";

const DEFAULT_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const DEFAULT_MAX_CHECKSUM_BYTES = 16 * 1024;
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;

const ENV_MAX_ARCHIVE_BYTES = "CONU_NPM_MAX_ARCHIVE_BYTES";
const ENV_MAX_CHECKSUM_BYTES = "CONU_NPM_MAX_CHECKSUM_BYTES";
const ENV_DOWNLOAD_TIMEOUT_MS = "CONU_NPM_DOWNLOAD_TIMEOUT_MS";

function getDownloadLimits(env = process.env) {
  return {
    maxArchiveBytes: readPositiveIntegerEnv(
      env,
      ENV_MAX_ARCHIVE_BYTES,
      DEFAULT_MAX_ARCHIVE_BYTES
    ),
    maxChecksumBytes: readPositiveIntegerEnv(
      env,
      ENV_MAX_CHECKSUM_BYTES,
      DEFAULT_MAX_CHECKSUM_BYTES
    ),
    timeoutMs: readPositiveIntegerEnv(
      env,
      ENV_DOWNLOAD_TIMEOUT_MS,
      DEFAULT_DOWNLOAD_TIMEOUT_MS
    )
  };
}

function readPositiveIntegerEnv(env, name, defaultValue) {
  if (env[name] === undefined) {
    return defaultValue;
  }

  const rawValue = String(env[name]).trim();
  if (!/^\d+$/.test(rawValue)) {
    throw new Error(`${name} must be a positive integer`);
  }

  const value = Number(rawValue);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }

  return value;
}

function parseContentLength(value) {
  if (value === undefined) {
    return null;
  }

  const firstValue = Array.isArray(value) ? value[0] : value;
  const text = String(firstValue).trim();
  if (!/^\d+$/.test(text)) {
    return null;
  }

  const bytes = Number(text);
  if (!Number.isSafeInteger(bytes)) {
    return null;
  }

  return bytes;
}

function downloadLimitError(kind, rawUrl, observedBytes, maxBytes, formatUrl) {
  const displayUrl = formatUrl(rawUrl);
  return new Error(
    `${kind} download exceeded maximum size for ${displayUrl}: ${observedBytes} bytes > ${maxBytes} bytes`
  );
}

module.exports = {
  DEFAULT_DOWNLOAD_TIMEOUT_MS,
  DEFAULT_MAX_ARCHIVE_BYTES,
  DEFAULT_MAX_CHECKSUM_BYTES,
  ENV_DOWNLOAD_TIMEOUT_MS,
  ENV_MAX_ARCHIVE_BYTES,
  ENV_MAX_CHECKSUM_BYTES,
  downloadLimitError,
  getDownloadLimits,
  parseContentLength,
  readPositiveIntegerEnv
};
