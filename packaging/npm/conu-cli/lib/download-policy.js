"use strict";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function validateDownloadUrl(rawUrl) {
  const parsed = parseDownloadUrl(rawUrl);
  if (parsed.username || parsed.password) {
    throw new Error("download URL must not include embedded credentials");
  }

  if (parsed.protocol === "https:") {
    return parsed;
  }

  if (parsed.protocol === "http:" && isLoopbackHost(parsed.hostname)) {
    return parsed;
  }

  if (parsed.protocol === "http:") {
    throw new Error("download URL must use HTTPS unless it points at a loopback test server");
  }

  throw new Error(`unsupported download URL protocol: ${parsed.protocol}`);
}

function formatDownloadUrlForError(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch (_error) {
    return "<invalid download URL>";
  }
}

function parseDownloadUrl(rawUrl) {
  try {
    return new URL(rawUrl);
  } catch (error) {
    throw new Error(`invalid download URL: ${error.message}`);
  }
}

function isLoopbackHost(hostname) {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase().replace(/^\[|\]$/g, ""));
}

module.exports = {
  formatDownloadUrlForError,
  isLoopbackHost,
  validateDownloadUrl
};
