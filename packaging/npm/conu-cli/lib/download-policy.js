"use strict";

const net = require("node:net");

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function validateDownloadUrl(rawUrl) {
  const parsed = parseDownloadUrl(rawUrl);
  if (parsed.username || parsed.password) {
    throw new Error("download URL must not include embedded credentials");
  }

  const hostClass = classifyDownloadHost(parsed.hostname);
  if (parsed.protocol === "https:") {
    return parsed;
  }

  if (parsed.protocol === "http:" && hostClass === "loopback") {
    return parsed;
  }

  if (parsed.protocol === "http:") {
    throw new Error("download URL must use HTTPS unless it points at a loopback test server");
  }

  throw new Error(`unsupported download URL protocol: ${parsed.protocol}`);
}

function validateUnverifiedDownloadBase(rawUrl) {
  const parsed = validateDownloadUrl(rawUrl);
  if (!isLoopbackHost(parsed.hostname)) {
    throw new Error(
      `CONU_NPM_ALLOW_UNVERIFIED=1 is only allowed for loopback testing downloads: ${formatDownloadUrlForError(rawUrl)}`
    );
  }
  return parsed;
}

function validateDownloadRedirect(fromRawUrl, toRawUrl) {
  const from = validateDownloadUrl(fromRawUrl);
  const to = validateDownloadUrl(toRawUrl);
  const fromLoopback = isLoopbackHost(from.hostname);
  const toLoopback = isLoopbackHost(to.hostname);
  if (fromLoopback !== toLoopback) {
    throw new Error(
      `download redirect must not cross public and loopback boundaries: ${formatDownloadUrlForError(fromRawUrl)} -> ${formatDownloadUrlForError(toRawUrl)}`
    );
  }
  return to;
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
  const host = normalizeHostname(hostname);
  if (LOOPBACK_HOSTS.has(host) || host.endsWith(".localhost")) {
    return true;
  }
  const ipVersion = net.isIP(host);
  if (ipVersion === 4) {
    return ipv4Octets(host)[0] === 127;
  }
  if (ipVersion === 6) {
    const parsed = parseIpv6(host);
    return parsed !== null && parsed === 1n;
  }
  return false;
}

function classifyDownloadHost(hostname) {
  const host = normalizeHostname(hostname);
  if (!host || host === "local" || host.endsWith(".local")) {
    throw new Error("download URL host must be public or loopback");
  }
  if (isLoopbackHost(host)) {
    return "loopback";
  }

  const ipVersion = net.isIP(host);
  if (ipVersion === 4 && isPublicIpv4(host)) {
    return "public";
  }
  if (ipVersion === 6 && isPublicIpv6(host)) {
    return "public";
  }
  if (ipVersion !== 0) {
    throw new Error("download URL host must be public or loopback");
  }

  return "public";
}

function normalizeHostname(hostname) {
  return String(hostname || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/g, "");
}

function isPublicIpv4(host) {
  const octets = ipv4Octets(host);
  const [first, second, third] = octets;
  return !(
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first === 169 && second === 254 ||
    first === 172 && second >= 16 && second <= 31 ||
    first === 192 && second === 168 ||
    first >= 224 ||
    first === 255 ||
    first === 100 && second >= 64 && second <= 127 ||
    first === 192 && second === 0 && third === 0 ||
    first === 192 && second === 0 && third === 2 ||
    first === 192 && second === 88 && third === 99 ||
    first === 198 && (second === 18 || second === 19) ||
    first === 198 && second === 51 && third === 100 ||
    first === 203 && second === 0 && third === 113
  );
}

function ipv4Octets(host) {
  return host.split(".").map((part) => Number.parseInt(part, 10));
}

function isPublicIpv6(host) {
  const value = parseIpv6(host);
  if (value === null) {
    throw new Error("download URL host must be public or loopback");
  }

  if (
    value === 0n ||
    value === 1n ||
    hasIpv6Prefix(value, "ff00::", 8) ||
    hasIpv6Prefix(value, "fc00::", 7) ||
    hasIpv6Prefix(value, "fe80::", 10) ||
    hasIpv6Prefix(value, "fec0::", 10) ||
    hasIpv6Prefix(value, "2001:db8::", 32) ||
    hasIpv6Prefix(value, "3fff::", 20) ||
    hasIpv6Prefix(value, "100::", 64) ||
    hasIpv6Prefix(value, "100:0:0:1::", 64) ||
    hasIpv6Prefix(value, "2001::", 23) ||
    hasIpv6Prefix(value, "64:ff9b:1::", 48) ||
    hasIpv6Prefix(value, "5f00::", 16) ||
    hasIpv6Prefix(value, "2002::", 16)
  ) {
    return false;
  }

  const mapped = ipv4MappedAddress(value);
  if (mapped !== null) {
    return isPublicIpv4(mapped);
  }
  const compatible = ipv4CompatibleAddress(value);
  if (compatible !== null) {
    return isPublicIpv4(compatible);
  }
  const wellKnownNat64 = wellKnownNat64Address(value);
  if (wellKnownNat64 !== null) {
    return isPublicIpv4(wellKnownNat64);
  }
  return true;
}

function hasIpv6Prefix(value, prefix, bits) {
  const prefixValue = parseIpv6(prefix);
  if (prefixValue === null) {
    throw new Error(`invalid IPv6 policy prefix: ${prefix}`);
  }
  const shift = BigInt(128 - bits);
  return value >> shift === prefixValue >> shift;
}

function ipv4MappedAddress(value) {
  if (value >> 32n !== 0xffffn) {
    return null;
  }
  return ipv4FromNumber(Number(value & 0xffffffffn));
}

function ipv4CompatibleAddress(value) {
  if (value >> 32n !== 0n || value === 0n || value === 1n) {
    return null;
  }
  return ipv4FromNumber(Number(value & 0xffffffffn));
}

function wellKnownNat64Address(value) {
  const prefix = parseIpv6("64:ff9b::");
  if (prefix === null || value >> 32n !== prefix >> 32n) {
    return null;
  }
  return ipv4FromNumber(Number(value & 0xffffffffn));
}

function ipv4FromNumber(value) {
  return [
    Math.floor(value / 256 ** 3) % 256,
    Math.floor(value / 256 ** 2) % 256,
    Math.floor(value / 256) % 256,
    value % 256
  ].join(".");
}

function parseIpv6(host) {
  let normalized = host.toLowerCase();
  if (normalized.includes("%")) {
    return null;
  }

  if (normalized.includes(".")) {
    const lastColon = normalized.lastIndexOf(":");
    if (lastColon === -1) {
      return null;
    }
    const ipv4 = normalized.slice(lastColon + 1);
    if (net.isIP(ipv4) !== 4) {
      return null;
    }
    const [a, b, c, d] = ipv4Octets(ipv4);
    normalized = `${normalized.slice(0, lastColon)}:${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  const halves = normalized.split("::");
  if (halves.length > 2) {
    return null;
  }

  const left = splitIpv6Half(halves[0]);
  const right = halves.length === 2 ? splitIpv6Half(halves[1]) : [];
  if (left === null || right === null) {
    return null;
  }

  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) {
    return null;
  }

  const parts = [...left, ...Array(missing).fill("0"), ...right];
  let value = 0n;
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) {
      return null;
    }
    value = (value << 16n) + BigInt(Number.parseInt(part, 16));
  }
  return value;
}

function splitIpv6Half(value) {
  if (value === "") {
    return [];
  }
  const parts = value.split(":");
  if (parts.some((part) => part.length === 0)) {
    return null;
  }
  return parts;
}

module.exports = {
  formatDownloadUrlForError,
  isLoopbackHost,
  validateDownloadRedirect,
  validateDownloadUrl,
  validateUnverifiedDownloadBase
};
