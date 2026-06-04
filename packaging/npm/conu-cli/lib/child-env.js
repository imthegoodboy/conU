"use strict";

const WRAPPER_ONLY_ENV = new Set(["CONU_BIN_NAME"]);
const PACKAGE_MANAGER_SECRET_ENV = new Set(["NODE_AUTH_TOKEN", "NPM_TOKEN"]);
const INSTALLER_ONLY_ENV_PREFIXES = ["CONU_NPM_"];

function buildChildEnv(sourceEnv = process.env) {
  const childEnv = {};
  for (const [name, value] of Object.entries(sourceEnv)) {
    if (!shouldScrubChildEnvName(name)) {
      childEnv[name] = value;
    }
  }
  return childEnv;
}

function shouldScrubChildEnvName(name) {
  const normalized = String(name).toUpperCase();
  if (WRAPPER_ONLY_ENV.has(normalized) || PACKAGE_MANAGER_SECRET_ENV.has(normalized)) {
    return true;
  }
  for (const prefix of INSTALLER_ONLY_ENV_PREFIXES) {
    if (normalized.startsWith(prefix)) {
      return true;
    }
  }
  return normalized.startsWith("NPM_");
}

module.exports = {
  buildChildEnv,
  INSTALLER_ONLY_ENV_PREFIXES,
  PACKAGE_MANAGER_SECRET_ENV,
  WRAPPER_ONLY_ENV,
  shouldScrubChildEnvName
};
