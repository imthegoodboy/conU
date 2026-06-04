"use strict";

const WRAPPER_ONLY_ENV = new Set(["CONU_BIN_NAME"]);

function buildChildEnv(sourceEnv = process.env) {
  const childEnv = { ...sourceEnv };
  for (const name of WRAPPER_ONLY_ENV) {
    delete childEnv[name];
  }
  return childEnv;
}

module.exports = {
  buildChildEnv,
  WRAPPER_ONLY_ENV
};
