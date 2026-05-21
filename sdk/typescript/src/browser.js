export const browserSupport = Object.freeze({
  supported: false,
  packageKind: "node-wrapper",
  reason:
    "@conu/sdk currently wraps local conu/conud/conu-mcp binaries and is not browser-native.",
  safeNextStep:
    "Use @conu/sdk from Node.js, or wait for a future browser-native protocol package.",
  contentsDisplayed: false,
});

export class BrowserUnsupportedError extends Error {
  constructor(message = browserSupport.reason) {
    super(message);
    this.name = "BrowserUnsupportedError";
    this.browserSupport = browserSupport;
  }
}

export class ConuClient {
  constructor() {
    throw new BrowserUnsupportedError();
  }
}

