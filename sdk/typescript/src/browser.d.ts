export interface BrowserSupportInfo {
  supported: false;
  packageKind: "node-wrapper";
  reason: string;
  safeNextStep: string;
  contentsDisplayed: false;
}

export declare const browserSupport: BrowserSupportInfo;

export class BrowserUnsupportedError extends Error {
  browserSupport: BrowserSupportInfo;
  constructor(message?: string);
}

export class ConuClient {
  constructor();
}

