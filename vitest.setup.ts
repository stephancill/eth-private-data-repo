import { webcrypto } from "node:crypto";

// Polyfill crypto for Node.js environment (viem/siwe needs it)
if (typeof globalThis.crypto === "undefined") {
	// @ts-expect-error - webcrypto is compatible with Web Crypto API
	globalThis.crypto = webcrypto;
}
