import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Set JWT_SECRET for tests before importing auth
process.env.JWT_SECRET = "test-secret-for-vitest-at-least-32-chars";

// Track consumed nonces in tests
const consumedNonces = new Set<string>();

// Mock key-value data store
const mockKeyValues = new Map<string, { value: string; is_public: number }>();

// Mock the db module (bun:sqlite not available in vitest)
vi.mock("./db", () => ({
	consumeNonce: vi.fn((nonce: string) => {
		// Nonces starting with "valid" are valid, but can only be used once
		if (nonce.startsWith("valid") && !consumedNonces.has(nonce)) {
			consumedNonces.add(nonce);
			return true;
		}
		return false;
	}),
	getKeyValue: vi.fn((owner: string, key: string) => {
		const storeKey = `${owner.toLowerCase()}:${key}`;
		const entry = mockKeyValues.get(storeKey);
		if (!entry) return null;
		return {
			owner: owner.toLowerCase(),
			key,
			value: entry.value,
			is_public: entry.is_public,
			created_at: "2025-01-01T00:00:00Z",
			updated_at: "2025-01-01T00:00:00Z",
		};
	}),
}));

// Mock viem's createPublicClient
vi.mock("viem", async (importOriginal) => {
	const actual = await importOriginal<typeof import("viem")>();
	return {
		...actual,
		createPublicClient: () => ({
			verifyMessage: vi.fn(
				async ({
					signature,
				}: {
					address: string;
					message: string;
					signature: string;
				}) => {
					// Return true for test signatures starting with 0xvalid
					return signature.startsWith("0xvalid");
				},
			),
		}),
	};
});

import {
	createKeyValueAuthMiddleware,
	exchangeToken,
	SCOPES,
	type TokenExchangeRequest,
} from "./auth";
import { getKeyValue } from "./db";

describe("Key-Value API", () => {
	let app: Hono;

	beforeEach(() => {
		mockKeyValues.clear();
		app = new Hono();

		// Helper function to check key visibility using the mocked getKeyValue
		function getKeyVisibility(owner: string, key: string): boolean | null {
			const kv = getKeyValue(owner, key);
			if (!kv) return null;
			return kv.is_public === 1;
		}

		// Mount the key-value endpoint
		app.get(
			"/user/:address/:key",
			createKeyValueAuthMiddleware(getKeyVisibility),
			(c) => {
				const ownerAddress = c.req.param("address").toLowerCase();
				const key = c.req.param("key");
				const kv = getKeyValue(ownerAddress, key);
				if (!kv) {
					return c.json({ error: "Key not found" }, 404);
				}
				return c.json(JSON.parse(kv.value));
			},
		);
	});

	describe("GET /user/:address/:key", () => {
		it("returns public key without authentication", async () => {
			const owner = "0x1234567890abcdef1234567890abcdef12345678";
			mockKeyValues.set(`${owner.toLowerCase()}:profile`, {
				value: JSON.stringify({ name: "Alice" }),
				is_public: 1,
			});

			const res = await app.request(`/user/${owner}/profile`);

			expect(res.status).toBe(200);
			const body = await res.json();
			expect(body).toEqual({ name: "Alice" });
		});

		it("returns 401 with WWW-Authenticate for private key without auth", async () => {
			const owner = "0x1234567890abcdef1234567890abcdef12345678";
			mockKeyValues.set(`${owner.toLowerCase()}:settings`, {
				value: JSON.stringify({ theme: "dark" }),
				is_public: 0,
			});

			const res = await app.request(`/user/${owner}/settings`);

			expect(res.status).toBe(401);

			const wwwAuth = res.headers.get("WWW-Authenticate");
			expect(wwwAuth).toBeTruthy();
			expect(wwwAuth).toContain("Bearer");
			expect(wwwAuth).toContain('realm="kv-settings"');
			expect(wwwAuth).toContain('scope="settings:read"');
			expect(wwwAuth).toContain("token_uri=");
			expect(wwwAuth).toContain('chain_id="1"');
			expect(wwwAuth).toContain('signing_scheme="eip4361"');

			const body = await res.json();
			expect(body.error).toBe("unauthorized");
		});

		it("returns 404 for non-existent key", async () => {
			const owner = "0x1234567890abcdef1234567890abcdef12345678";

			const res = await app.request(`/user/${owner}/nonexistent`);

			expect(res.status).toBe(404);
		});

		it("returns 401 with WWW-Authenticate header for invalid token on private key", async () => {
			const owner = "0x1234567890abcdef1234567890abcdef12345678";
			mockKeyValues.set(`${owner.toLowerCase()}:settings`, {
				value: JSON.stringify({ theme: "dark" }),
				is_public: 0,
			});

			const res = await app.request(`/user/${owner}/settings`, {
				headers: {
					Authorization: "Bearer invalid-token",
				},
			});

			expect(res.status).toBe(401);

			const wwwAuth = res.headers.get("WWW-Authenticate");
			expect(wwwAuth).toBeTruthy();

			const body = await res.json();
			expect(body.error).toBe("invalid_token");
		});

		it("returns 403 when trying to read another address's private key", async () => {
			// Owner's address (Bob)
			const owner = "0xb0b0000000000000000000000000000000000000";
			mockKeyValues.set(`${owner.toLowerCase()}:settings`, {
				value: JSON.stringify({ theme: "dark" }),
				is_public: 0,
			});

			// Get a token for Alice's address (different from owner)
			const aliceMessage = `localhost wants you to sign in with your Ethereum account:
0xa11ce00000000000000000000000000000000000

Sign in to access your data.

URI: http://localhost:3000
Version: 1
Chain ID: 1
Nonce: validnonce10001
Issued At: 2025-12-22T07:15:00Z
Resources:
- urn:oauth:scope:settings:read`;

			const tokenResult = await exchangeToken(
				{
					message: aliceMessage,
					signature: "0xvalid",
				},
				[SCOPES.KV_WRITE],
			);

			expect("error" in tokenResult).toBe(false);
			if ("error" in tokenResult) return;

			// Alice tries to read Bob's private key using her token
			const res = await app.request(`/user/${owner}/settings`, {
				headers: {
					Authorization: `Bearer ${tokenResult.token}`,
				},
			});

			expect(res.status).toBe(403);

			const body = await res.json();
			expect(body.error).toBe("insufficient_scope");
			expect(body.error_description).toContain("other addresses");
		});

		it("allows owner to read their own private key", async () => {
			// Token address matches owner address
			const owner = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
			mockKeyValues.set(`${owner.toLowerCase()}:settings`, {
				value: JSON.stringify({ theme: "dark" }),
				is_public: 0,
			});

			const ownerMessage = `localhost wants you to sign in with your Ethereum account:
0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

Sign in to access your data.

URI: http://localhost:3000
Version: 1
Chain ID: 1
Nonce: validnonce10002
Issued At: 2025-12-22T07:15:00Z`;

			const tokenResult = await exchangeToken(
				{
					message: ownerMessage,
					signature: "0xvalid",
				},
				[SCOPES.KV_WRITE],
			);

			expect("error" in tokenResult).toBe(false);
			if ("error" in tokenResult) return;

			// Owner reads their own private key
			const res = await app.request(`/user/${owner}/settings`, {
				headers: {
					Authorization: `Bearer ${tokenResult.token}`,
				},
			});

			expect(res.status).toBe(200);

			const body = await res.json();
			expect(body).toEqual({ theme: "dark" });
		});
	});
});

describe("Token Exchange", () => {
	// Helper to create SIWE messages with unique nonces
	function createSiweMessage(options: {
		nonce: string;
		chainId?: number;
		resources?: string[];
	}) {
		const { nonce, chainId = 1, resources } = options;
		let message = `localhost wants you to sign in with your Ethereum account:
0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

Sign in to access your data.

URI: http://localhost:3000
Version: 1
Chain ID: ${chainId}
Nonce: ${nonce}
Issued At: 2025-12-22T07:15:00Z`;

		if (resources && resources.length > 0) {
			message += `\nResources:\n${resources.map((r) => `- ${r}`).join("\n")}`;
		}
		return message;
	}

	it("returns error for missing address", async () => {
		const request: TokenExchangeRequest = {
			message: "invalid message",
			signature: "0xvalid",
		};

		const result = await exchangeToken(request);
		expect("error" in result).toBe(true);
		if ("error" in result) {
			expect(result.error).toBe("Missing address");
		}
	});

	it("returns error for invalid nonce", async () => {
		const message = createSiweMessage({ nonce: "invalidnonce9999" });

		const request: TokenExchangeRequest = {
			message,
			signature: "0xvalid",
		};

		const result = await exchangeToken(request);
		expect("error" in result).toBe(true);
		if ("error" in result) {
			expect(result.error).toBe("Invalid or expired nonce");
		}
	});

	it("returns error for invalid signature", async () => {
		const message = createSiweMessage({ nonce: "validnonce00001" });

		const request: TokenExchangeRequest = {
			message,
			signature: "0xinvalid",
		};

		const result = await exchangeToken(request);
		expect("error" in result).toBe(true);
		if ("error" in result) {
			expect(result.error).toBe("Invalid signature");
		}
	});

	it("returns token with kv:write scope from request body", async () => {
		const message = createSiweMessage({ nonce: "validnonce00002" });

		const request: TokenExchangeRequest = {
			grant_type: "eth_signature",
			message,
			signature: "0xvalid",
			scope: "kv:write",
		};

		const result = await exchangeToken(request, [SCOPES.KV_WRITE]);

		expect("error" in result).toBe(false);
		if (!("error" in result)) {
			expect(result.token).toBeTruthy();
			expect(result.address).toBe("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
			expect(result.chainId).toBe(1);
			expect(result.scope).toBe("kv:write");
		}
	});

	it("returns token with per-key read scope", async () => {
		const message = createSiweMessage({
			nonce: "validnonce00003",
			resources: ["urn:oauth:scope:profile:read"],
		});

		const request: TokenExchangeRequest = {
			message,
			signature: "0xvalid",
		};

		const result = await exchangeToken(request, [SCOPES.KV_WRITE]);

		expect("error" in result).toBe(false);
		if (!("error" in result)) {
			expect(result.token).toBeTruthy();
			// Dynamic read scopes are always allowed
			expect(result.scope).toBe("profile:read");
		}
	});

	it("returns token with multiple scopes from SIWE resources", async () => {
		const message = createSiweMessage({
			nonce: "validnonce00004",
			resources: [
				"urn:oauth:scope:profile:read",
				"urn:oauth:scope:settings:read",
				"urn:oauth:scope:kv:write",
			],
		});

		const request: TokenExchangeRequest = {
			message,
			signature: "0xvalid",
		};

		const result = await exchangeToken(request, [SCOPES.KV_WRITE]);

		expect("error" in result).toBe(false);
		if (!("error" in result)) {
			expect(result.token).toBeTruthy();
			expect(result.scope).toBe("profile:read settings:read kv:write");
		}
	});

	it("returns error for wrong chain ID", async () => {
		const message = createSiweMessage({
			nonce: "validnonce00005",
			chainId: 137,
		});

		const request: TokenExchangeRequest = {
			message,
			signature: "0xvalid",
		};

		const result = await exchangeToken(request);
		expect("error" in result).toBe(true);
		if ("error" in result) {
			expect(result.error).toContain("Invalid chain ID");
		}
	});
});

describe("WWW-Authenticate Challenge Format", () => {
	it("conforms to RFC 6750 Bearer scheme for private keys", async () => {
		const app = new Hono();

		function getKeyVisibility(_owner: string, key: string): boolean | null {
			if (key === "private-key") return false;
			return null;
		}

		app.get(
			"/user/:address/:key",
			createKeyValueAuthMiddleware(getKeyVisibility),
			(c) => c.json({ ok: true }),
		);

		const res = await app.request(
			"/user/0x1234567890abcdef1234567890abcdef12345678/private-key",
		);
		const wwwAuth = res.headers.get("WWW-Authenticate");

		// Should start with Bearer scheme
		expect(wwwAuth).toMatch(/^Bearer/);

		// Should contain required OAuth parameters
		expect(wwwAuth).toMatch(/realm="[^"]+"/);
		expect(wwwAuth).toMatch(/scope="[^"]+"/);

		// Should contain SIWE-specific parameters
		expect(wwwAuth).toMatch(/token_uri="[^"]+"/);
		expect(wwwAuth).toMatch(/chain_id="[^"]+"/);
		expect(wwwAuth).toMatch(/signing_scheme="eip4361"/);

		// Should have per-key scope
		expect(wwwAuth).toContain('scope="private-key:read"');
	});
});
