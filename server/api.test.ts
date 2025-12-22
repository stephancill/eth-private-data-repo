import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Set JWT_SECRET for tests before importing auth
process.env.JWT_SECRET = "test-secret-for-vitest-at-least-32-chars";

// Track consumed nonces in tests
const consumedNonces = new Set<string>();

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
	getMessagesByAuthor: vi.fn((author: string) => [
		{
			id: 1,
			content: "Test message",
			author: author.toLowerCase(),
			created_at: "2025-01-01T00:00:00Z",
			updated_at: "2025-01-01T00:00:00Z",
		},
	]),
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
	createScopedAuthMiddleware,
	exchangeToken,
	SCOPES,
	type TokenExchangeRequest,
} from "./auth";

describe("Discoverable OAuth API", () => {
	let app: Hono;

	beforeEach(() => {
		app = new Hono();

		// Mount the discoverable endpoint
		app.get(
			"/api/authors/:address/messages",
			createScopedAuthMiddleware("author-messages", [SCOPES.MESSAGES_READ]),
			(c) => {
				const { getMessagesByAuthor } = require("./db");
				const authorAddress = c.req.param("address").toLowerCase();
				const messages = getMessagesByAuthor(authorAddress);
				return c.json({ author: authorAddress, messages });
			},
		);
	});

	describe("GET /api/authors/:address/messages", () => {
		it("returns 401 with WWW-Authenticate header when no auth provided", async () => {
			const res = await app.request(
				"/api/authors/0x1234567890abcdef1234567890abcdef12345678/messages",
			);

			expect(res.status).toBe(401);

			const wwwAuth = res.headers.get("WWW-Authenticate");
			expect(wwwAuth).toBeTruthy();
			expect(wwwAuth).toContain("Bearer");
			expect(wwwAuth).toContain('realm="author-messages"');
			expect(wwwAuth).toContain('scope="messages:read"');
			expect(wwwAuth).toContain("token_uri=");
			expect(wwwAuth).toContain('chain_id="1"');
			expect(wwwAuth).toContain('signing_scheme="eip4361"');

			const body = await res.json();
			expect(body.error).toBe("unauthorized");
			expect(body.error_description).toBe("Authentication required");
		});

		it("returns 401 with WWW-Authenticate header for invalid token", async () => {
			const res = await app.request(
				"/api/authors/0x1234567890abcdef1234567890abcdef12345678/messages",
				{
					headers: {
						Authorization: "Bearer invalid-token",
					},
				},
			);

			expect(res.status).toBe(401);

			const wwwAuth = res.headers.get("WWW-Authenticate");
			expect(wwwAuth).toBeTruthy();

			const body = await res.json();
			expect(body.error).toBe("invalid_token");
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

Sign in to access your messages.

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

	it("returns token with scopes from request body", async () => {
		const message = createSiweMessage({ nonce: "validnonce00002" });

		const request: TokenExchangeRequest = {
			grant_type: "eth_signature",
			message,
			signature: "0xvalid",
			scope: "messages:read",
		};

		const result = await exchangeToken(request, [SCOPES.MESSAGES_READ]);

		expect("error" in result).toBe(false);
		if (!("error" in result)) {
			expect(result.token).toBeTruthy();
			expect(result.address).toBe("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
			expect(result.chainId).toBe(1);
			expect(result.scope).toBe("messages:read");
		}
	});

	it("returns token with scopes from SIWE resources", async () => {
		const message = createSiweMessage({
			nonce: "validnonce00003",
			resources: [
				"urn:oauth:scope:messages:read",
				"urn:oauth:scope:messages:write",
			],
		});

		const request: TokenExchangeRequest = {
			message,
			signature: "0xvalid",
		};

		const result = await exchangeToken(request, [
			SCOPES.MESSAGES_READ,
			SCOPES.MESSAGES_WRITE,
		]);

		expect("error" in result).toBe(false);
		if (!("error" in result)) {
			expect(result.token).toBeTruthy();
			expect(result.scope).toBe("messages:read messages:write");
		}
	});

	it("filters out unauthorized scopes", async () => {
		const message = createSiweMessage({
			nonce: "validnonce00004",
			resources: [
				"urn:oauth:scope:messages:read",
				"urn:oauth:scope:messages:write",
			],
		});

		const request: TokenExchangeRequest = {
			message,
			signature: "0xvalid",
		};

		// Only allow messages:read
		const result = await exchangeToken(request, [SCOPES.MESSAGES_READ]);

		expect("error" in result).toBe(false);
		if (!("error" in result)) {
			expect(result.scope).toBe("messages:read");
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
	it("conforms to RFC 6750 Bearer scheme", async () => {
		const app = new Hono();
		app.get(
			"/test",
			createScopedAuthMiddleware("test", [SCOPES.MESSAGES_READ]),
			(c) => c.json({ ok: true }),
		);

		const res = await app.request("/test");
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
	});
});
