import { describe, expect, it, vi } from "vitest";

// Mock db module before importing auth (bun:sqlite not available in vitest)
vi.mock("./db", () => ({
	consumeNonce: vi.fn(),
}));

import {
	generateWWWAuthenticateChallenge,
	getKeyFromReadScope,
	isReadScope,
	makeReadScope,
	parseScopesFromResources,
	SCOPES,
	validateScopes,
} from "./auth";

// Mock Hono context
function createMockContext(headers: Record<string, string> = {}) {
	return {
		req: {
			header: (name: string) => headers[name.toLowerCase()],
		},
	} as Parameters<typeof generateWWWAuthenticateChallenge>[0];
}

describe("Dynamic Scope Helpers", () => {
	describe("makeReadScope", () => {
		it("creates a read scope for a key", () => {
			expect(makeReadScope("profile")).toBe("profile:read");
			expect(makeReadScope("settings")).toBe("settings:read");
		});
	});

	describe("isReadScope", () => {
		it("returns true for read scopes", () => {
			expect(isReadScope("profile:read")).toBe(true);
			expect(isReadScope("settings:read")).toBe(true);
		});

		it("returns false for non-read scopes", () => {
			expect(isReadScope("kv:write")).toBe(false);
			expect(isReadScope("profile:write")).toBe(false);
			expect(isReadScope("random")).toBe(false);
		});
	});

	describe("getKeyFromReadScope", () => {
		it("extracts key from read scope", () => {
			expect(getKeyFromReadScope("profile:read")).toBe("profile");
			expect(getKeyFromReadScope("settings:read")).toBe("settings");
		});

		it("returns null for non-read scopes", () => {
			expect(getKeyFromReadScope("kv:write")).toBeNull();
			expect(getKeyFromReadScope("random")).toBeNull();
		});
	});
});

describe("parseScopesFromResources", () => {
	it("returns empty array for undefined resources", () => {
		expect(parseScopesFromResources(undefined)).toEqual([]);
	});

	it("returns empty array for empty resources", () => {
		expect(parseScopesFromResources([])).toEqual([]);
	});

	it("parses scopes from urn:oauth:scope: prefix", () => {
		const resources = [
			"urn:oauth:scope:profile:read",
			"urn:oauth:scope:kv:write",
		];
		expect(parseScopesFromResources(resources)).toEqual([
			"profile:read",
			"kv:write",
		]);
	});

	it("ignores non-scope resources", () => {
		const resources = [
			"https://example.com/resource",
			"urn:oauth:scope:profile:read",
			"ipfs://QmHash",
		];
		expect(parseScopesFromResources(resources)).toEqual(["profile:read"]);
	});
});

describe("validateScopes", () => {
	it("returns empty array when no scopes requested", () => {
		expect(validateScopes([], [SCOPES.KV_WRITE])).toEqual([]);
	});

	it("allows static scopes that are in allowed list", () => {
		const requested = ["kv:write"];
		const allowed = [SCOPES.KV_WRITE];
		expect(validateScopes(requested, allowed)).toEqual(["kv:write"]);
	});

	it("filters out static scopes not in allowed list", () => {
		const requested = ["kv:write", "admin:all"];
		const allowed = [SCOPES.KV_WRITE];
		expect(validateScopes(requested, allowed)).toEqual(["kv:write"]);
	});

	it("allows any read scope when *:read is in allowed list", () => {
		const requested = ["profile:read", "settings:read"];
		const allowed = ["*:read"];
		expect(validateScopes(requested, allowed)).toEqual([
			"profile:read",
			"settings:read",
		]);
	});
});

describe("generateWWWAuthenticateChallenge", () => {
	it("generates challenge with correct format", () => {
		const ctx = createMockContext({
			host: "api.example.com",
			"x-forwarded-proto": "https",
		});

		const challenge = generateWWWAuthenticateChallenge(ctx, "test-realm", [
			"profile:read",
		]);

		expect(challenge).toContain("Bearer");
		expect(challenge).toContain('realm="test-realm"');
		expect(challenge).toContain('scope="profile:read"');
		expect(challenge).toContain(
			'token_uri="https://api.example.com/api/auth/token"',
		);
		expect(challenge).toContain('chain_id="1"');
		expect(challenge).toContain('signing_scheme="eip4361"');
	});

	it("uses http when x-forwarded-proto is not set", () => {
		const ctx = createMockContext({
			host: "localhost:3000",
		});

		const challenge = generateWWWAuthenticateChallenge(ctx, "test-realm", [
			"profile:read",
		]);

		expect(challenge).toContain(
			'token_uri="http://localhost:3000/api/auth/token"',
		);
	});

	it("includes multiple scopes space-separated", () => {
		const ctx = createMockContext({
			host: "api.example.com",
		});

		const challenge = generateWWWAuthenticateChallenge(ctx, "test-realm", [
			"profile:read",
			"settings:read",
		]);

		expect(challenge).toContain('scope="profile:read settings:read"');
	});

	it("defaults host to localhost when not provided", () => {
		const ctx = createMockContext({});

		const challenge = generateWWWAuthenticateChallenge(ctx, "test-realm", [
			"profile:read",
		]);

		expect(challenge).toContain('token_uri="http://localhost/api/auth/token"');
	});
});
