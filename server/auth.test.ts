import { describe, expect, it, vi } from "vitest";

// Mock db module before importing auth (bun:sqlite not available in vitest)
vi.mock("./db", () => ({
	consumeNonce: vi.fn(),
}));

import {
	generateWWWAuthenticateChallenge,
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

describe("parseScopesFromResources", () => {
	it("returns empty array for undefined resources", () => {
		expect(parseScopesFromResources(undefined)).toEqual([]);
	});

	it("returns empty array for empty resources", () => {
		expect(parseScopesFromResources([])).toEqual([]);
	});

	it("parses scopes from urn:oauth:scope: prefix", () => {
		const resources = [
			"urn:oauth:scope:messages:read",
			"urn:oauth:scope:messages:write",
		];
		expect(parseScopesFromResources(resources)).toEqual([
			"messages:read",
			"messages:write",
		]);
	});

	it("ignores non-scope resources", () => {
		const resources = [
			"https://example.com/resource",
			"urn:oauth:scope:messages:read",
			"ipfs://QmHash",
		];
		expect(parseScopesFromResources(resources)).toEqual(["messages:read"]);
	});
});

describe("validateScopes", () => {
	it("returns empty array when no scopes requested", () => {
		expect(validateScopes([], [SCOPES.MESSAGES_READ])).toEqual([]);
	});

	it("filters out invalid scopes", () => {
		const requested = ["messages:read", "invalid:scope", "messages:write"];
		const allowed = [SCOPES.MESSAGES_READ];
		expect(validateScopes(requested, allowed)).toEqual(["messages:read"]);
	});

	it("returns all requested scopes when all are allowed", () => {
		const requested = ["messages:read", "messages:write"];
		const allowed = [SCOPES.MESSAGES_READ, SCOPES.MESSAGES_WRITE];
		expect(validateScopes(requested, allowed)).toEqual([
			"messages:read",
			"messages:write",
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
			SCOPES.MESSAGES_READ,
		]);

		expect(challenge).toContain("Bearer");
		expect(challenge).toContain('realm="test-realm"');
		expect(challenge).toContain('scope="messages:read"');
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
			SCOPES.MESSAGES_READ,
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
			SCOPES.MESSAGES_READ,
			SCOPES.MESSAGES_WRITE,
		]);

		expect(challenge).toContain('scope="messages:read messages:write"');
	});

	it("defaults host to localhost when not provided", () => {
		const ctx = createMockContext({});

		const challenge = generateWWWAuthenticateChallenge(ctx, "test-realm", [
			SCOPES.MESSAGES_READ,
		]);

		expect(challenge).toContain('token_uri="http://localhost/api/auth/token"');
	});
});
