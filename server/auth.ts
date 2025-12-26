import type { Context } from "hono";
import { createMiddleware } from "hono/factory";
import { type JWTPayload, jwtVerify, SignJWT } from "jose";
import { createPublicClient, http } from "viem";
import { mainnet } from "viem/chains";
import { parseSiweMessage } from "viem/siwe";
import { consumeNonce } from "./db";

const TOKEN_EXPIRY = "1h";
const DEFAULT_CHAIN_ID = 1;

// OAuth scopes
export const SCOPES = {
	KV_WRITE: "kv:write",
} as const;

export type StaticScope = (typeof SCOPES)[keyof typeof SCOPES];

// Dynamic scope pattern for per-key read access: <key>:read
export function makeReadScope(key: string): string {
	return `${key}:read`;
}

export function isReadScope(scope: string): boolean {
	return scope.endsWith(":read");
}

export function getKeyFromReadScope(scope: string): string | null {
	if (!isReadScope(scope)) return null;
	return scope.slice(0, -5); // Remove ":read" suffix
}

// Get JWT secret from environment
function getJwtSecret(): Uint8Array {
	const secret = process.env.JWT_SECRET;
	if (!secret) {
		throw new Error("JWT_SECRET environment variable is required");
	}
	return new TextEncoder().encode(secret);
}

// Create mainnet public client for signature verification
const publicClient = createPublicClient({
	chain: mainnet,
	transport: http(),
});

interface TokenPayload extends JWTPayload {
	sub: string; // eip155:chainId:address
	address: string;
	chainId: number;
	scope?: string;
}

// Generate WWW-Authenticate challenge header per draft spec
export function generateWWWAuthenticateChallenge(
	c: Context,
	realm: string,
	scopes: string[],
): string {
	const host = c.req.header("host") || "localhost";
	const protocol = c.req.header("x-forwarded-proto") || "http";
	const baseUrl = `${protocol}://${host}`;

	return [
		"Bearer",
		`realm="${realm}"`,
		`scope="${scopes.join(" ")}"`,
		`token_uri="${baseUrl}/api/auth/token"`,
		`chain_id="${DEFAULT_CHAIN_ID}"`,
		`signing_scheme="eip4361"`,
	].join(", ");
}

// Parse scopes from SIWE resources field
export function parseScopesFromResources(resources?: string[]): string[] {
	if (!resources) return [];

	return resources
		.filter((r) => r.startsWith("urn:oauth:scope:"))
		.map((r) => r.replace("urn:oauth:scope:", ""));
}

// Validate requested scopes - for dynamic scopes, we validate the format
export function validateScopes(
	requested: string[],
	allowed: string[],
): string[] {
	const allowedSet = new Set<string>(allowed);
	return requested.filter((s) => {
		// Allow static scopes that are in the allowed set
		if (allowedSet.has(s)) return true;
		// Allow any <key>:read scope if "dynamic:read" is allowed or no restrictions
		if (isReadScope(s) && (allowedSet.has("*:read") || allowed.length === 0)) {
			return true;
		}
		return false;
	});
}

async function createToken(payload: TokenPayload): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256" })
		.setIssuedAt()
		.setExpirationTime(TOKEN_EXPIRY)
		.sign(getJwtSecret());
}

async function verifyToken(token: string): Promise<TokenPayload | null> {
	try {
		const { payload } = await jwtVerify(token, getJwtSecret());
		return payload as unknown as TokenPayload;
	} catch {
		return null;
	}
}

export interface TokenExchangeRequest {
	grant_type?: "eth_signature";
	message: string;
	signature: `0x${string}`;
	scope?: string;
}

export interface TokenExchangeSuccess {
	token: string;
	address: string;
	chainId: number;
	scope: string;
}

export interface TokenExchangeError {
	error: string;
}

export async function exchangeToken(
	request: TokenExchangeRequest,
	allowedScopes?: string[],
): Promise<TokenExchangeSuccess | TokenExchangeError> {
	try {
		const { message, signature, scope: requestedScope } = request;

		const parsed = parseSiweMessage(message);

		if (!parsed.address) {
			return { error: "Missing address" };
		}

		if (!parsed.nonce) {
			return { error: "Missing nonce" };
		}

		// Verify chain ID matches expected
		if (parsed.chainId && parsed.chainId !== DEFAULT_CHAIN_ID) {
			return { error: `Invalid chain ID. Expected ${DEFAULT_CHAIN_ID}` };
		}

		// Verify nonce is valid and consume it
		if (!consumeNonce(parsed.nonce)) {
			return { error: "Invalid or expired nonce" };
		}

		// Check expiration
		if (parsed.expirationTime && new Date(parsed.expirationTime) < new Date()) {
			return { error: "Message expired" };
		}

		// Verify signature using mainnet public client (supports EIP-1271 for smart contract wallets)
		const valid = await publicClient.verifyMessage({
			address: parsed.address,
			message,
			signature,
		});

		if (!valid) {
			return { error: "Invalid signature" };
		}

		// Parse scopes from SIWE resources
		const scopesFromResources = parseScopesFromResources(parsed.resources);

		// Use scopes from request body if provided, otherwise from SIWE message
		const requestedScopes = requestedScope
			? requestedScope.split(" ")
			: scopesFromResources;

		// For token exchange, we allow:
		// - kv:write (static scope)
		// - Any <key>:read scope (dynamic scopes)
		let grantedScopes: string[];
		if (allowedScopes) {
			grantedScopes = requestedScopes.filter((s) => {
				// Static scopes must be in allowed list
				if (allowedScopes.includes(s)) return true;
				// Dynamic read scopes are always allowed (format validated)
				if (isReadScope(s)) return true;
				return false;
			});
		} else {
			grantedScopes = requestedScopes;
		}

		const address = parsed.address.toLowerCase();
		const chainId = parsed.chainId || DEFAULT_CHAIN_ID;
		const scopeString = grantedScopes.join(" ");

		const token = await createToken({
			sub: `eip155:${chainId}:${address}`,
			address,
			chainId,
			scope: scopeString,
		});

		return { token, address, chainId, scope: scopeString };
	} catch (e) {
		return { error: e instanceof Error ? e.message : "Token exchange failed" };
	}
}

// Auth middleware for protected routes (owner operations)
export const authMiddleware = createMiddleware<{
	Variables: { address: string; chainId: number; scopes: string[] };
}>(async (c, next) => {
	const authHeader = c.req.header("Authorization");

	if (!authHeader?.startsWith("Bearer ")) {
		return c.json({ error: "Missing authorization header" }, 401);
	}

	const token = authHeader.slice(7);
	const payload = await verifyToken(token);

	if (!payload) {
		return c.json({ error: "Invalid or expired token" }, 401);
	}

	c.set("address", payload.address);
	c.set("chainId", payload.chainId);
	c.set("scopes", payload.scope ? payload.scope.split(" ") : []);

	await next();
});

// Create a middleware for the /user/:address/:key endpoint
// This handles both public and private key access with dynamic scopes
export function createKeyValueAuthMiddleware(
	getKeyVisibility: (owner: string, key: string) => boolean | null,
) {
	return createMiddleware<{
		Variables: {
			address: string | null;
			chainId: number | null;
			scopes: string[];
		};
	}>(async (c, next) => {
		const ownerAddress = c.req.param("address")?.toLowerCase();
		const key = c.req.param("key");

		if (!ownerAddress || !key) {
			return c.json({ error: "Missing address or key" }, 400);
		}

		// Check if the key exists and its visibility
		const isPublic = getKeyVisibility(ownerAddress, key);

		if (isPublic === null) {
			// Key doesn't exist
			return c.json({ error: "Key not found" }, 404);
		}

		if (isPublic) {
			// Public key - no auth needed
			c.set("address", null);
			c.set("chainId", null);
			c.set("scopes", []);
			await next();
			return;
		}

		// Private key - requires authentication with specific scope
		const requiredScope = makeReadScope(key);
		const authHeader = c.req.header("Authorization");

		if (!authHeader?.startsWith("Bearer ")) {
			const challenge = generateWWWAuthenticateChallenge(c, `kv-${key}`, [
				requiredScope,
			]);
			c.header("WWW-Authenticate", challenge);
			return c.json(
				{
					error: "unauthorized",
					error_description: "Authentication required for private key",
				},
				401,
			);
		}

		const token = authHeader.slice(7);
		const payload = await verifyToken(token);

		if (!payload) {
			const challenge = generateWWWAuthenticateChallenge(c, `kv-${key}`, [
				requiredScope,
			]);
			c.header("WWW-Authenticate", challenge);
			return c.json(
				{
					error: "invalid_token",
					error_description: "Invalid or expired token",
				},
				401,
			);
		}

		// Check if token has the required scope OR if requester is the owner
		const tokenScopes = payload.scope ? payload.scope.split(" ") : [];
		const isOwner = payload.address.toLowerCase() === ownerAddress;
		const hasRequiredScope = tokenScopes.includes(requiredScope);

		if (!hasRequiredScope && !isOwner) {
			const challenge = generateWWWAuthenticateChallenge(c, `kv-${key}`, [
				requiredScope,
			]);
			c.header("WWW-Authenticate", challenge);
			return c.json(
				{
					error: "insufficient_scope",
					error_description: `Required scope: ${requiredScope}`,
				},
				403,
			);
		}

		c.set("address", payload.address);
		c.set("chainId", payload.chainId);
		c.set("scopes", tokenScopes);

		await next();
	});
}
