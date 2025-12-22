import type { Address } from "viem";
import { createSiweMessage } from "viem/siwe";

const TOKEN_KEY = "auth_token";

export function getToken(): string | null {
	return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
	localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
	localStorage.removeItem(TOKEN_KEY);
}

export async function fetchNonce(): Promise<string> {
	const res = await fetch("/api/auth/nonce");
	const data = await res.json();
	return data.nonce;
}

export function buildSiweMessage({
	address,
	chainId,
	nonce,
}: {
	address: Address;
	chainId: number;
	nonce: string;
}): string {
	const now = new Date();
	const expirationTime = new Date(now.getTime() + 5 * 60 * 1000); // 5 minutes

	return createSiweMessage({
		address,
		chainId,
		domain: window.location.host,
		nonce,
		uri: window.location.origin,
		version: "1",
		statement: "Sign in to manage your messages.",
		issuedAt: now,
		expirationTime,
	});
}

export async function exchangeSignatureForToken(
	message: string,
	signature: `0x${string}`,
): Promise<string> {
	const res = await fetch("/api/auth/token", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ message, signature }),
	});

	if (!res.ok) {
		const error = await res.json();
		throw new Error(error.error || "Token exchange failed");
	}

	const data = await res.json();
	return data.access_token;
}
