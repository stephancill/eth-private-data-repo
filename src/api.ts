import { getToken } from "./auth";

export interface KeyValueEntry {
	key: string;
	value: unknown;
	isPublic: boolean;
	createdAt?: string;
	updatedAt?: string;
}

const API_BASE = "/api";

function authHeaders(): HeadersInit {
	const token = getToken();
	if (!token) throw new Error("Not authenticated");
	return {
		"Content-Type": "application/json",
		Authorization: `Bearer ${token}`,
	};
}

export async function fetchKeys(): Promise<KeyValueEntry[]> {
	const res = await fetch(`${API_BASE}/keys`, {
		headers: authHeaders(),
	});
	if (res.status === 401) throw new Error("Unauthorized");
	if (!res.ok) throw new Error("Failed to fetch keys");
	return res.json();
}

export async function upsertKey(
	key: string,
	value: unknown,
	isPublic: boolean,
): Promise<KeyValueEntry> {
	const res = await fetch(`${API_BASE}/keys/${encodeURIComponent(key)}`, {
		method: "PUT",
		headers: authHeaders(),
		body: JSON.stringify({ value, isPublic }),
	});
	if (res.status === 401) throw new Error("Unauthorized");
	if (!res.ok) {
		const error = await res
			.json()
			.catch(() => ({ error: "Failed to save key" }));
		throw new Error(error.error || "Failed to save key");
	}
	return res.json();
}

export async function deleteKey(key: string): Promise<void> {
	const res = await fetch(`${API_BASE}/keys/${encodeURIComponent(key)}`, {
		method: "DELETE",
		headers: authHeaders(),
	});
	if (res.status === 401) throw new Error("Unauthorized");
	if (!res.ok) throw new Error("Failed to delete key");
}
