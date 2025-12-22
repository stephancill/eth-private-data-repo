import { getToken } from "./auth";

export interface Message {
	id: number;
	content: string;
	author: string;
	created_at: string;
	updated_at: string;
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

export async function fetchMessages(): Promise<Message[]> {
	const res = await fetch(`${API_BASE}/messages`, {
		headers: authHeaders(),
	});
	if (res.status === 401) throw new Error("Unauthorized");
	if (!res.ok) throw new Error("Failed to fetch messages");
	return res.json();
}

export async function createMessage(content: string): Promise<Message> {
	const res = await fetch(`${API_BASE}/messages`, {
		method: "POST",
		headers: authHeaders(),
		body: JSON.stringify({ content }),
	});
	if (res.status === 401) throw new Error("Unauthorized");
	if (!res.ok) throw new Error("Failed to create message");
	return res.json();
}

export async function updateMessage(
	id: number,
	content: string,
): Promise<Message> {
	const res = await fetch(`${API_BASE}/messages/${id}`, {
		method: "PUT",
		headers: authHeaders(),
		body: JSON.stringify({ content }),
	});
	if (res.status === 401) throw new Error("Unauthorized");
	if (!res.ok) throw new Error("Failed to update message");
	return res.json();
}

export async function deleteMessage(id: number): Promise<void> {
	const res = await fetch(`${API_BASE}/messages/${id}`, {
		method: "DELETE",
		headers: authHeaders(),
	});
	if (res.status === 401) throw new Error("Unauthorized");
	if (!res.ok) throw new Error("Failed to delete message");
}
