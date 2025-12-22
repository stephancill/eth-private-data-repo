import { Database } from "bun:sqlite";
import { existsSync, mkdirSync } from "node:fs";

const DATA_DIR = process.env.DATA_DIR || "./data";

// Ensure data directory exists
if (!existsSync(DATA_DIR)) {
	mkdirSync(DATA_DIR, { recursive: true });
}

const dbPath = `${DATA_DIR}/messages.db`;
export const db = new Database(dbPath);

// Initialize schema
db.run(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

export interface Message {
	id: number;
	content: string;
	author: string;
	created_at: string;
	updated_at: string;
}

export function getAllMessages(): Message[] {
	return db
		.query("SELECT * FROM messages ORDER BY created_at DESC")
		.all() as Message[];
}

export function getMessagesByAuthor(author: string): Message[] {
	return db
		.query("SELECT * FROM messages WHERE author = ? ORDER BY created_at DESC")
		.all(author.toLowerCase()) as Message[];
}

export function getMessage(id: number): Message | null {
	return db
		.query("SELECT * FROM messages WHERE id = ?")
		.get(id) as Message | null;
}

export function createMessage(content: string, author: string): Message {
	const result = db
		.query("INSERT INTO messages (content, author) VALUES (?, ?) RETURNING *")
		.get(content, author.toLowerCase()) as Message;
	return result;
}

export function updateMessage(
	id: number,
	content: string,
	author: string,
): Message | null {
	const result = db
		.query(
			"UPDATE messages SET content = ?, updated_at = datetime('now') WHERE id = ? AND author = ? RETURNING *",
		)
		.get(content, id, author.toLowerCase()) as Message | null;
	return result;
}

export function deleteMessage(id: number, author: string): boolean {
	const result = db.run("DELETE FROM messages WHERE id = ? AND author = ?", [
		id,
		author.toLowerCase(),
	]);
	return result.changes > 0;
}

// Nonce management
function generateAlphanumericNonce(length = 16): string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	const bytes = crypto.getRandomValues(new Uint8Array(length));
	return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

export function createNonce(): string {
	const nonce = generateAlphanumericNonce();
	db.run("INSERT INTO nonces (nonce) VALUES (?)", [nonce]);
	// Clean up old nonces (older than 5 minutes)
	db.run("DELETE FROM nonces WHERE created_at < datetime('now', '-5 minutes')");
	return nonce;
}

export function consumeNonce(nonce: string): boolean {
	const result = db.run("DELETE FROM nonces WHERE nonce = ?", [nonce]);
	return result.changes > 0;
}
