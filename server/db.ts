import { Database } from "bun:sqlite";
import { existsSync, mkdirSync } from "node:fs";

const DATA_DIR = process.env.DATA_DIR || "./data";

// Ensure data directory exists
if (!existsSync(DATA_DIR)) {
	mkdirSync(DATA_DIR, { recursive: true });
}

const dbPath = `${DATA_DIR}/data.db`;
export const db = new Database(dbPath);

// Initialize schema
db.run(`
  CREATE TABLE IF NOT EXISTS key_values (
    owner TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    is_public INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (owner, key)
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

export interface KeyValue {
	owner: string;
	key: string;
	value: string; // JSON-encoded
	is_public: number;
	created_at: string;
	updated_at: string;
}

export interface KeyValueInput {
	key: string;
	value: unknown; // Will be JSON-encoded
	isPublic: boolean;
}

export function getAllKeysByOwner(owner: string): KeyValue[] {
	return db
		.query("SELECT * FROM key_values WHERE owner = ? ORDER BY key ASC")
		.all(owner.toLowerCase()) as KeyValue[];
}

export function getKeyValue(owner: string, key: string): KeyValue | null {
	return db
		.query("SELECT * FROM key_values WHERE owner = ? AND key = ?")
		.get(owner.toLowerCase(), key) as KeyValue | null;
}

export function upsertKeyValue(
	owner: string,
	key: string,
	value: unknown,
	isPublic: boolean,
): KeyValue {
	const jsonValue = JSON.stringify(value);
	const result = db
		.query(
			`INSERT INTO key_values (owner, key, value, is_public)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(owner, key) DO UPDATE SET
			   value = excluded.value,
			   is_public = excluded.is_public,
			   updated_at = datetime('now')
			 RETURNING *`,
		)
		.get(owner.toLowerCase(), key, jsonValue, isPublic ? 1 : 0) as KeyValue;
	return result;
}

export function deleteKeyValue(owner: string, key: string): boolean {
	const result = db.run("DELETE FROM key_values WHERE owner = ? AND key = ?", [
		owner.toLowerCase(),
		key,
	]);
	return result.changes > 0;
}

// Nonce management
function generateAlphanumericNonce(length = 16): string {
	const chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
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
