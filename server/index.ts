import { Hono } from "hono";
import { serveStatic } from "hono/bun";
import { cors } from "hono/cors";
import {
	authMiddleware,
	createKeyValueAuthMiddleware,
	exchangeToken,
	SCOPES,
	type TokenExchangeRequest,
} from "./auth";
import {
	createNonce,
	deleteKeyValue,
	getAllKeysByOwner,
	getKeyValue,
	upsertKeyValue,
} from "./db";

const app = new Hono();

// CORS for development
app.use(
	"/api/*",
	cors({
		origin: "*",
		exposeHeaders: ["WWW-Authenticate"],
	}),
);

// Also enable CORS for /user/* endpoint
app.use(
	"/user/*",
	cors({
		origin: "*",
		exposeHeaders: ["WWW-Authenticate"],
	}),
);

// Auth endpoints (public)
app.get("/api/auth/nonce", (c) => {
	const nonce = createNonce();
	return c.json({ nonce });
});

app.post("/api/auth/token", async (c) => {
	const body = await c.req.json<TokenExchangeRequest>();

	// Support both legacy format and new eth_signature grant type
	if (!body.message || !body.signature) {
		return c.json({ error: "Missing message or signature" }, 400);
	}

	// Validate grant_type if provided
	if (body.grant_type && body.grant_type !== "eth_signature") {
		return c.json({ error: "unsupported_grant_type" }, 400);
	}

	// Allow kv:write and any <key>:read scopes
	const allowedScopes = [SCOPES.KV_WRITE];
	const result = await exchangeToken(body, allowedScopes);

	if ("error" in result) {
		return c.json({ error: result.error }, 400);
	}

	return c.json({
		access_token: result.token,
		token_type: "Bearer",
		expires_in: 3600,
		scope: result.scope,
	});
});

// Public key-value access endpoint with discoverable OAuth
// GET /user/:address/:key
const userApi = new Hono<{
	Variables: {
		address: string | null;
		chainId: number | null;
		scopes: string[];
	};
}>();

// Helper function to check key visibility
function getKeyVisibility(owner: string, key: string): boolean | null {
	const kv = getKeyValue(owner, key);
	if (!kv) return null;
	return kv.is_public === 1;
}

userApi.get(
	"/:address/:key",
	createKeyValueAuthMiddleware(getKeyVisibility),
	(c) => {
		const ownerAddress = c.req.param("address").toLowerCase();
		const key = c.req.param("key");

		const kv = getKeyValue(ownerAddress, key);
		if (!kv) {
			return c.json({ error: "Key not found" }, 404);
		}

		return c.json({
			key: kv.key,
			value: JSON.parse(kv.value),
			owner: kv.owner,
			isPublic: kv.is_public === 1,
		});
	},
);

app.route("/user", userApi);

// Protected API routes (owner operations)
const api = new Hono<{
	Variables: { address: string; chainId: number; scopes: string[] };
}>();
api.use("*", authMiddleware);

// List all keys for authenticated user
api.get("/keys", (c) => {
	const address = c.get("address");
	const keys = getAllKeysByOwner(address);
	return c.json(
		keys.map((kv) => ({
			key: kv.key,
			value: JSON.parse(kv.value),
			isPublic: kv.is_public === 1,
			createdAt: kv.created_at,
			updatedAt: kv.updated_at,
		})),
	);
});

// Create or update a key-value pair
api.put("/keys/:key", async (c) => {
	const key = c.req.param("key");
	const body = await c.req.json<{ value: unknown; isPublic?: boolean }>();
	const owner = c.get("address");

	if (body.value === undefined) {
		return c.json({ error: "Value is required" }, 400);
	}

	// Validate key format (alphanumeric, hyphens, underscores)
	if (!/^[a-zA-Z0-9_-]+$/.test(key)) {
		return c.json(
			{
				error:
					"Invalid key format. Use alphanumeric characters, hyphens, and underscores only.",
			},
			400,
		);
	}

	const isPublic = body.isPublic ?? false;
	const kv = upsertKeyValue(owner, key, body.value, isPublic);

	return c.json({
		key: kv.key,
		value: JSON.parse(kv.value),
		isPublic: kv.is_public === 1,
		createdAt: kv.created_at,
		updatedAt: kv.updated_at,
	});
});

// Delete a key
api.delete("/keys/:key", (c) => {
	const key = c.req.param("key");
	const owner = c.get("address");

	const deleted = deleteKeyValue(owner, key);
	if (!deleted) {
		return c.json({ error: "Key not found" }, 404);
	}
	return c.json({ success: true });
});

app.route("/api", api);

const port = parseInt(process.env.PORT || "3000", 10);
const isDev = process.env.NODE_ENV !== "production";

if (isDev) {
	// Development: start Vite and proxy to it
	const { createServer } = await import("vite");
	const vite = await createServer({
		server: { port: 5173, strictPort: true },
		appType: "spa",
	});
	await vite.listen();
	console.log(`Vite dev server on http://localhost:5173`);

	// Proxy all non-API requests to Vite
	app.all("*", async (c) => {
		const url = new URL(c.req.url);
		const viteUrl = `http://localhost:5173${url.pathname}${url.search}`;

		const headers = new Headers(c.req.raw.headers);
		headers.delete("host");

		const response = await fetch(viteUrl, {
			method: c.req.method,
			headers,
			body:
				c.req.method !== "GET" && c.req.method !== "HEAD"
					? await c.req.raw.text()
					: undefined,
		});

		return new Response(response.body, {
			status: response.status,
			headers: response.headers,
		});
	});

	console.log(`Dev server on http://localhost:${port}`);
} else {
	// Production: serve static files
	app.use("/*", serveStatic({ root: "./dist" }));
	app.get("*", serveStatic({ path: "./dist/index.html" }));
	console.log(`Server running on port ${port}`);
}

export default {
	port,
	fetch: app.fetch,
};
