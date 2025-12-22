import { Hono } from "hono";
import { serveStatic } from "hono/bun";
import { cors } from "hono/cors";
import {
	authMiddleware,
	createScopedAuthMiddleware,
	exchangeToken,
	SCOPES,
	type TokenExchangeRequest,
} from "./auth";
import {
	createMessage,
	createNonce,
	deleteMessage,
	getMessage,
	getMessagesByAuthor,
	updateMessage,
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

	// All scopes are allowed by default at the token endpoint
	const allowedScopes = [SCOPES.MESSAGES_READ, SCOPES.MESSAGES_WRITE];
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

// Discoverable OAuth endpoint for author messages
// Returns 401 with WWW-Authenticate challenge when unauthenticated
const authorsApi = new Hono<{
	Variables: { address: string; chainId: number; scopes: string[] };
}>();

authorsApi.get(
	"/:address/messages",
	createScopedAuthMiddleware("author-messages", [SCOPES.MESSAGES_READ]),
	(c) => {
		const authorAddress = c.req.param("address").toLowerCase();
		const messages = getMessagesByAuthor(authorAddress);
		return c.json({
			author: authorAddress,
			messages,
		});
	},
);

app.route("/api/authors", authorsApi);

// Protected API routes
const api = new Hono<{
	Variables: { address: string; chainId: number; scopes: string[] };
}>();
api.use("*", authMiddleware);

api.get("/messages", (c) => {
	// Return only the authenticated user's messages
	const address = c.get("address");
	const messages = getMessagesByAuthor(address);
	return c.json(messages);
});

api.get("/messages/:id", (c) => {
	const id = parseInt(c.req.param("id"), 10);
	const message = getMessage(id);
	if (!message) {
		return c.json({ error: "Message not found" }, 404);
	}
	return c.json(message);
});

api.post("/messages", async (c) => {
	const body = await c.req.json<{ content: string }>();
	const author = c.get("address");

	if (!body.content?.trim()) {
		return c.json({ error: "Content is required" }, 400);
	}

	const message = createMessage(body.content.trim(), author);
	return c.json(message, 201);
});

api.put("/messages/:id", async (c) => {
	const id = parseInt(c.req.param("id"), 10);
	const body = await c.req.json<{ content: string }>();
	const author = c.get("address");

	if (!body.content?.trim()) {
		return c.json({ error: "Content is required" }, 400);
	}

	const message = updateMessage(id, body.content.trim(), author);
	if (!message) {
		return c.json({ error: "Message not found or not authorized" }, 404);
	}
	return c.json(message);
});

api.delete("/messages/:id", (c) => {
	const id = parseInt(c.req.param("id"), 10);
	const author = c.get("address");

	const deleted = deleteMessage(id, author);
	if (!deleted) {
		return c.json({ error: "Message not found or not authorized" }, 404);
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
