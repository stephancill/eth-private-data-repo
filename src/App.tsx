import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
	useAccount,
	useConnect,
	useDisconnect,
	useSignMessage,
	useSwitchChain,
} from "wagmi";
import { mainnet } from "wagmi/chains";
import { deleteKey, fetchKeys, type KeyValueEntry, upsertKey } from "./api";
import {
	buildSiweMessage,
	clearToken,
	exchangeSignatureForToken,
	fetchNonce,
	getToken,
	setToken,
} from "./auth";

function App() {
	const queryClient = useQueryClient();
	const { address, isConnected } = useAccount();
	const { connect, connectors } = useConnect();
	const { disconnect } = useDisconnect();
	const { signMessageAsync } = useSignMessage();
	const { switchChainAsync } = useSwitchChain();

	const [isAuthenticated, setIsAuthenticated] = useState(!!getToken());
	const [authError, setAuthError] = useState<string | null>(null);
	const [isSigningIn, setIsSigningIn] = useState(false);

	const [newKey, setNewKey] = useState("");
	const [newValue, setNewValue] = useState("");
	const [newIsPublic, setNewIsPublic] = useState(false);
	const [editingKey, setEditingKey] = useState<string | null>(null);
	const [editValue, setEditValue] = useState("");
	const [editIsPublic, setEditIsPublic] = useState(false);
	const [formError, setFormError] = useState<string | null>(null);

	useEffect(() => {
		if (!isConnected) {
			clearToken();
			setIsAuthenticated(false);
			queryClient.clear();
		}
	}, [isConnected, queryClient]);

	const handleSignIn = async () => {
		if (!address) return;
		setIsSigningIn(true);
		setAuthError(null);

		try {
			await switchChainAsync({ chainId: mainnet.id });
			const nonce = await fetchNonce();
			const message = buildSiweMessage({
				address,
				chainId: mainnet.id,
				nonce,
			});
			const signature = await signMessageAsync({ message });
			const token = await exchangeSignatureForToken(message, signature);
			setToken(token);
			setIsAuthenticated(true);
		} catch (e) {
			setAuthError(e instanceof Error ? e.message : "Sign in failed");
		} finally {
			setIsSigningIn(false);
		}
	};

	const handleSignOut = () => {
		clearToken();
		setIsAuthenticated(false);
		queryClient.clear();
		disconnect();
	};

	const {
		data: keys,
		isLoading,
		error,
	} = useQuery({
		queryKey: ["keys"],
		queryFn: fetchKeys,
		enabled: isAuthenticated,
	});

	const upsertMutation = useMutation({
		mutationFn: ({
			key,
			value,
			isPublic,
		}: {
			key: string;
			value: unknown;
			isPublic: boolean;
		}) => upsertKey(key, value, isPublic),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["keys"] });
			setNewKey("");
			setNewValue("");
			setNewIsPublic(false);
			setEditingKey(null);
			setFormError(null);
		},
		onError: (e) => {
			setFormError(e instanceof Error ? e.message : "Failed to save");
		},
	});

	const deleteMutation = useMutation({
		mutationFn: deleteKey,
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["keys"] });
		},
	});

	const parseJsonValue = (str: string): unknown => {
		try {
			return JSON.parse(str);
		} catch {
			return str;
		}
	};

	const handleCreate = (e: React.FormEvent) => {
		e.preventDefault();
		setFormError(null);
		if (newKey.trim()) {
			upsertMutation.mutate({
				key: newKey.trim(),
				value: parseJsonValue(newValue),
				isPublic: newIsPublic,
			});
		}
	};

	const handleUpdate = (e: React.FormEvent) => {
		e.preventDefault();
		setFormError(null);
		if (editingKey) {
			upsertMutation.mutate({
				key: editingKey,
				value: parseJsonValue(editValue),
				isPublic: editIsPublic,
			});
		}
	};

	const startEdit = (entry: KeyValueEntry) => {
		setEditingKey(entry.key);
		setEditValue(
			typeof entry.value === "string"
				? entry.value
				: JSON.stringify(entry.value, null, 2),
		);
		setEditIsPublic(entry.isPublic);
		setFormError(null);
	};

	const cancelEdit = () => {
		setEditingKey(null);
		setEditValue("");
		setEditIsPublic(false);
		setFormError(null);
	};

	const formatValue = (value: unknown): string => {
		if (typeof value === "string") return value;
		return JSON.stringify(value, null, 2);
	};

	if (!isConnected) {
		return (
			<div style={{ maxWidth: 600, margin: "0 auto", padding: 20 }}>
				<h1>Key-Value Store</h1>
				<p>Connect your wallet to sign in.</p>
				{connectors.map((connector) => (
					<button
						type="button"
						key={connector.uid}
						onClick={() => connect({ connector })}
					>
						Connect {connector.name}
					</button>
				))}
			</div>
		);
	}

	if (!isAuthenticated) {
		return (
			<div style={{ maxWidth: 600, margin: "0 auto", padding: 20 }}>
				<h1>Key-Value Store</h1>
				<p>Connected: {address}</p>
				<button type="button" onClick={handleSignIn} disabled={isSigningIn}>
					{isSigningIn ? "Signing..." : "Sign In with Ethereum"}
				</button>{" "}
				<button type="button" onClick={() => disconnect()}>
					Disconnect
				</button>
				{authError && <p style={{ color: "red" }}>{authError}</p>}
			</div>
		);
	}

	return (
		<div style={{ maxWidth: 600, margin: "0 auto", padding: 20 }}>
			<h1>Key-Value Store</h1>
			<p>
				Signed in as: <code>{address}</code>{" "}
				<button type="button" onClick={handleSignOut}>
					Sign Out
				</button>
			</p>

			<h3>Add New Key</h3>
			<form onSubmit={handleCreate}>
				<div style={{ marginBottom: 8 }}>
					<input
						type="text"
						value={newKey}
						onChange={(e) => setNewKey(e.target.value)}
						placeholder="Key (e.g., profile, settings)"
					/>
				</div>
				<div style={{ marginBottom: 8 }}>
					<textarea
						value={newValue}
						onChange={(e) => setNewValue(e.target.value)}
						placeholder="Value (JSON or text)"
						rows={3}
					/>
				</div>
				<div style={{ marginBottom: 8 }}>
					<label>
						<input
							type="checkbox"
							checked={newIsPublic}
							onChange={(e) => setNewIsPublic(e.target.checked)}
						/>{" "}
						Public
					</label>
				</div>
				<button
					type="submit"
					disabled={upsertMutation.isPending || !newKey.trim()}
				>
					{upsertMutation.isPending ? "Saving..." : "Save"}
				</button>
			</form>
			{formError && !editingKey && <p style={{ color: "red" }}>{formError}</p>}

			<hr />

			<h3>Your Keys</h3>
			{isLoading && <p>Loading...</p>}
			{error && (
				<p style={{ color: "red" }}>Error: {(error as Error).message}</p>
			)}
			{keys?.length === 0 && <p style={{ opacity: 0.6 }}>No keys yet.</p>}

			{keys?.map((entry) => (
				<div
					key={entry.key}
					style={{ marginBottom: 16, padding: 12, border: "1px solid #333" }}
				>
					{editingKey === entry.key ? (
						<form onSubmit={handleUpdate}>
							<div style={{ marginBottom: 8 }}>
								<strong>{entry.key}</strong>
							</div>
							<div style={{ marginBottom: 8 }}>
								<textarea
									value={editValue}
									onChange={(e) => setEditValue(e.target.value)}
									rows={4}
								/>
							</div>
							<div style={{ marginBottom: 8 }}>
								<label>
									<input
										type="checkbox"
										checked={editIsPublic}
										onChange={(e) => setEditIsPublic(e.target.checked)}
									/>{" "}
									Public
								</label>
							</div>
							{formError && <p style={{ color: "red" }}>{formError}</p>}
							<button type="submit" disabled={upsertMutation.isPending}>
								{upsertMutation.isPending ? "Saving..." : "Save"}
							</button>{" "}
							<button type="button" onClick={cancelEdit}>
								Cancel
							</button>
						</form>
					) : (
						<>
							<div style={{ marginBottom: 8 }}>
								<strong>{entry.key}</strong>{" "}
								<small style={{ opacity: 0.6 }}>
									({entry.isPublic ? "public" : "private"})
								</small>
							</div>
							<pre style={{ marginBottom: 8 }}>{formatValue(entry.value)}</pre>
							{entry.isPublic && address && (
								<div
									style={{ marginBottom: 8, fontSize: "0.85em", opacity: 0.6 }}
								>
									URL: /user/{address.toLowerCase()}/{entry.key}
								</div>
							)}
							<button type="button" onClick={() => startEdit(entry)}>
								Edit
							</button>{" "}
							<button
								type="button"
								onClick={() => deleteMutation.mutate(entry.key)}
								disabled={deleteMutation.isPending}
							>
								Delete
							</button>
						</>
					)}
				</div>
			))}
		</div>
	);
}

export default App;
