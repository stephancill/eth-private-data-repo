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
import {
	createMessage,
	deleteMessage,
	fetchMessages,
	type Message,
	updateMessage,
} from "./api";
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

	const [newContent, setNewContent] = useState("");
	const [editingId, setEditingId] = useState<number | null>(null);
	const [editContent, setEditContent] = useState("");

	// Clear auth when disconnected
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
			// Switch to mainnet for SIWE signature
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
		data: messages,
		isLoading,
		error,
	} = useQuery({
		queryKey: ["messages"],
		queryFn: fetchMessages,
		enabled: isAuthenticated,
	});

	const createMutation = useMutation({
		mutationFn: createMessage,
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["messages"] });
			setNewContent("");
		},
	});

	const updateMutation = useMutation({
		mutationFn: ({ id, content }: { id: number; content: string }) =>
			updateMessage(id, content),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["messages"] });
			setEditingId(null);
			setEditContent("");
		},
	});

	const deleteMutation = useMutation({
		mutationFn: deleteMessage,
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["messages"] });
		},
	});

	const handleCreate = (e: React.FormEvent) => {
		e.preventDefault();
		if (newContent.trim()) {
			createMutation.mutate(newContent);
		}
	};

	const handleUpdate = (e: React.FormEvent) => {
		e.preventDefault();
		if (editingId && editContent.trim()) {
			updateMutation.mutate({ id: editingId, content: editContent });
		}
	};

	const startEdit = (message: Message) => {
		setEditingId(message.id);
		setEditContent(message.content);
	};

	const cancelEdit = () => {
		setEditingId(null);
		setEditContent("");
	};

	// Not connected
	if (!isConnected) {
		return (
			<div style={{ maxWidth: 600, margin: "0 auto", padding: 20 }}>
				<h1>Messages</h1>
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

	// Connected but not authenticated
	if (!isAuthenticated) {
		return (
			<div style={{ maxWidth: 600, margin: "0 auto", padding: 20 }}>
				<h1>Messages</h1>
				<p>Connected: {address}</p>
				<button type="button" onClick={handleSignIn} disabled={isSigningIn}>
					{isSigningIn ? "Signing..." : "Sign In with Ethereum"}
				</button>
				<button type="button" onClick={() => disconnect()}>
					Disconnect
				</button>
				{authError && <p style={{ color: "red" }}>{authError}</p>}
			</div>
		);
	}

	// Authenticated
	return (
		<div style={{ maxWidth: 600, margin: "0 auto", padding: 20 }}>
			<h1>Messages</h1>
			<p>
				Signed in as: {address}
				<button
					type="button"
					onClick={handleSignOut}
					style={{ marginLeft: 10 }}
				>
					Sign Out
				</button>
			</p>

			<form onSubmit={handleCreate}>
				<input
					type="text"
					value={newContent}
					onChange={(e) => setNewContent(e.target.value)}
					placeholder="New message..."
					style={{ width: "100%", padding: 8, marginBottom: 8 }}
				/>
				<button type="submit" disabled={createMutation.isPending}>
					{createMutation.isPending ? "Adding..." : "Add Message"}
				</button>
			</form>

			<hr style={{ margin: "20px 0" }} />

			{isLoading && <p>Loading...</p>}
			{error && (
				<p style={{ color: "red" }}>Error: {(error as Error).message}</p>
			)}
			{messages?.length === 0 && <p>No messages yet.</p>}

			<ul style={{ listStyle: "none", padding: 0 }}>
				{messages?.map((message) => (
					<li
						key={message.id}
						style={{
							padding: 10,
							marginBottom: 8,
							border: "1px solid #333",
						}}
					>
						{editingId === message.id ? (
							<form onSubmit={handleUpdate}>
								<input
									type="text"
									value={editContent}
									onChange={(e) => setEditContent(e.target.value)}
									style={{ width: "100%", padding: 8, marginBottom: 8 }}
								/>
								<button type="submit" disabled={updateMutation.isPending}>
									Save
								</button>
								<button type="button" onClick={cancelEdit}>
									Cancel
								</button>
							</form>
						) : (
							<>
								<div>{message.content}</div>
								<small style={{ opacity: 0.6 }}>
									{new Date(message.created_at).toLocaleString()}
								</small>
								<div style={{ marginTop: 8 }}>
									<button type="button" onClick={() => startEdit(message)}>
										Edit
									</button>
									<button
										type="button"
										onClick={() => deleteMutation.mutate(message.id)}
										disabled={deleteMutation.isPending}
									>
										Delete
									</button>
								</div>
							</>
						)}
					</li>
				))}
			</ul>
		</div>
	);
}

export default App;
