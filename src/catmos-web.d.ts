/**
 * Type declarations for the catmos-web WASM package.
 *
 * These mirror the wasm-bindgen exports from catmos/catmos-web/src/.
 * Update this file when new functions are exposed from the Rust WASM crate.
 */
declare module 'catmos-web' {
	// wasm-pack default export: initializes the WASM binary before use.
	export default function init(): Promise<void>;

	// App-level init (sets up MLS context, credentials, API client).
	export function wasm_init(base_url: string): Promise<void>;

	import type {
		Conversation,
		Message,
		AuthState,
		GroupMember,
		ProfileView,
		SearchResult,
		OptInStatus
	} from '$lib/tauri';

	// Auth
	export function wasm_start_login(identifier: string): Promise<void>;
	export function wasm_complete_login(session_id: string): Promise<AuthState>;
	export function wasm_try_restore_session(): Promise<AuthState | null>;
	export function wasm_logout(): Promise<void>;

	// Conversations
	export function wasm_get_conversations(): Promise<Conversation[]>;
	export function wasm_create_group(name: string, member_dids: string[]): Promise<Conversation>;
	export function wasm_subscribe_conversation(conversation_id: string): Promise<void>;
	export function wasm_unsubscribe_conversation(conversation_id: string): Promise<void>;

	// Messages
	export function wasm_send_message(conversation_id: string, content: string): Promise<Message>;
	export function wasm_send_image(
		conversation_id: string,
		content: string,
		data: Uint8Array,
		content_type: string,
		width: number,
		height: number,
		alt_text?: string
	): Promise<Message>;
	export function wasm_get_messages(conversation_id: string, before?: string): Promise<Message[]>;
	export function wasm_fetch_new_messages(conversation_id: string): Promise<Message[]>;
	export function wasm_send_reaction(
		conversation_id: string,
		message_id: string,
		emoji: string,
		action: 'add' | 'remove'
	): Promise<void>;
	export function wasm_send_typing(conversation_id: string, is_typing: boolean): Promise<void>;
	export function wasm_update_cursor(conversation_id: string, cursor: string): Promise<void>;

	// Members
	export function wasm_get_group_members(conversation_id: string): Promise<GroupMember[]>;
	export function wasm_promote_member(conversation_id: string, target_did: string): Promise<void>;
	export function wasm_demote_member(conversation_id: string, target_did: string): Promise<void>;
	export function wasm_remove_group_member(
		conversation_id: string,
		target_did: string
	): Promise<void>;
	export function wasm_leave_conversation(conversation_id: string): Promise<void>;

	// Profiles & Search
	export function wasm_get_profiles(dids: string[]): Promise<ProfileView[]>;
	export function wasm_search_users(query: string): Promise<SearchResult[]>;
	export function wasm_check_opt_in_status(dids: string[]): Promise<OptInStatus[]>;

	// Group metadata
	export function wasm_get_group_metadata(conversation_id: string): Promise<unknown>;
	export function wasm_update_group_metadata(
		conversation_id: string,
		name: string | null,
		description: string | null,
		avatar_hash: string | null
	): Promise<void>;
}

declare module 'catbird-mls-web' {
	import type {
		AuthState,
		Conversation,
		GroupMember,
		Message,
		OptInStatus,
		ProfileView,
		SearchResult
	} from '$lib/tauri';

	export default function init(): Promise<void>;
	export function catbird_mls_init(config: object): Promise<void>;
	export function catbird_mls_set_auth(did: string, token: string): void;
	export function catbird_mls_clear_auth(): void;
	export function catbird_mls_setup(): Promise<void>;
	export function catbird_mls_replenish_key_packages(): Promise<void>;
	export function catbird_mls_ping(): string;
	export function catbird_mls_list_conversations(): Promise<Conversation[]>;
	export function catbird_mls_create_conversation(
		name: string,
		memberDids: string[]
	): Promise<Conversation>;
	export function catbird_mls_join_group(convoId: string): Promise<unknown>;
	export function catbird_mls_send_message(
		conversationId: string,
		content: string
	): Promise<Message>;
	export function catbird_mls_send_image(
		conversationId: string,
		content: string,
		data: Uint8Array,
		contentType: string,
		width: number,
		height: number,
		altText?: string
	): Promise<Message>;
	export function catbird_mls_messages(
		conversationId: string,
		before?: string
	): Promise<Message[]>;
	export function catbird_mls_get_image_attachment(
		blobId: string,
		keyB64: string,
		ivB64: string,
		sha256: string,
		contentType: string
	): Promise<string>;
	export function catbird_mls_fetch_new_messages(conversationId: string): Promise<Message[]>;
	export function catbird_mls_send_reaction(
		conversationId: string,
		messageId: string,
		emoji: string,
		action: string
	): Promise<void>;
	export function catbird_mls_update_cursor(
		conversationId: string,
		cursor: string
	): Promise<void>;
	export function catbird_mls_subscribe(
		conversationId: string,
		onMessage: (message: Message) => void,
		onEvent: (event: unknown) => void,
		onStatus: (status: unknown) => void,
		cursor?: string
	): Promise<{ close(): void } | null>;
	export function catbird_mls_get_members(conversationId: string): Promise<GroupMember[]>;
	export function catbird_mls_add_group_members(
		conversationId: string,
		memberDids: string[]
	): Promise<void>;
	export function catbird_mls_add_participants(
		conversationId: string,
		did: string
	): Promise<void>;
	export function catbird_mls_demote_member(
		conversationId: string,
		did: string
	): Promise<void>;
	export function catbird_mls_remove_participants(
		conversationId: string,
		did: string
	): Promise<void>;
	export function catbird_mls_leave_conversation(conversationId: string): Promise<void>;
	export function catbird_mls_get_profiles(dids: string[]): Promise<ProfileView[]>;
	export function catbird_mls_search_users(query: string): Promise<SearchResult[]>;
	export function catbird_mls_check_opt_in_status(dids: string[]): Promise<OptInStatus[]>;
	export function catbird_mls_get_group_metadata(conversationId: string): Promise<unknown>;
	export function catbird_mls_update_group_metadata(
		conversationId: string,
		name: string | null,
		description: string | null,
		avatarHash: string | null
	): Promise<void>;
	export function catbird_mls_send_typing(
		conversationId: string,
		isTyping: boolean
	): Promise<void>;
	export function catbird_mls_promote_member(
		conversationId: string,
		targetDid: string
	): Promise<void>;
}
