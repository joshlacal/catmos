/**
 * Type declarations for the catbird-mls-web WASM package.
 *
 * Vite resolves `import ... from 'catbird-mls-web'` to
 * `../catbird-mls-web/pkg/catbird_mls_web.js` via its alias config in
 * `vite.config.ts`. svelte-check / tsserver does NOT follow Vite aliases,
 * so this ambient module declaration hand-mirrors the wasm-bindgen exports.
 *
 * Preserved from the pre-task-#45 `catmos-web.d.ts` shim during the port
 * from `catmos-web` to `catbird-mls-web`. Update when new functions are
 * added to the Rust WASM crate.
 *
 * Known drift between this shim and the generated `pkg/catbird_mls_web.d.ts`:
 *   - `catbird_mls_update_cursor`: declared here but not currently exported
 *     by the WASM module. Caller in `mls-worker.ts` still invokes it.
 *   - `catbird_mls_subscribe`: declared with 5 args; WASM exports 4.
 * Both are pre-existing bugs to reconcile against the live WASM API in a
 * follow-up, together with the `mls-worker.ts` call sites.
 */
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
