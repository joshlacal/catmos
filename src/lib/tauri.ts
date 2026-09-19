import { invoke } from '@tauri-apps/api/core';

export interface Conversation {
  pendingConsent?: boolean;
	id: string;
	/** Current MLS group identifier (hex). Changes on group reset. */
	groupId: string;
	displayName: string;
	description?: string;
	members: string[];
	/** Immutable projection kind from the browser/WASM conversation API. */
	conversationKind?: 'direct' | 'group' | string;
	/** Server MemberView roster, including creator and role. */
	memberViews?: ConversationMember[];
	lastMessage?: string;
	lastMessageAt?: string;
	unreadCount: number;
	isGroup: boolean;
	mutedUntil?: string;
	/**
	 * Decrypted avatar rendered as a `data:` URL by the Tauri backend after
	 * `bootstrap_group_metadata` succeeds. Frontend embeds it directly into
	 * an `<img src>`. `undefined` means the group has no avatar (or
	 * bootstrap hasn't run yet).
	 */
	avatarDataUrl?: string;
}

export interface ConversationMember {
	did: string;
	role: 'admin' | 'member' | string;
}

export interface Message {
	id: string;
	conversationId: string;
	senderDid: string;
	senderHandle: string;
	content: string;
	timestamp: string;
	/** Canonical conversation sequence; absent or zero means not yet confirmed. */
	sequenceNumber?: number;
	status: 'sending' | 'sent' | 'delivered' | 'read' | 'failed';
	messageType?: 'text' | 'image' | 'voice' | 'system' | 'event';
	image?: ImageAttachment;
	groupInvitation?: import("./request-types").GroupInvitationReference;
	audioAttachment?: AudioAttachment;
	reactions?: Record<string, string[]>;
}

export interface ImageAttachment {
	blobId: string;
	keyB64: string;
	ivB64: string;
	sha256: string;
	contentType: string;
	size: number;
	width: number;
	height: number;
	altText?: string;
	blurhash?: string;
	localUrl?: string;
}

export interface AudioAttachment {
	blobId: string;
	key: Uint8Array;
	iv: Uint8Array;
	sha256: string;
	contentType: string;
	size: number;
	durationMs: number;
	waveform: number[];
	transcript?: string;
}

export interface PreparedImageUpload {
	data: Uint8Array;
	contentType: string;
	width: number;
	height: number;
	altText?: string;
	previewUrl?: string;
}

export interface ReactionEvent {
	conversationId: string;
	messageId: string;
	senderDid: string;
	emoji: string;
	action: 'add' | 'remove';
}

export interface TypingEvent {
	conversationId: string;
	senderDid: string;
	isTyping: boolean;
}

export interface GroupResetEvent {
	convoId: string;
	newGroupId: string;
	resetGeneration: number;
	resetBy: string;
	reason?: string;
}

export interface AuthState {
	did: string;
	handle: string;
	displayName?: string;
	avatar?: string;
}

export interface GroupMember {
	did: string;
	handle: string;
	displayName?: string;
	role: 'admin' | 'member';
	pendingConsent?: boolean;
}

export interface ProfileView {
	did: string;
	handle: string;
	displayName?: string;
	avatar?: string;
}

export async function startLogin(identifier: string): Promise<void> {
	return invoke('start_login', { identifier });
}

export async function completeLogin(sessionId: string): Promise<AuthState> {
	return invoke('complete_login', { sessionId });
}

export async function tryRestoreSession(): Promise<AuthState | null> {
	return invoke('try_restore_session');
}

export async function logout(): Promise<void> {
	return invoke('logout');
}

export async function getConversations(): Promise<Conversation[]> {
	return invoke('get_conversations');
}

export async function createGroup(
	name: string,
	memberDids: string[],
	description?: string
): Promise<Conversation> {
	return invoke('create_group', { name, memberDids, description });
}

export async function sendMessage(conversationId: string, content: string): Promise<Message> {
	return invoke('send_message', { conversationId, content });
}

export async function sendImage(
	conversationId: string,
	content: string,
	data: Uint8Array,
	contentType: string,
	width: number,
	height: number,
	altText?: string
): Promise<Message> {
	return invoke('send_image', {
		conversationId,
		content,
		data: Array.from(data),
		contentType,
		width,
		height,
		altText
	});
}

export async function getMessages(conversationId: string, before?: string): Promise<Message[]> {
	return invoke('get_messages', { conversationId, before });
}

export async function getImageAttachment(image: ImageAttachment, conversationId: string): Promise<string> {
	return invoke('get_image_attachment', {
        conversationId,
		blobId: image.blobId,
		keyB64: image.keyB64,
		ivB64: image.ivB64,
		sha256: image.sha256,
		contentType: image.contentType
	});
}

export async function getGroupMembers(conversationId: string): Promise<GroupMember[]> {
	return invoke('get_group_members', { conversationId });
}

export async function subscribeConversation(conversationId: string): Promise<void> {
	return invoke('subscribe_conversation', { conversationId });
}

export async function unsubscribeConversation(conversationId: string): Promise<void> {
	return invoke('unsubscribe_conversation', { conversationId });
}

export async function subscribeAllEvents(): Promise<void> {
	return invoke('subscribe_all_events');
}

export async function unsubscribeAllEvents(): Promise<void> {
	return invoke('unsubscribe_all_events');
}

export async function fetchNewMessages(conversationId: string): Promise<Message[]> {
	return invoke('fetch_new_messages', { conversationId });
}

export async function getProfiles(dids: string[]): Promise<ProfileView[]> {
	return invoke('get_profiles', { dids });
}

export async function sendReaction(
	conversationId: string,
	messageId: string,
	emoji: string,
	action: 'add' | 'remove'
): Promise<void> {
	return invoke('send_reaction', { conversationId, messageId, emoji, action });
}

export async function sendTyping(conversationId: string, isTyping: boolean): Promise<void> {
	return invoke('send_typing', { conversationId, isTyping });
}

export async function updateCursor(
	conversationId: string,
	cursor: string
): Promise<void> {
	return invoke('update_cursor', { conversationId, cursor });
}

export interface SearchResult {
	did: string;
	handle: string;
	displayName?: string;
	avatar?: string;
}

export interface OptInStatus {
	did: string;
	optedIn: boolean;
}

export async function searchUsers(query: string): Promise<SearchResult[]> {
	return invoke('search_users', { query });
}

export async function checkOptInStatus(dids: string[]): Promise<OptInStatus[]> {
	return invoke('check_opt_in_status', { dids });
}

export async function promoteMember(conversationId: string, targetDid: string): Promise<void> {
	return invoke('promote_member', { conversationId, targetDid });
}

export async function demoteMember(conversationId: string, targetDid: string): Promise<void> {
	return invoke('demote_member', { conversationId, targetDid });
}

export async function removeGroupMember(conversationId: string, targetDid: string): Promise<void> {
	return invoke('remove_group_member', { conversationId, targetDid });
}

export interface SearchHit {
	messageId: string;
	conversationId: string;
	conversationName: string;
	senderDid: string;
	content: string;
	timestamp: string;
}

export interface GroupMetadataView {
	name?: string;
	description?: string;
	avatarHash?: string;
}

export async function getGroupMetadata(
	conversationId: string
): Promise<GroupMetadataView | null> {
	return invoke('get_group_metadata', { conversationId });
}

export async function updateGroupMetadata(
	conversationId: string,
	name?: string,
	description?: string,
	avatarBlobLocator?: string,
	avatarContentType?: string
): Promise<void> {
	return invoke('update_group_metadata', {
		conversationId,
		name,
		description,
		avatarBlobLocator,
		avatarContentType
	});
}

export async function reportSpam(
	conversationId: string,
	reportedDid: string,
	reason?: string
): Promise<void> {
	return invoke('report_spam', { conversationId, reportedDid, reason });
}

// ── Layer 3 quarantine ───────────────────────────────────────────────────────
// Wire format mirrors the Rust serde camelCase output from
// `quarantine_observer::QuarantineEnteredPayload` /
// `commands::QuarantineStateView`.

export type QuarantineReasonTag =
	| 'peer_bad_commit'
	| 'multi_peer_bad_commits'
	| 'repeated_framing_failures';

export type QuarantineExitTag =
	| 'peer_commit_succeeded'
	| 'server_reset'
	| 'user_confirmed_reset';

export interface QuarantineEnteredEvent {
	convoId: string;
	reasonTag: QuarantineReasonTag;
	suspectedDids: string[];
}

export interface QuarantineClearedEvent {
	convoId: string;
	viaTag: QuarantineExitTag;
}

export interface QuarantineState {
	reasonTag: QuarantineReasonTag;
	sinceMs: number;
	suspectedDids: string[];
}

export async function getQuarantineState(
	conversationId: string
): Promise<QuarantineState | null> {
	return invoke('get_quarantine_state', { conversationId });
}

export async function confirmManualReset(conversationId: string): Promise<void> {
	return invoke('confirm_manual_reset', { conversationId });
}
