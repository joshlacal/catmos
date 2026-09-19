/** Handwritten UI projections of the shared Rust request facade; never consent authority. */
export interface GroupInvitationReference {
  authorityDid: string; conversationId: string; invitationTransitionId: string;
  invitedByDid: string; invitedByDeviceId: string; recipientDid: string;
}
export interface DirectRequestInput { draftId: string; recipientDid: string; text: string; invitation?: GroupInvitationReference | null }
export type DirectRequestOutcome =
  | { type: 'requestSent'; conversationId: string; messageId: string; requestId: string }
  | { type: 'outcomeUnknown'; requestId: string }
  | { type: 'existingDirect'; conversationId: string; requiresAcceptance: boolean }
  | { type: 'retryable'; code: string }
  | { type: 'terminalNotPublished'; requestId: string; code: string };
export interface DirectRequestView {
  conversationId: string; firstMessageId?: string | null;
  introduction?: { senderDid: string; senderDeviceId: string; receivedAt: string; epoch: number; sequenceNumber: number } | null;
  consent: 'incomingPending' | 'outgoingPending' | 'accepted' | 'closed';
  crypto: 'welcomeAvailable' | 'importing' | 'ready' | 'unavailable';
  preview?: { type: 'ready'; text: string; invitation?: GroupInvitationReference | null } | { type: 'unavailable'; code: string } | null;
  capabilities: { canPreview: boolean; canAccept: boolean; canClose: boolean; canSend: boolean; canEmitReceipts: boolean; canAdminister: boolean };
  stateVersion: number; generation: number;
}
export interface RequestDraft { input: DirectRequestInput; recipientLabel: string; phase: 'draft' | 'attempted' | 'checking' | 'resolved'; outcome?: DirectRequestOutcome | null; archived: boolean }
export interface RequestWorkspace { ownerDid: string; deliveryEnabled?: boolean | null; drafts: RequestDraft[]; requests: DirectRequestView[] }
