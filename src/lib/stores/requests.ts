import { writable, get } from 'svelte/store';
import * as api from '$lib/wasm';
import type { DirectRequestView, RequestDraft, GroupInvitationReference } from '$lib/request-types';

export interface RequestState {
  ownerDid: string | null; deliveryEnabled: boolean | null; notice: string | null; views: DirectRequestView[]; drafts: RequestDraft[];
  pane: 'none' | 'inbox' | 'draft' | 'request'; selectedId: string | null;
  loading: boolean; busy: boolean; error: string | null;
}
const empty = (): RequestState => ({ ownerDid: null, deliveryEnabled: null, notice: null, views: [], drafts: [], pane: 'none', selectedId: null, loading: false, busy: false, error: null });
function newer(old: DirectRequestView | undefined, incoming: DirectRequestView): DirectRequestView {
  if (!old) return incoming;
  if (old.consent === 'closed') return old;
  if (old.generation > incoming.generation || (old.generation === incoming.generation && old.stateVersion > incoming.stateVersion)) return old;
  if (old.consent === 'accepted' && incoming.consent !== 'accepted' && incoming.consent !== 'closed') return old;
  if (old.firstMessageId && incoming.firstMessageId && old.firstMessageId !== incoming.firstMessageId) return old;
  return incoming;
}
export function createRequestsStore() {
  const store = writable<RequestState>(empty());
  let epoch = 0;
  let authRevision: string | undefined;
  const saves = new Map<string, Promise<void>>();
  const active = (owner: string, revision: number) => get(store).ownerDid === owner && epoch === revision;
  const mergeView = (view: DirectRequestView) => store.update(s => ({ ...s, views: [...s.views.filter(v => v.conversationId !== view.conversationId), newer(s.views.find(v => v.conversationId === view.conversationId), view)] }));
  const mergeDraft = (draft: RequestDraft) => store.update(s => ({ ...s, drafts: [...s.drafts.filter(d => d.input.draftId !== draft.input.draftId), draft] }));
  async function operation(work: (owner: string) => Promise<void>) {
    const state=get(store); if (!state.ownerDid || state.busy) return;
    const owner=state.ownerDid, revision=epoch;
    store.update(s=>({...s,busy:true,error:null,notice:null}));
    try { await work(owner); } catch(e) { if(active(owner,revision)) store.update(s=>({...s,error:e instanceof Error?e.message:String(e)})); }
    finally { if(active(owner,revision)) store.update(s=>({...s,busy:false})); }
  }
  async function persistDraft(owner: string, revision: number, updated: RequestDraft) {
    const id=updated.input.draftId;
    const save=(saves.get(id) ?? Promise.resolve()).then(async()=>{
      if(!active(owner,revision))return;
      try { const saved=await api.saveRequestDraft(owner,updated.input,updated.recipientLabel,authRevision); if(active(owner,revision) && JSON.stringify(get(store).drafts.find(d=>d.input.draftId===id)?.input)===JSON.stringify(updated.input))mergeDraft(saved); }
      catch(e){if(active(owner,revision))store.update(s=>({...s,error:String(e)}));}
    });
    saves.set(id,save);await save;
  }
  async function load() {
    const owner=get(store).ownerDid, revision=epoch; if(!owner || !api.requestBackendAvailable) return;
    store.update(s=>({...s,loading:true}));
    try {
      const value=await api.getRequestWorkspace(owner,authRevision); if(!active(owner,revision) || value.ownerDid!==owner) return;
      store.update(s=>({...s,notice:value.discoveryError ?? null,deliveryEnabled:value.deliveryEnabled ?? null,drafts:[...s.drafts.filter(local=>!value.drafts.some(saved=>saved.input.draftId===local.input.draftId)),...value.drafts.map(saved=>{const local=s.drafts.find(d=>d.input.draftId===saved.input.draftId);return local?.phase==='draft'&&saved.phase==='draft'?local:saved;})],views:value.requests.reduce((all,v)=>{const previous=all.find(x=>x.conversationId===v.conversationId);return [...all.filter(x=>x.conversationId!==v.conversationId),newer(previous,v)];},s.views),loading:false}));
    } catch(e) { if(active(owner,revision)) store.update(s=>({...s,loading:false,error:String(e)})); }
  }
  return {
    subscribe: store.subscribe,
    bindAccount(ownerDid: string | null, revision?: string) { if(get(store).ownerDid===ownerDid && authRevision===revision)return; authRevision=revision; epoch++; saves.clear(); store.set({...empty(),ownerDid}); },
    load,
    showInbox() { store.update(s=>({...s,pane:'inbox',selectedId:null,error:null})); },
    hide() { store.update(s=>({...s,pane:'none',selectedId:null,error:null})); },
    selectDraft(id: string) { store.update(s=>({...s,pane:'draft',selectedId:id,error:null})); },
    selectRequest(id: string) { store.update(s=>({...s,pane:'request',selectedId:id,error:null})); },
    begin(recipientDid: string, recipientLabel: string, text='', invitation?: GroupInvitationReference) {
      const s=get(store); if(!s.ownerDid || s.ownerDid===recipientDid)return;
      let existing=s.drafts.find(d=>!d.archived && d.input.recipientDid===recipientDid && (d.phase==='draft'||d.phase==='attempted'||d.phase==='checking'||d.outcome?.type==='retryable'));
      if(existing?.phase==='draft' && invitation && !existing.input.invitation){existing={...existing,input:{...existing.input,invitation,text:existing.input.text||text}};mergeDraft(existing);if(api.requestBackendAvailable)void persistDraft(s.ownerDid,epoch,existing);}
      if(existing && invitation && JSON.stringify(existing.input.invitation)!==JSON.stringify(invitation)){store.update(s=>({...s,pane:'draft',selectedId:existing.input.draftId,error:'The group invitation is separate. This saved request already has its own content; no invitation note was sent.'}));return false;}
      const draft=existing ?? {input:{draftId:crypto.randomUUID(),recipientDid,text,invitation},recipientLabel,phase:'draft' as const,outcome:null,archived:false};
      mergeDraft(draft); store.update(s=>({...s,pane:'draft',selectedId:draft.input.draftId,error:null}));
      if(!existing && api.requestBackendAvailable) void persistDraft(s.ownerDid,epoch,draft);
      return true;
    },
    async saveText(id: string, text: string) {
      const s=get(store), owner=s.ownerDid, revision=epoch;
      const draft=s.drafts.find(d=>d.input.draftId===id); if(!owner || !draft || draft.phase!=='draft')return;
      const updated={...draft,input:{...draft.input,text}}; mergeDraft(updated);
      if(!api.requestBackendAvailable)return;
      await persistDraft(owner,revision,updated);
    },
    async send(id: string) { await operation(async owner=>{
      const revision=epoch, draft=get(store).drafts.find(d=>d.input.draftId===id); if(!draft)return;
      await saves.get(id); if(!active(owner,revision))return;
      const persisted=await api.saveRequestDraft(owner,draft.input,draft.recipientLabel,authRevision); if(!active(owner,revision))return;
      mergeDraft({...persisted,phase:'attempted'});
      try {
        const result=await api.submitRequestDraft(owner,id,authRevision); if(!active(owner,revision))return;
        mergeDraft(result); await load();
      } catch (error) {
        // Read the host's durable phase without remote inventory. A verified
        // terminal refusal is editable; ambiguous delivery remains immutable.
        if(active(owner,revision))try {
          const current=await api.saveRequestDraft(owner,draft.input,draft.recipientLabel,authRevision);
          if(active(owner,revision))mergeDraft(current);
        } catch {}
        throw error;
      }
    }); },
    async resume(id: string) { await operation(async owner=>{
      const revision=epoch, draft=get(store).drafts.find(d=>d.input.draftId===id);
      try {
        const result=await api.resumeRequestDraft(owner,id,authRevision);
        if(active(owner,revision)){mergeDraft(result);await load();}
      } catch(error) {
        if(active(owner,revision)&&draft)try {
          const current=await api.saveRequestDraft(owner,draft.input,draft.recipientLabel,authRevision);
          if(active(owner,revision))mergeDraft(current);
        } catch {}
        throw error;
      }
    }); },
    async cancel(id: string) { await operation(async owner=>{const revision=epoch; const draft=get(store).drafts.find(d=>d.input.draftId===id);if(!draft)return;
      if(draft.phase==='draft'&&!api.requestBackendAvailable){mergeDraft({...draft,archived:true});store.update(s=>({...s,pane:'inbox'}));return;}
      await api.saveRequestDraft(owner,draft.input,draft.recipientLabel,authRevision);if(!active(owner,revision))return;const result=await api.cancelRequestDraft(owner,id,authRevision);if(active(owner,revision)){mergeDraft(result);if(result.archived)store.update(s=>({...s,pane:'inbox'}));}
    }); },
    async sendInvitationNote(id:string) { await operation(async owner=>{const revision=epoch;try {const draft=await api.sendExistingInvitationNote(owner,id,authRevision);if(active(owner,revision))mergeDraft(draft);} finally {if(active(owner,revision))await load();}}); },
    async refresh(id:string) { await operation(async owner=>{const revision=epoch;const view=await api.refreshDirectRequest(owner,id,authRevision);if(active(owner,revision))mergeView(view);}); },
    async accept(id:string) { await operation(async owner=>{const revision=epoch;const view=await api.acceptDirectRequest(owner,id,authRevision);if(active(owner,revision)){mergeView(view);try{const {conversations}=await import("./conversations");await conversations.load();}catch(e){console.warn("[catmos] conversations.load after accept failed:",e);}}}); },
    async close(id:string) { await operation(async owner=>{const revision=epoch;const view=await api.closeDirectRequest(owner,id,authRevision);if(active(owner,revision))mergeView(view);}); },
    async block(id:string) { await operation(async owner=>{const revision=epoch;await api.blockRequestSender(owner,id,authRevision);if(active(owner,revision))store.update(s=>({...s,notice:'Sender blocked. You can close this request separately.'}));}); },
    async setDeliveryEnabled(enabled: boolean) { await operation(async owner => {const revision=epoch;await api.setRequestDeliveryEnabled(owner, enabled,authRevision);if(active(owner,revision))store.update(s=>({...s,deliveryEnabled:enabled,notice:enabled?'Encrypted request delivery enabled for this device.':'New request delivery turned off for this device.'})); }); },
    applyView(owner:string,view:DirectRequestView) { if(get(store).ownerDid===owner)mergeView(view); },
    canUseOrdinaryActivity(id:string) { const view=get(store).views.find(v=>v.conversationId===id);return !view || (view.consent==='accepted'&&view.capabilities.canSend&&view.capabilities.canEmitReceipts); }
  };
}
export const requests=createRequestsStore();
