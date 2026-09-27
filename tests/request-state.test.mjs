// Real request store, transport replaced; does not prove MLS or server authority.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import { get, writable } from 'svelte/store';
const compiled=ts.transpileModule(await readFile(new URL('../src/lib/stores/requests.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
async function subject(overrides={}) {
 const context=vm.createContext({console,crypto:{randomUUID}});
 const api={requestBackendAvailable:true,getRequestWorkspace:async owner=>({ownerDid:owner,drafts:[],requests:[]}),saveRequestDraft:async(owner,input,recipientLabel)=>({input,recipientLabel,phase:'draft',archived:false}),submitRequestDraft:async()=>{throw Error('Unexpected send')},resumeRequestDraft:async()=>{throw Error('Unexpected resume')},cancelRequestDraft:async()=>{throw Error('Unexpected cancel')},refreshDirectRequest:async()=>{throw Error('Unexpected refresh')},acceptDirectRequest:async()=>{throw Error('Unexpected accept')},...overrides};
 const transport=new vm.SyntheticModule(Object.keys(api),function(){for(const [k,v]of Object.entries(api))this.setExport(k,v)},{context});
 const svelte=new vm.SyntheticModule(['writable','get'],function(){this.setExport('writable',writable);this.setExport('get',get)},{context});
 const module=new vm.SourceTextModule(compiled,{context});await module.link(name=>name==='svelte/store'?svelte:transport);await module.evaluate();const store=module.namespace.createRequestsStore();store.bindAccount('did:plc:alice');return store;
}
const view=(consent='incomingPending',version=1)=>({conversationId:'conversation',firstMessageId:'first',consent,crypto:'ready',preview:{type:'ready',text:'A private hello'},generation:0,stateVersion:version,capabilities:{canPreview:true,canAccept:consent==='incomingPending',canClose:true,canSend:consent==='accepted',canEmitReceipts:consent==='accepted',canAdminister:false}});
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {resolve,promise}};
function uncertain(){let attempted=false;return {
 saveRequestDraft:async(owner,input,recipientLabel)=>({input,recipientLabel,phase:attempted?'attempted':'draft',archived:false}),
 submitRequestDraft:async()=>{attempted=true;throw Error('Delivery uncertain')}
};}
test('contact selection remains local and first send reuses the saved immutable identity',async()=>{
 const calls=[];const store=await subject({submitRequestDraft:async(owner,id)=>{calls.push([owner,id]);return {...get(store).drafts[0],phase:'checking',outcome:{type:'outcomeUnknown',requestId:'request'}}},getRequestWorkspace:async owner=>({ownerDid:owner,drafts:get(store).drafts,requests:[]})});
 store.begin('did:plc:bob','Bob');assert.equal(calls.length,0);const id=get(store).selectedId;await store.saveText(id,'hello');await store.send(id);await store.send(id);assert.equal(calls.length,2);assert.equal(calls[0][1],calls[1][1]);assert.equal(get(store).drafts[0].input.text,'hello');assert.equal(get(store).drafts[0].phase,'checking');
});
test('double submit while waiting invokes transport only once',async()=>{
 const pending=deferred();let count=0;const store=await subject({submitRequestDraft:async()=>{count++;return pending.promise}});store.begin('did:plc:bob','Bob','hello');const id=get(store).selectedId;const first=store.send(id);for(let i=0;i<12&&count===0;i++)await Promise.resolve();await store.send(id);assert.equal(count,1);pending.resolve({...get(store).drafts[0],phase:'checking'});await first;
});
test('account switch drops delayed decrypted workspace and operation results',async()=>{
 const pending=deferred();const store=await subject({getRequestWorkspace:()=>pending.promise});const loading=store.load();store.bindAccount('did:plc:bob');pending.resolve({ownerDid:'did:plc:alice',drafts:[],requests:[view()]});await loading;assert.equal(get(store).ownerDid,'did:plc:bob');assert.equal(get(store).views.length,0);
 store.applyView('did:plc:alice',view());assert.equal(get(store).views.length,0);
});
test('acceptance and close cannot be rolled back by late pending events or omissions',async()=>{
 const store=await subject();store.applyView('did:plc:alice',view('accepted',2));store.applyView('did:plc:alice',view());assert.equal(get(store).views[0].consent,'accepted');await store.load();assert.equal(get(store).views[0].consent,'accepted');store.applyView('did:plc:alice',view('closed',3));store.applyView('did:plc:alice',view('accepted',8));assert.equal(get(store).views[0].consent,'closed');assert.equal(store.canUseOrdinaryActivity('conversation'),false);
});
test('first message identity cannot change during acceptance; repeated views deduplicate',async()=>{
 const store=await subject();store.applyView('did:plc:alice',view());store.applyView('did:plc:alice',view());store.applyView('did:plc:alice',{...view('accepted',2),firstMessageId:'other'});assert.equal(get(store).views.length,1);assert.equal(get(store).views[0].firstMessageId,'first');assert.equal(get(store).views[0].consent,'incomingPending');
});
test('unavailable encryption does not accept or synthesize a preview',async()=>{
 const store=await subject();store.applyView('did:plc:alice',{...view(),crypto:'unavailable',preview:{type:'unavailable',code:'missingKey'}});assert.equal(get(store).views[0].preview.type,'unavailable');assert.equal(get(store).views[0].consent,'incomingPending');assert.equal(store.canUseOrdinaryActivity('conversation'),false);
});
test('failed send keeps protected draft identity and disables editing until reconciled',async()=>{
 const store=await subject(uncertain());store.begin('did:plc:bob','Bob','original');const id=get(store).selectedId;await store.send(id);assert.equal(get(store).drafts[0].phase,'attempted');await store.saveText(id,'replacement');assert.equal(get(store).drafts[0].input.text,'original');assert.equal(get(store).drafts[0].input.draftId,id);
});
test('pre-intent authority refusal restores an editable draft in the open composer',async()=>{
 const store=await subject({
  submitRequestDraft:async()=>{throw Error('Direct request receipt authority resolution unavailable. No legacy delivery was attempted.')},
  getRequestWorkspace:async()=>{throw Error('Remote inventory unavailable')}
 });
 store.begin('did:plc:bob','Bob','original');const id=get(store).selectedId;
 await store.send(id);
 assert.equal(get(store).drafts[0].phase,'draft');
 assert.match(get(store).error,/receipt authority resolution unavailable/);
 await store.saveText(id,'replacement');
 assert.equal(get(store).drafts[0].input.text,'replacement');
});
test('terminal refusal on retry reopens the same draft without remote inventory',async()=>{
 let phase='draft', sends=0, inventory=0;
 const store=await subject({
  saveRequestDraft:async(owner,input,recipientLabel)=>({input,recipientLabel,phase,archived:false}),
  submitRequestDraft:async()=>{sends++;phase='attempted';throw Error('Delivery uncertain')},
  resumeRequestDraft:async()=>{phase='draft';throw Error('Direct request recipient is homed on another chat authority. No legacy delivery was attempted.')},
  getRequestWorkspace:async()=>{inventory++;throw Error('Remote inventory unavailable')}
 });
 store.begin('did:plc:bob','Bob','original');const id=get(store).selectedId;
 await store.send(id);assert.equal(get(store).drafts[0].phase,'attempted');
 await store.resume(id);assert.equal(get(store).drafts[0].phase,'draft');
 assert.match(get(store).error,/recipient is homed on another chat authority/);
 await store.saveText(id,'edited after terminal refusal');
 assert.equal(get(store).drafts[0].input.text,'edited after terminal refusal');
 assert.equal(get(store).drafts[0].input.draftId,id);assert.equal(sends,1);assert.equal(inventory,0);
});
test('previously unknown outcome becomes editable only after host returns a terminal draft',async()=>{
 let terminal=false, inventory=0;
 const store=await subject({
  saveRequestDraft:async(owner,input,recipientLabel)=>({input,recipientLabel,phase:terminal?'draft':'checking',outcome:terminal?null:{type:'outcomeUnknown',requestId:'request'},archived:false}),
  submitRequestDraft:async()=>({...get(store).drafts[0],phase:'checking',outcome:{type:'outcomeUnknown',requestId:'request'}}),
  resumeRequestDraft:async()=>{terminal=true;throw Error('Direct request recipient is homed on another chat authority. No legacy delivery was attempted.')},
  getRequestWorkspace:async owner=>{inventory++;return {ownerDid:owner,drafts:get(store).drafts,requests:[]}}
 });
 store.begin('did:plc:bob','Bob','original');const id=get(store).selectedId;
 await store.send(id);
 assert.equal(get(store).drafts[0].phase,'checking');
 assert.equal(get(store).drafts[0].outcome.type,'outcomeUnknown');
 await store.resume(id);
 assert.equal(get(store).drafts[0].phase,'draft');
 assert.equal(get(store).drafts[0].outcome,null);
 assert.match(get(store).error,/recipient is homed on another chat authority/);
 await store.saveText(id,'edited after unknown resolved');
 assert.equal(get(store).drafts[0].input.text,'edited after unknown resolved');
 assert.equal(get(store).drafts[0].input.draftId,id);
 assert.equal(inventory,1);
});
test('queued draft saves are ordered and never cross an account switch',async()=>{
 const first=deferred();const calls=[];const store=await subject({saveRequestDraft:async(owner,input,recipientLabel)=>{if(input.text==='')return {input,recipientLabel,phase:'draft',archived:false};calls.push(input.text);if(calls.length===1)await first.promise;return {input,recipientLabel,phase:'draft',archived:false}}});store.begin('did:plc:bob','Bob');const id=get(store).selectedId;const a=store.saveText(id,'one');const b=store.saveText(id,'two');for(let i=0;i<8&&calls.length===0;i++)await Promise.resolve();assert.deepEqual(calls,['one']);store.bindAccount('did:plc:other');first.resolve();await Promise.all([a,b]);assert.deepEqual(calls,['one']);assert.equal(get(store).drafts.length,0);
});
test('browser unsupported mode cannot create a false durable pending operation',async()=>{
 const store=await subject({requestBackendAvailable:false});store.begin('did:plc:bob','Bob','hello');const id=get(store).selectedId;await store.saveText(id,'browser draft');assert.equal(get(store).drafts[0].phase,'draft');await store.cancel(id);assert.equal(get(store).drafts[0].archived,true);
});

test('reselecting a contact with ambiguous delivery retains the unresolved draft identity',async()=>{const store=await subject(uncertain());store.begin('did:plc:bob','Bob','first');const id=get(store).selectedId;await store.send(id);store.begin('did:plc:bob','Bob','second');assert.equal(get(store).selectedId,id);assert.equal(get(store).drafts.length,1);assert.equal(get(store).drafts[0].input.text,'first');});

test('invitation note cannot silently replace an existing immutable introduction',async()=>{const store=await subject(uncertain());store.begin('did:plc:bob','Bob','first');const id=get(store).selectedId;await store.send(id);assert.equal(store.begin('did:plc:bob','Bob','note',{conversationId:'group',invitationId:'invite'}),false);assert.equal(get(store).drafts.length,1);assert.equal(get(store).drafts[0].input.text,'first');assert.equal(get(store).drafts[0].input.invitation,undefined);assert.match(get(store).error,/no invitation note was sent/);});

test('ExistingDirect retains the note and never sends it as an automatic fallback',async()=>{let notes=0;const store=await subject({submitRequestDraft:async()=>({...get(store).drafts[0],phase:'resolved',outcome:{type:'existingDirect',conversationId:'accepted',requiresAcceptance:false}}),sendExistingInvitationNote:async()=>{notes++;return {...get(store).drafts[0],noteDelivery:{conversationId:'accepted',messageId:'note-1'}}},getRequestWorkspace:async owner=>({ownerDid:owner,drafts:get(store).drafts,requests:[]})});store.begin('did:plc:bob','Bob','A separate note',{authorityDid:'did:web:chat.catbird.blue',conversationId:'group'});const id=get(store).selectedId;await store.send(id);assert.equal(notes,0);assert.equal(get(store).drafts[0].input.text,'A separate note');await store.sendInvitationNote(id);assert.equal(notes,1);assert.equal(get(store).drafts[0].noteDelivery.messageId,'note-1');});
test('delayed note outcome never crosses an account switch',async()=>{const pending=deferred();const store=await subject({sendExistingInvitationNote:()=>pending.promise});store.begin('did:plc:bob','Bob','Note');const draft=get(store).drafts[0];const send=store.sendInvitationNote(draft.input.draftId);store.bindAccount('did:plc:other');pending.resolve({...draft,noteDelivery:{conversationId:'accepted',messageId:'note'}});await send;assert.equal(get(store).drafts.length,0);assert.equal(get(store).ownerDid,'did:plc:other');});

test('explicit note selection attaches a verified reference to an unattempted local draft only',async()=>{const store=await subject();store.begin('did:plc:bob','Bob','Retained local text');const id=get(store).selectedId;const invitation={authorityDid:'did:web:chat.catbird.blue',conversationId:'group'};assert.equal(store.begin('did:plc:bob','Bob','',invitation),true);assert.equal(get(store).selectedId,id);assert.equal(get(store).drafts[0].input.text,'Retained local text');assert.equal(get(store).drafts[0].input.invitation.conversationId,'group');assert.equal(get(store).drafts[0].phase,'draft');});

test('late local draft acknowledgement cannot erase a newly attached invitation',async()=>{const pending=deferred();let first=true;const store=await subject({saveRequestDraft:async(owner,input,recipientLabel)=>{if(first){first=false;await pending.promise;}return {input,recipientLabel,phase:'draft',archived:false};}});store.begin('did:plc:bob','Bob','Same text');await Promise.resolve();store.begin('did:plc:bob','Bob','',{authorityDid:'did:web:chat.catbird.blue',conversationId:'group'});pending.resolve();for(let i=0;i<8;i++)await Promise.resolve();assert.equal(get(store).drafts[0].input.invitation.conversationId,'group');});

test('pending ExistingDirect note can retry explicit action after current consent becomes accepted without changing outcome', async () => {
    let accepted = false, sends = 0;
    const store = await subject({
        submitRequestDraft: async () => ({...get(store).drafts[0],phase:'resolved',outcome:{type:'existingDirect',conversationId:'direct',requiresAcceptance:true}}),
        getRequestWorkspace: async owner => ({ownerDid:owner,drafts:get(store).drafts,requests:[]}),
        sendExistingInvitationNote: async () => {
            if (!accepted) throw Error('Acceptance required');
            sends++;
            return {...get(store).drafts[0],noteDelivery:{conversationId:'direct',messageId:'note'}};
        }
    });
    store.begin('did:plc:bob','Bob','Note',{authorityDid:'did:web:chat.catbird.blue',conversationId:'group'});
    const id = get(store).selectedId;
    await store.send(id);
    const original = JSON.stringify(get(store).drafts[0].outcome);
    await store.sendInvitationNote(id);
    assert.equal(sends,0);
    accepted=true;
    await store.sendInvitationNote(id);
    assert.equal(sends,1);
    assert.equal(JSON.stringify(get(store).drafts[0].outcome),original);
});

test('same-DID replacement discards old request save before submitting a new-session effect', async () => {
    const pending = deferred(); let submit = 0, saves = 0;
    const store = await subject({
        saveRequestDraft: async (owner, input, recipientLabel) => { saves++; await pending.promise; return {input, recipientLabel, phase:'draft', archived:false}; },
        submitRequestDraft: async () => { submit++; throw Error('Old intent used new session'); }
    });
    store.bindAccount('did:plc:alice', '1');
    store.begin('did:plc:bob', 'Bob', 'old session draft');
    const id = get(store).selectedId;
    const send = store.send(id);
    await Promise.resolve();
    store.bindAccount('did:plc:alice', '3');
    pending.resolve(); await send;
    assert.equal(submit, 0); assert.equal(get(store).drafts.length, 0);
    assert.equal(get(store).ownerDid, 'did:plc:alice');
});
