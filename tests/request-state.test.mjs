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
test('contact selection remains local and first send reuses the saved immutable identity',async()=>{
 const calls=[];const store=await subject({submitRequestDraft:async(owner,id)=>{calls.push([owner,id]);return {...get(store).drafts[0],phase:'checking',outcome:{type:'outcomeUnknown',requestId:'request'}}},getRequestWorkspace:async owner=>({ownerDid:owner,drafts:get(store).drafts,requests:[]})});
 store.begin('did:plc:bob','Bob');assert.equal(calls.length,0);const id=get(store).selectedId;await store.saveText(id,'hello');await store.send(id);await store.send(id);assert.equal(calls.length,2);assert.equal(calls[0][1],calls[1][1]);assert.equal(get(store).drafts[0].input.text,'hello');assert.equal(get(store).drafts[0].phase,'checking');
});
test('double submit while waiting invokes transport only once',async()=>{
 const pending=deferred();let count=0;const store=await subject({submitRequestDraft:async()=>{count++;return pending.promise}});store.begin('did:plc:bob','Bob','hello');const id=get(store).selectedId;const first=store.send(id);await Promise.resolve();await Promise.resolve();await store.send(id);assert.equal(count,1);pending.resolve({...get(store).drafts[0],phase:'checking'});await first;
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
 const store=await subject({submitRequestDraft:async()=>{throw Error('Delivery uncertain')}});store.begin('did:plc:bob','Bob','original');const id=get(store).selectedId;await store.send(id);assert.equal(get(store).drafts[0].phase,'attempted');await store.saveText(id,'replacement');assert.equal(get(store).drafts[0].input.text,'original');assert.equal(get(store).drafts[0].input.draftId,id);
});
test('queued draft saves are ordered and never cross an account switch',async()=>{
 const first=deferred();const calls=[];const store=await subject({saveRequestDraft:async(owner,input,recipientLabel)=>{calls.push(input.text);if(calls.length===1)await first.promise;return {input,recipientLabel,phase:'draft',archived:false}}});store.begin('did:plc:bob','Bob');const id=get(store).selectedId;const a=store.saveText(id,'one');const b=store.saveText(id,'two');await Promise.resolve();assert.deepEqual(calls,['one']);store.bindAccount('did:plc:other');first.resolve();await Promise.all([a,b]);assert.deepEqual(calls,['one']);assert.equal(get(store).drafts.length,0);
});
test('browser unsupported mode cannot create a false durable pending operation',async()=>{
 const store=await subject({requestBackendAvailable:false});store.begin('did:plc:bob','Bob','hello');const id=get(store).selectedId;await store.saveText(id,'browser draft');assert.equal(get(store).drafts[0].phase,'draft');await store.cancel(id);assert.equal(get(store).drafts[0].archived,true);
});
