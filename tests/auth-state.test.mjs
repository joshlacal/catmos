// Actual auth store with paused transport; bounded UI state fencing only.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import { get, writable } from 'svelte/store';
const compiled=ts.transpileModule(await readFile(new URL('../src/lib/stores/auth.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {resolve,promise}};
const user=revision=>({did:'did:plc:alice',handle:'alice',authRevision:revision});
async function subject(overrides={}) {
 const context=vm.createContext({console});const cached=[];
 const api={isTauri:false,getProfiles:async()=>[],tryRestoreSession:async()=>user('1'),completeLogin:async()=>user('1'),logout:async()=>{},startLogin:async()=>{},listenForEvent:async()=>()=>{},...overrides};
 const mods={
 'svelte/store':{writable},'$lib/wasm':api,'./requests':{requests:{bindAccount(){}}},'./profiles':{profiles:{setProfile(p){cached.push(p)}}}
 };
 const loaded=new Map();const module=new vm.SourceTextModule(compiled,{context});
 await module.link(name=>{if(!loaded.has(name)){const exports=mods[name];loaded.set(name,new vm.SyntheticModule(Object.keys(exports),function(){for(const[k,v]of Object.entries(exports))this.setExport(k,v)},{context}));}return loaded.get(name)});
 await module.evaluate();return {store:module.namespace.createAuthStore(),cached};
}
for(const operation of ['tryRestore','completeOAuthCallback']) test(`${operation} cannot restore user or profile after logout during profile await`,async()=>{
 const pending=deferred(),entered=deferred();const {store,cached}=await subject({getProfiles:()=>{entered.resolve();return pending.promise}});
 const old=store[operation]('session');await entered.promise;await store.logout();pending.resolve([{did:'did:plc:alice',handle:'stale',displayName:'Old profile'}]);await old;
 assert.equal(get(store).user,null);assert.equal(cached.length,0);
});
test('same-DID replacement wins over old profile and old logout completion',async()=>{
 const profile=deferred(),entered=deferred(),logout=deferred();const {store,cached}=await subject({getProfiles:()=>{entered.resolve();return profile.promise},logout:()=>logout.promise});
 const old=store.tryRestore();await entered.promise;const leaving=store.logout();store.setUser(user('3'));profile.resolve([{did:'did:plc:alice',handle:'stale'}]);await old;logout.resolve();await leaving;
 assert.equal(get(store).user.authRevision,'3');assert.equal(cached.length,0);
});
test('stale restore failure does not replace newer session',async()=>{
 const pending=deferred();const {store}=await subject({tryRestoreSession:()=>pending.promise});const old=store.tryRestore();store.setUser(user('3'));pending.resolve(null);await old;assert.equal(get(store).user.authRevision,'3');
});
