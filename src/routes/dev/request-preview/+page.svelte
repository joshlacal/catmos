<script lang="ts">
 import { dev } from '$app/environment';
 import { onMount } from 'svelte';
 import { requests } from '$lib/stores/requests';
 import type { DirectRequestView } from '$lib/request-types';
 import RequestInbox from '$lib/components/RequestInbox.svelte';
 import RequestDetail from '$lib/components/RequestDetail.svelte';
 import RequestComposer from '$lib/components/RequestComposer.svelte';
 import MessageList from '$lib/components/MessageList.svelte';
 let mode=$state('preview');
 let notice=$state('');
 const fixture:DirectRequestView={conversationId:'00000000-0000-4000-8000-000000000001',firstMessageId:'00000000-0000-4000-8000-000000000002',consent:'incomingPending',crypto:'ready',preview:{type:'ready',text:'Hi Maya — I enjoyed your notes on the city garden. Would you like to trade a few ideas for the autumn planting?\n\nhttps://example.invalid/no-preview',invitation:{authorityDid:'did:web:chat.catbird.blue',conversationId:'00000000-0000-4000-8000-000000000003',invitationTransitionId:'00000000-0000-4000-8000-000000000004',invitedByDid:'did:plc:fixturepeer',invitedByDeviceId:'00000000-0000-4000-8000-000000000005',recipientDid:'did:plc:fixtureowner'}},capabilities:{canPreview:true,canAccept:true,canClose:true,canSend:false,canEmitReceipts:false,canAdminister:false},generation:0,stateVersion:1};
 const unavailable:DirectRequestView={...fixture,crypto:'unavailable',preview:{type:'unavailable',code:'missingKey'}};
 const accepted:DirectRequestView={...fixture,consent:'accepted',stateVersion:2,capabilities:{...fixture.capabilities,canAccept:false,canSend:true,canEmitReceipts:true}};
 onMount(()=>{if(dev){requests.bindAccount('did:plc:fixtureowner');requests.applyView('did:plc:fixtureowner',fixture);requests.begin('did:plc:fixturepeer','Maya','Hello Maya!');}});
</script>
{#if dev}
 <div class="fixture-shell"><nav aria-label="Request preview scenarios"><strong>LOCAL UI FIXTURE</strong><span>Rendering evidence only · no server publication</span>{#each ['preview','unavailable','draft','inbox','accepted'] as item}<button onclick={()=>{mode=item;notice='';}}>{item}</button>{/each}</nav>
 <main>{#if mode==='draft' && $requests.drafts[0]}<RequestComposer draft={$requests.drafts[0]} onOpenConversation={()=>{notice='Navigation only';}} />{:else if mode==='inbox'}<RequestInbox />{:else if mode==='accepted'}<MessageList messages={[]} request={accepted} />{:else}<RequestDetail view={mode==='unavailable'?unavailable:fixture} title="Maya" onOpenConversation={()=>{notice='Navigation only';}} onViewInvitation={()=>{notice='Group invitation opened for review; not accepted';}} />{/if}{#if notice}<p role="status">{notice}</p>{/if}</main></div>
{:else}<p>Not found</p>{/if}
<style>.fixture-shell{display:flex;flex-direction:column;height:100dvh;width:100vw;background:var(--bg-app)}nav{padding:14px 22px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);font-size:11px;flex-wrap:wrap}nav strong{color:var(--accent);letter-spacing:.1em}nav span{flex:1;color:var(--text-tertiary)}button{padding:7px 12px;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);cursor:pointer}main{display:flex;flex:1;min-height:0;flex-direction:column;overflow:auto}main>p{text-align:center;font-size:12px;color:var(--text-secondary)}</style>
