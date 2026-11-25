<script lang="ts">
	import { onDestroy } from 'svelte';
	import { searchUsers, checkOptInStatus, type SearchResult } from '#lib/wasm.ts';
	import { isSameAccountDid, stripDidFragment } from '#lib/did.ts';
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';

	let {
		selected = $bindable<SearchResult[]>([]),
		mode = 'multiple',
		inputId = 'user-search-input',
		placeholder = 'Search by Bluesky name or handle...',
		excludeDids = []
	}: {
		selected: SearchResult[];
		mode?: 'single' | 'multiple';
		inputId?: string;
		placeholder?: string;
		excludeDids?: string[];
	} = $props();

	let query = $state('');
	let results = $state<SearchResult[]>([]);
	let searching = $state(false);
	let searched = $state(false);
	let searchError = $state('');
	let lastSearchedQuery = $state('');
	let optInMap = $state<Record<string, boolean>>({});
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	let searchSeq = 0;

	const excludeSet = $derived(
		new Set(excludeDids.map((did) => stripDidFragment(did)).filter(Boolean))
	);
	const visibleResults = $derived(
		results.filter((user) => !excludeSet.has(stripDidFragment(user.did) || user.did))
	);

	function optInKey(did: string): string {
		return stripDidFragment(did) || did;
	}

	function isSelected(did: string): boolean {
		return selected.some((s) => isSameAccountDid(s.did, did));
	}

	function toggleUser(user: SearchResult) {
		if (isSelected(user.did)) {
			selected = selected.filter((s) => !isSameAccountDid(s.did, user.did));
			return;
		}
		if (mode === 'single') {
			selected = [user];
		} else {
			selected = [...selected, user];
		}
	}

	function removeUser(did: string) {
		selected = selected.filter((s) => !isSameAccountDid(s.did, did));
	}

	function clearQuery() {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		searchSeq += 1;
		query = '';
		results = [];
		searching = false;
		searched = false;
		searchError = '';
		lastSearchedQuery = '';
	}

	async function doSearch(rawQuery: string) {
		const trimmed = rawQuery.trim();
		const seq = ++searchSeq;

		if (!trimmed) {
			results = [];
			searching = false;
			searched = false;
			searchError = '';
			lastSearchedQuery = '';
			return;
		}

		searching = true;
		searchError = '';
		lastSearchedQuery = trimmed;

		let fetched: SearchResult[] = [];
		try {
			fetched = await searchUsers(trimmed);
			if (seq !== searchSeq) return;
			results = fetched;
			searched = true;
		} catch {
			if (seq !== searchSeq) return;
			results = [];
			searched = true;
			searchError = 'Could not search Bluesky accounts. Try again.';
		} finally {
			if (seq === searchSeq) {
				searching = false;
			}
		}

		if (seq !== searchSeq || fetched.length === 0) return;

		try {
			const didsToCheck = fetched
				.map((r) => optInKey(r.did))
				.filter((d) => !(d in optInMap) && !excludeSet.has(d));
			if (didsToCheck.length > 0) {
				const statuses = await checkOptInStatus(didsToCheck);
				if (seq !== searchSeq) return;
				const nextMap = { ...optInMap };
				for (const status of statuses) {
					nextMap[optInKey(status.did)] = status.optedIn;
				}
				optInMap = nextMap;
			}
		} catch {
			// Opt-in check is non-fatal
		}
	}

	function handleInput() {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		if (!query.trim()) {
			searchSeq += 1;
			results = [];
			searching = false;
			searched = false;
			searchError = '';
			lastSearchedQuery = '';
			return;
		}
		const targetQuery = query;
		debounceTimer = setTimeout(() => {
			debounceTimer = null;
			doSearch(targetQuery);
		}, 250);
	}

	onDestroy(() => {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		searchSeq += 1;
	});
</script>

<div class="user-search">
	{#if selected.length > 0}
		<ul role="list" class="selected-chips" aria-label="Selected recipients">
			{#each selected as user (user.did)}
				<li class="chip">
					<Avatar
						src={user.avatar ?? null}
						name={user.displayName ?? user.handle}
						id={user.did}
						size={20}
						shape="circle"
					/>
					<span class="chip-name">{user.displayName || `@${user.handle}`}</span>
					<button
						type="button"
						class="chip-remove"
						onclick={() => removeUser(user.did)}
						aria-label={`Remove ${user.displayName || user.handle}`}
					>
						<Icon name="x" size={13} />
					</button>
				</li>
			{/each}
		</ul>
	{/if}

	<div class="search-input-wrap">
		<span class="search-icon" aria-hidden="true">
			<Icon name="search" size={16} />
		</span>
		<input
			id={inputId}
			type="search"
			class="search-input"
			{placeholder}
			bind:value={query}
			oninput={handleInput}
			autocomplete="off"
			autocorrect="off"
			autocapitalize="none"
			spellcheck="false"
			enterkeyhint="search"
		/>
		{#if query.length > 0}
			<button
				type="button"
				class="search-clear"
				onclick={clearQuery}
				aria-label="Clear search"
			>
				<Icon name="x" size={15} />
			</button>
		{/if}
	</div>

	{#if searching}
		<div class="search-status">
			<progress class="catmos-progress search-progress" aria-label="Searching accounts"></progress>
			<span>Searching accounts...</span>
		</div>
	{:else if searchError}
		<p class="search-error" role="alert">{searchError}</p>
	{:else if visibleResults.length > 0}
		<ul role="list" class="search-results" aria-label="Account search results">
			{#each visibleResults as user (user.did)}
				{@const active = isSelected(user.did)}
				<li>
					<button
						type="button"
						class="search-result"
						class:selected-result={active}
						aria-pressed={active}
						onclick={() => toggleUser(user)}
					>
						<Avatar
							src={user.avatar ?? null}
							name={user.displayName ?? user.handle}
							id={user.did}
							size={36}
							shape="circle"
						/>
						<span class="result-info">
							<span class="result-top">
								<span class="result-name">{user.displayName || user.handle}</span>
							</span>
							<span class="result-meta">
								<span class="result-handle">@{user.handle}</span>
								{#if optInMap[optInKey(user.did)] === true}
									<span class="meta-sep" aria-hidden="true">·</span>
									<span class="optin-status ready">Encrypted ready</span>
								{:else if optInMap[optInKey(user.did)] === false}
									<span class="meta-sep" aria-hidden="true">·</span>
									<span class="optin-status unavailable">Not set up for Catmos</span>
								{/if}
							</span>
						</span>
						{#if active}
							<span class="check-icon" aria-hidden="true">
								<Icon name="check" size={16} />
							</span>
						{/if}
					</button>
				</li>
			{/each}
		</ul>
	{:else if searched && lastSearchedQuery}
		<p class="search-empty">No Bluesky accounts found for "{lastSearchedQuery}".</p>
	{/if}
</div>

<style>
	.user-search {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.selected-chips {
		list-style: none;
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
	}

	.chip {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		min-block-size: max(1.875rem, var(--touch-min));
		padding-inline: var(--space-1) var(--space-2);
		padding-block: var(--space-fine);
		background: var(--bg-surface);
		border: 1px solid var(--border-strong);
		color: var(--text-primary);
		border-radius: var(--radius-full);
		font-size: var(--text-sm);
		font-weight: 500;
		max-inline-size: 100%;
	}

	.chip-name {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-inline-size: 14rem;
	}

	.chip-remove {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(1.5rem, var(--touch-min));
		min-block-size: max(1.5rem, var(--touch-min));
		margin-inline-end: calc(-1 * var(--space-1));
		border-radius: var(--radius-full);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.chip-remove:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.search-input-wrap {
		position: relative;
		display: flex;
		align-items: center;
		background: var(--bg-input);
		border: 1px solid var(--border-input);
		border-radius: var(--radius-sm);
		transition: border-color var(--dur-fast) var(--ease-out);
	}

	.search-input-wrap:focus-within {
		border-color: var(--focus-ring);
	}

	.search-icon {
		display: inline-flex;
		align-items: center;
		padding-inline-start: var(--space-3);
		color: var(--text-muted);
		pointer-events: none;
	}

	.search-input {
		flex: 1;
		min-inline-size: 0;
		min-block-size: max(2.5rem, var(--touch-min));
		padding-inline: var(--space-2) var(--space-3);
		padding-block: var(--space-2);
		color: var(--text-primary);
		font-size: var(--text-body);
		outline: none;
	}

	.search-input::placeholder {
		color: var(--text-muted);
	}

	.search-input::-webkit-search-cancel-button {
		-webkit-appearance: none;
	}

	.search-clear {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-inline-size: max(2rem, var(--touch-min));
		min-block-size: max(2rem, var(--touch-min));
		margin-inline-end: var(--space-1);
		border-radius: var(--radius-xs);
		color: var(--text-secondary);
		transition:
			background-color var(--dur-fast) var(--ease-out),
			color var(--dur-fast) var(--ease-out);
	}

	.search-clear:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.search-status {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding-block: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.search-progress {
		inline-size: 1rem;
		block-size: 1rem;
		border-width: 2px;
	}

	.search-error {
		font-size: var(--text-sm);
		color: var(--danger-text);
		padding-block: var(--space-1);
	}

	.search-empty {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		padding: var(--space-3);
		text-align: center;
		background: var(--bg-surface);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
	}

	.search-results {
		list-style: none;
		max-block-size: 14.5rem;
		overflow-y: auto;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
		background: var(--bg-surface);
	}

	.search-results li + li {
		border-block-start: 1px solid var(--border);
	}

	.search-result {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		width: 100%;
		min-block-size: max(3.25rem, var(--touch-min));
		padding-inline: var(--space-3);
		padding-block: var(--space-2);
		text-align: start;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.search-result:hover {
		background: var(--bg-hover);
	}

	.search-result.selected-result {
		background: var(--bg-selected);
	}

	.result-info {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.result-top {
		display: flex;
		align-items: baseline;
		gap: var(--space-2);
		min-inline-size: 0;
	}

	.result-name {
		color: var(--text-primary);
		font-size: var(--text-body);
		font-weight: 600;
		line-height: 1.3;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.result-meta {
		display: flex;
		align-items: baseline;
		flex-wrap: wrap;
		gap: var(--space-1);
		font-size: var(--text-sm);
		line-height: 1.35;
	}

	.result-handle {
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-inline-size: 100%;
	}

	.meta-sep {
		color: var(--text-muted);
	}

	.optin-status {
		font-size: var(--text-sm);
		font-weight: 500;
		white-space: nowrap;
	}

	.optin-status.ready {
		color: var(--success-text);
	}

	.optin-status.unavailable {
		color: var(--text-muted);
	}

	.check-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		color: var(--text-link);
		flex-shrink: 0;
	}
</style>
