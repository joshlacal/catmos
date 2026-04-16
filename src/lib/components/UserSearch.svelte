<script lang="ts">
	import { searchUsers, checkOptInStatus, type SearchResult } from '$lib/wasm';

	let { selected = $bindable([]) }: { selected: SearchResult[] } = $props();

	let query = $state('');
	let results = $state<SearchResult[]>([]);
	let searching = $state(false);
	let optInMap = $state<Record<string, boolean>>({});
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;

	function isSelected(did: string): boolean {
		return selected.some((s) => s.did === did);
	}

	function toggleUser(user: SearchResult) {
		if (isSelected(user.did)) {
			selected = selected.filter((s) => s.did !== user.did);
		} else {
			selected = [...selected, user];
		}
	}

	function removeUser(did: string) {
		selected = selected.filter((s) => s.did !== did);
	}

	async function doSearch(q: string) {
		if (!q.trim()) {
			results = [];
			return;
		}
		searching = true;
		try {
			results = await searchUsers(q);
		} catch {
			results = [];
		} finally {
			searching = false;
		}
		try {
			const dids = results.map((r) => r.did).filter((d) => !(d in optInMap));
			if (dids.length > 0) {
				const statuses = await checkOptInStatus(dids);
				const newMap = { ...optInMap };
				for (const s of statuses) {
					newMap[s.did] = s.optedIn;
				}
				optInMap = newMap;
			}
		} catch {
			// Non-fatal
		}
	}

	function onInput() {
		if (debounceTimer) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => doSearch(query), 300);
	}
</script>

<div class="user-search">
	{#if selected.length > 0}
		<div class="selected-chips">
			{#each selected as user (user.did)}
				<span class="chip">
					<span class="chip-name">{user.displayName ?? user.handle}</span>
					<button class="chip-remove" onclick={() => removeUser(user.did)} title="Remove">
						<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
							<line x1="18" y1="6" x2="6" y2="18" />
							<line x1="6" y1="6" x2="18" y2="18" />
						</svg>
					</button>
				</span>
			{/each}
		</div>
	{/if}

	<input
		type="text"
		class="search-input"
		placeholder="Search by name or handle..."
		bind:value={query}
		oninput={onInput}
	/>

	{#if searching}
		<div class="search-status">Searching...</div>
	{/if}

	{#if results.length > 0}
		<div class="search-results">
			{#each results as user (user.did)}
				<button
					type="button"
					class="search-result"
					class:selected-result={isSelected(user.did)}
					onclick={() => toggleUser(user)}
				>
					<div class="result-avatar">
						{#if user.avatar}
							<img src={user.avatar} alt="" class="avatar-img" />
						{:else}
							<span class="avatar-letter">
								{(user.displayName ?? user.handle).charAt(0).toUpperCase()}
							</span>
						{/if}
					</div>
					<div class="result-info">
						<span class="result-name">{user.displayName ?? user.handle}</span>
						<span class="result-handle">@{user.handle}</span>
					</div>
					{#if optInMap[user.did] === true}
						<span class="optin-badge yes">MLS</span>
					{:else if optInMap[user.did] === false}
						<span class="optin-badge no">No MLS</span>
					{/if}
					{#if isSelected(user.did)}
						<svg class="check-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
							<polyline points="20 6 9 17 4 12" />
						</svg>
					{/if}
				</button>
			{/each}
		</div>
	{/if}
</div>

<style>
	.user-search {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.selected-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
	}

	.chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 4px 10px;
		background: var(--accent);
		color: var(--text-on-accent);
		border-radius: var(--radius-full);
		font-size: 12px;
		font-weight: 600;
	}

	.chip-remove {
		background: none;
		border: none;
		color: rgba(255, 255, 255, 0.7);
		cursor: pointer;
		padding: 0;
		display: flex;
		align-items: center;
	}

	.chip-remove:hover {
		color: white;
	}

	.search-input {
		display: block;
		width: 100%;
		padding: 10px 14px;
		background: var(--bg-input);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		color: var(--text-primary);
		font-family: inherit;
		font-size: 14px;
		transition: border-color var(--transition-fast);
	}

	.search-input:focus {
		border-color: var(--accent);
		outline: none;
	}

	.search-input::placeholder {
		color: var(--text-tertiary);
	}

	.search-status {
		font-size: 12px;
		color: var(--text-secondary);
		padding: 2px 0;
	}

	.search-results {
		max-height: 200px;
		overflow-y: auto;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
		background: var(--bg-input);
	}

	.search-result {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 12px;
		width: 100%;
		text-align: left;
		transition: background var(--transition-fast);
	}

	.search-result:hover {
		background: var(--bg-hover);
	}

	.search-result.selected-result {
		background: var(--bg-selected);
	}

	.result-avatar {
		width: 32px;
		height: 32px;
		border-radius: var(--radius-full);
		overflow: hidden;
		flex-shrink: 0;
		background: var(--accent);
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.avatar-img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	.avatar-letter {
		color: var(--text-on-accent);
		font-weight: 600;
		font-size: 14px;
	}

	.result-info {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
	}

	.result-name {
		color: var(--text-primary);
		font-size: 13px;
		font-weight: 600;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.result-handle {
		color: var(--text-secondary);
		font-size: 12px;
	}

	.optin-badge {
		font-size: 10px;
		padding: 2px 7px;
		border-radius: var(--radius-full);
		font-weight: 700;
		flex-shrink: 0;
		letter-spacing: 0.02em;
	}

	.optin-badge.yes {
		background: rgba(52, 199, 89, 0.15);
		color: var(--success);
	}

	.optin-badge.no {
		background: rgba(255, 59, 48, 0.15);
		color: var(--danger);
	}

	.check-icon {
		flex-shrink: 0;
	}
</style>
