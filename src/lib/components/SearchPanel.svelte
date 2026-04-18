<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { conversations } from '$lib/stores/conversations';
  import { messages } from '$lib/stores/messages';
  import * as api from '$lib/wasm';
  import type { SearchHit } from '$lib/wasm';

  let {
    open = false,
    onClose,
    onNavigate
  }: {
    open: boolean;
    onClose: () => void;
    onNavigate: (conversationId: string, messageId: string) => void;
  } = $props();

  let query = $state('');
  let results = $state<SearchHit[]>([]);
  let loading = $state(false);
  let searched = $state(false);
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let inputEl: HTMLInputElement | undefined = $state();

  $effect(() => {
    if (open && inputEl) {
      inputEl.focus();
    }
  });

  $effect(() => {
    if (!open) {
      query = '';
      results = [];
      searched = false;
      loading = false;
    }
  });

  function handleInput() {
    if (debounceTimer) clearTimeout(debounceTimer);
    if (!query.trim()) {
      results = [];
      searched = false;
      loading = false;
      return;
    }
    loading = true;
    debounceTimer = setTimeout(() => {
      performSearch();
    }, 300);
  }

  async function performSearch() {
    const q = query.trim();
    if (!q) {
      results = [];
      searched = false;
      loading = false;
      return;
    }
    try {
      results = await api.searchMessages(q);
    } catch (e) {
      console.error('[catmos] searchMessages failed:', e);
      results = [];
    } finally {
      loading = false;
      searched = true;
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      onClose();
    }
  }

  function handleResultClick(hit: SearchHit) {
    onNavigate(hit.conversationId, hit.messageId);
    onClose();
  }

  function highlightMatch(text: string, q: string): string {
    if (!q.trim()) return escapeHtml(text);
    const escaped = escapeHtml(text);
    const escapedQuery = escapeHtml(q.trim());
    const regex = new RegExp(`(${escapeRegex(escapedQuery)})`, 'gi');
    return escaped.replace(regex, '<mark>$1</mark>');
  }

  function escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function formatTimestamp(ts: string): string {
    const date = new Date(ts);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const oneDay = 86400000;

    if (diff < oneDay) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    if (diff < 7 * oneDay) {
      return date.toLocaleDateString([], { weekday: 'short' });
    }
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }

  onDestroy(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="search-overlay" onkeydown={handleKeydown}>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="search-backdrop" onclick={onClose}></div>
    <div class="search-panel">
      <div class="search-header">
        <div class="search-input-row">
          <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            bind:this={inputEl}
            type="text"
            placeholder="Search messages..."
            bind:value={query}
            oninput={handleInput}
            class="search-input"
          />
          <button class="close-btn" onclick={onClose} title="Close search">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <div class="search-shortcut">
          <kbd>{navigator.platform.includes('Mac') ? '\u2318' : 'Ctrl'}+K</kbd> to toggle
        </div>
      </div>

      <div class="search-results">
        {#if loading}
          <div class="search-state">
            <div class="search-spinner"></div>
            <p>Searching...</p>
          </div>
        {:else if searched && results.length === 0}
          <div class="search-state">
            <p class="no-results">No messages found for "{query}"</p>
          </div>
        {:else if results.length > 0}
          {#each results as hit (hit.messageId)}
            <button class="search-result" onclick={() => handleResultClick(hit)}>
              <div class="result-header">
                <span class="result-convo">{hit.conversationName}</span>
                <span class="result-time">{formatTimestamp(hit.timestamp)}</span>
              </div>
              <div class="result-sender">{hit.senderDid}</div>
              <div class="result-content">
                {@html highlightMatch(hit.content, query)}
              </div>
            </button>
          {/each}
        {:else}
          <div class="search-state">
            <p class="search-hint">Type to search through your message history</p>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .search-overlay {
    position: fixed;
    inset: 0;
    z-index: 100;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: 10vh;
  }

  .search-backdrop {
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
  }

  .search-panel {
    position: relative;
    width: min(560px, 90vw);
    max-height: 70vh;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-lg);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .search-header {
    padding: 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .search-input-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .search-icon {
    color: var(--text-tertiary);
    flex-shrink: 0;
  }

  .search-input {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--text-primary);
    font-size: 16px;
    outline: none;
    padding: 0;
  }

  .search-input::placeholder {
    color: var(--text-tertiary);
  }

  .close-btn {
    width: 28px;
    height: 28px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    flex-shrink: 0;
    transition: all var(--transition-fast);
  }

  .close-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .search-shortcut {
    margin-top: 8px;
    font-size: 11px;
    color: var(--text-tertiary);
  }

  .search-shortcut kbd {
    display: inline-block;
    padding: 1px 5px;
    font-size: 11px;
    font-family: inherit;
    background: var(--bg-hover);
    border: 1px solid var(--border);
    border-radius: 3px;
    color: var(--text-secondary);
  }

  .search-results {
    overflow-y: auto;
    flex: 1;
    min-height: 0;
  }

  .search-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 40px 20px;
    gap: 8px;
  }

  .search-state p {
    color: var(--text-secondary);
    font-size: 14px;
  }

  .no-results {
    color: var(--text-tertiary);
  }

  .search-hint {
    color: var(--text-tertiary);
  }

  .search-spinner {
    width: 24px;
    height: 24px;
    border: 2px solid var(--border);
    border-top: 2px solid var(--accent);
    border-radius: var(--radius-full);
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .search-result {
    display: block;
    width: 100%;
    text-align: left;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    transition: background var(--transition-fast);
    cursor: pointer;
  }

  .search-result:hover {
    background: var(--bg-hover);
  }

  .search-result:last-child {
    border-bottom: none;
  }

  .result-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 2px;
  }

  .result-convo {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-link);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .result-time {
    font-size: 11px;
    color: var(--text-tertiary);
    flex-shrink: 0;
    margin-left: 8px;
  }

  .result-sender {
    font-size: 11px;
    color: var(--text-secondary);
    margin-bottom: 4px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .result-content {
    font-size: 13px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .result-content :global(mark) {
    background: var(--accent);
    color: var(--text-on-accent);
    border-radius: 2px;
    padding: 0 2px;
  }
</style>
