<script lang="ts">
  import { connection } from '$lib/stores/connection';

  let visible = $derived(
    $connection.state !== 'connected' && $connection.state !== 'connecting'
  );
  let label = $derived(
    $connection.state === 'offline'
      ? 'Offline'
      : $connection.state === 'error'
        ? 'Connection failed'
        : `Reconnecting${$connection.retryCount > 0 ? ` (${$connection.retryCount})` : ''}...`
  );
  let showSpinner = $derived($connection.state === 'reconnecting');
</script>

{#if visible}
  <div class="connection-banner" class:error={$connection.state === 'error'}>
    {#if showSpinner}
      <span class="spinner"></span>
    {:else if $connection.state === 'offline'}
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="1" y1="1" x2="23" y2="23" />
        <path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55" />
        <path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39" />
        <path d="M10.71 5.05A16 16 0 0 1 22.56 9" />
        <path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88" />
        <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
        <line x1="12" y1="20" x2="12.01" y2="20" />
      </svg>
    {/if}
    <span class="banner-text">{label}</span>
  </div>
{/if}

<style>
  .connection-banner {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 6px 12px;
    background: var(--bg-hover);
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 500;
    flex-shrink: 0;
  }

  .connection-banner.error {
    background: color-mix(in srgb, var(--danger) 15%, transparent);
    color: var(--danger);
  }

  .banner-text {
    line-height: 1;
  }

  .spinner {
    width: 12px;
    height: 12px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
