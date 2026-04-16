<script lang="ts">
  let {
    senderName,
    preview,
    onCancel
  }: {
    senderName: string;
    preview: string;
    onCancel: () => void;
  } = $props();

  let truncated = $derived(
    preview.length > 100 ? preview.slice(0, 100) + '...' : preview
  );
</script>

<div class="reply-preview">
  <div class="reply-content">
    <span class="reply-sender">{senderName}</span>
    <span class="reply-text">{truncated}</span>
  </div>
  <button class="reply-cancel" onclick={onCancel} aria-label="Cancel reply">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  </button>
</div>

<style>
  .reply-preview {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    margin: 0 20px;
    background: var(--bg-hover);
    border-left: 3px solid var(--accent);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  }

  .reply-content {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .reply-sender {
    font-size: 12px;
    font-weight: 600;
    color: var(--accent);
  }

  .reply-text {
    font-size: 12px;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .reply-cancel {
    flex-shrink: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-sm);
    color: var(--text-tertiary);
    transition: all var(--transition-fast);
  }

  .reply-cancel:hover {
    color: var(--text-primary);
    background: var(--bg-active);
  }

  @media (max-width: 768px) {
    .reply-preview {
      margin: 0 12px;
    }
  }
</style>
