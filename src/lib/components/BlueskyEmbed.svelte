<script lang="ts">
	let { url }: { url: string } = $props();

	let post = $state<{
		author: { displayName?: string; handle: string; avatar?: string };
		text: string;
		createdAt: string;
		likeCount?: number;
		repostCount?: number;
		replyCount?: number;
	} | null>(null);
	let loading = $state(true);
	let error = $state(false);

	// Parse bsky.app URL → API call
	// Format: https://bsky.app/profile/{handle}/post/{rkey}
	// or at://did:xxx/app.bsky.feed.post/rkey
	function parseUrl(input: string): { handle: string; rkey: string } | null {
		const bskyMatch = input.match(
			/https:\/\/bsky\.app\/profile\/([^/]+)\/post\/([a-zA-Z0-9]+)/
		);
		if (bskyMatch) return { handle: bskyMatch[1], rkey: bskyMatch[2] };

		const atMatch = input.match(
			/at:\/\/(did:[^/]+)\/app\.bsky\.feed\.post\/([a-zA-Z0-9]+)/
		);
		if (atMatch) return { handle: atMatch[1], rkey: atMatch[2] };

		return null;
	}

	$effect(() => {
		const parsed = parseUrl(url);
		if (!parsed) {
			error = true;
			loading = false;
			return;
		}

		loading = true;
		error = false;

		const uri = parsed.handle.startsWith('did:')
			? `at://${parsed.handle}/app.bsky.feed.post/${parsed.rkey}`
			: null;

		// We need to resolve the handle to a DID first if it's a handle
		(async () => {
			try {
				let atUri: string;

				if (uri) {
					atUri = uri;
				} else {
					// Resolve handle → DID
					const resolveRes = await fetch(
						`https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(parsed.handle)}`
					);
					if (!resolveRes.ok) throw new Error('Failed to resolve handle');
					const resolved = await resolveRes.json();
					atUri = `at://${resolved.did}/app.bsky.feed.post/${parsed.rkey}`;
				}

				// Fetch the post thread
				const res = await fetch(
					`https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=${encodeURIComponent(atUri)}&depth=0`
				);
				if (!res.ok) throw new Error('Failed to fetch post');
				const data = await res.json();

				const p = data.thread?.post;
				if (!p) throw new Error('No post in thread');

				post = {
					author: {
						displayName: p.author?.displayName,
						handle: p.author?.handle ?? '',
						avatar: p.author?.avatar
					},
					text: p.record?.text ?? '',
					createdAt: p.record?.createdAt ?? p.indexedAt ?? '',
					likeCount: p.likeCount,
					repostCount: p.repostCount,
					replyCount: p.replyCount
				};
				loading = false;
			} catch (e) {
				console.error('[catmos] Failed to fetch Bluesky post:', e);
				error = true;
				loading = false;
			}
		})();
	});

	function formatDate(iso: string): string {
		const d = new Date(iso);
		return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
	}

	function formatCount(n: number | undefined): string {
		if (n === undefined || n === 0) return '';
		if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
		return String(n);
	}

	function openPost() {
		// If it's already a bsky.app URL, open it; otherwise construct one
		const bskyUrl = url.startsWith('https://bsky.app') ? url : null;
		if (bskyUrl) {
			window.open(bskyUrl, '_blank', 'noopener');
		}
	}
</script>

{#if loading}
	<div class="bsky-embed loading">
		<div class="bsky-loading-bar"></div>
	</div>
{:else if error || !post}
	<a class="bsky-embed-link" href={url.startsWith('https://') ? url : '#'} target="_blank" rel="noopener">
		<svg width="16" height="16" viewBox="0 0 600 530" fill="currentColor" class="bsky-logo">
			<path d="M135.72 44.03C202.22 93.85 274.73 195.4 300 249.49c25.27-54.09 97.78-155.64 164.28-205.46C528.48-5.49 600-22.52 600 84.33c0 21.35-12.24 179.3-19.43 204.89-25.01 89.05-116.25 111.83-196.08 98.05 139.59 23.83 175.08 102.88 98.35 181.93C375.07 685.07 300 578.19 300 578.19s-75.07 106.88-182.84-9c-76.73-79.05-41.24-158.1 98.35-181.93-79.82 13.78-171.07-8.99-196.08-98.05C12.24 263.63 0 105.68 0 84.33 0-22.52 71.52-5.49 135.72 44.03z"/>
		</svg>
		<span>View on Bluesky</span>
	</a>
{:else}
	<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
	<div class="bsky-embed" onclick={openPost}>
		<div class="bsky-header">
			{#if post.author.avatar}
				<img src={post.author.avatar} alt="" class="bsky-avatar" />
			{:else}
				<div class="bsky-avatar-placeholder">
					{(post.author.displayName ?? post.author.handle).charAt(0).toUpperCase()}
				</div>
			{/if}
			<div class="bsky-author">
				{#if post.author.displayName}
					<span class="bsky-name">{post.author.displayName}</span>
				{/if}
				<span class="bsky-handle">@{post.author.handle}</span>
			</div>
			<svg width="18" height="18" viewBox="0 0 600 530" fill="var(--accent)" class="bsky-logo-sm">
				<path d="M135.72 44.03C202.22 93.85 274.73 195.4 300 249.49c25.27-54.09 97.78-155.64 164.28-205.46C528.48-5.49 600-22.52 600 84.33c0 21.35-12.24 179.3-19.43 204.89-25.01 89.05-116.25 111.83-196.08 98.05 139.59 23.83 175.08 102.88 98.35 181.93C375.07 685.07 300 578.19 300 578.19s-75.07 106.88-182.84-9c-76.73-79.05-41.24-158.1 98.35-181.93-79.82 13.78-171.07-8.99-196.08-98.05C12.24 263.63 0 105.68 0 84.33 0-22.52 71.52-5.49 135.72 44.03z"/>
			</svg>
		</div>
		{#if post.text}
			<p class="bsky-text">{post.text}</p>
		{/if}
		<div class="bsky-footer">
			<span class="bsky-date">{formatDate(post.createdAt)}</span>
			<div class="bsky-stats">
				{#if post.replyCount}
					<span class="bsky-stat">
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
						</svg>
						{formatCount(post.replyCount)}
					</span>
				{/if}
				{#if post.repostCount}
					<span class="bsky-stat">
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<polyline points="17 1 21 5 17 9" />
							<path d="M3 11V9a4 4 0 0 1 4-4h14" />
							<polyline points="7 23 3 19 7 15" />
							<path d="M21 13v2a4 4 0 0 1-4 4H3" />
						</svg>
						{formatCount(post.repostCount)}
					</span>
				{/if}
				{#if post.likeCount}
					<span class="bsky-stat">
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z" />
						</svg>
						{formatCount(post.likeCount)}
					</span>
				{/if}
			</div>
		</div>
	</div>
{/if}

<style>
	.bsky-embed {
		margin-top: 8px;
		padding: 14px;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: var(--radius-md);
		cursor: pointer;
		transition: background var(--transition-fast);
		max-width: 340px;
	}

	.bsky-embed:hover {
		background: var(--bg-hover);
	}

	.bsky-embed.loading {
		padding: 20px;
		cursor: default;
	}

	.bsky-loading-bar {
		width: 60%;
		height: 4px;
		background: var(--border);
		border-radius: 2px;
		overflow: hidden;
		position: relative;
	}

	.bsky-loading-bar::after {
		content: '';
		position: absolute;
		top: 0;
		left: -40%;
		width: 40%;
		height: 100%;
		background: var(--accent);
		border-radius: 2px;
		animation: loading-slide 1.2s ease-in-out infinite;
	}

	@keyframes loading-slide {
		0% { left: -40%; }
		100% { left: 100%; }
	}

	.bsky-embed-link {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		margin-top: 6px;
		padding: 8px 14px;
		background: var(--bg-hover);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		color: var(--text-link);
		font-size: 13px;
		font-weight: 500;
		text-decoration: none;
		transition: background var(--transition-fast);
	}

	.bsky-embed-link:hover {
		background: var(--bg-active);
		text-decoration: none;
	}

	.bsky-logo {
		opacity: 0.6;
	}

	.bsky-header {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 10px;
	}

	.bsky-avatar {
		width: 36px;
		height: 36px;
		border-radius: var(--radius-full);
		object-fit: cover;
		flex-shrink: 0;
	}

	.bsky-avatar-placeholder {
		width: 36px;
		height: 36px;
		border-radius: var(--radius-full);
		background: var(--accent);
		color: var(--text-on-accent);
		display: flex;
		align-items: center;
		justify-content: center;
		font-weight: 600;
		font-size: 15px;
		flex-shrink: 0;
	}

	.bsky-author {
		flex: 1;
		min-width: 0;
	}

	.bsky-name {
		display: block;
		font-size: 14px;
		font-weight: 600;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.bsky-handle {
		display: block;
		font-size: 12px;
		color: var(--text-secondary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.bsky-logo-sm {
		flex-shrink: 0;
		opacity: 0.6;
	}

	.bsky-text {
		font-size: 14px;
		line-height: 1.5;
		color: var(--text-primary);
		white-space: pre-wrap;
		word-break: break-word;
		margin-bottom: 10px;
	}

	/* Ensure text is readable when inside own (blue) bubble */
	:global(.bubble.own) .bsky-embed {
		background: rgba(255, 255, 255, 0.12);
		border-color: rgba(255, 255, 255, 0.15);
	}

	:global(.bubble.own) .bsky-embed:hover {
		background: rgba(255, 255, 255, 0.18);
	}

	:global(.bubble.own) .bsky-name,
	:global(.bubble.own) .bsky-text {
		color: var(--text-on-accent);
	}

	:global(.bubble.own) .bsky-handle,
	:global(.bubble.own) .bsky-date,
	:global(.bubble.own) .bsky-stat {
		color: rgba(255, 255, 255, 0.7);
	}

	.bsky-footer {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}

	.bsky-date {
		font-size: 12px;
		color: var(--text-tertiary);
	}

	.bsky-stats {
		display: flex;
		gap: 12px;
	}

	.bsky-stat {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: 12px;
		color: var(--text-secondary);
	}
</style>
