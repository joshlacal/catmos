<script lang="ts">
	import Avatar from './Avatar.svelte';
	import Icon from './Icon.svelte';

	let {
		url,
		inOwnBubble = false
	}: {
		url: string;
		inOwnBubble?: boolean;
	} = $props();

	interface BlueskyPostData {
		author: {
			displayName?: string;
			handle: string;
			avatar?: string;
		};
		text: string;
		createdAt: string;
		likeCount?: number;
		repostCount?: number;
		replyCount?: number;
	}

	interface ParsedPostRef {
		handle: string;
		rkey: string;
	}

	const dateFormatter = new Intl.DateTimeFormat(undefined, {
		month: 'short',
		day: 'numeric',
		year: 'numeric'
	});

	let post = $state<BlueskyPostData | null>(null);
	let loading = $state(true);
	let failed = $state(false);

	function parsePostUrl(input: string): ParsedPostRef | null {
		const bskyMatch = input.match(
			/https:\/\/bsky\.app\/profile\/([^/\s?#]+)\/post\/([a-zA-Z0-9]+)/
		);
		if (bskyMatch) {
			return { handle: bskyMatch[1], rkey: bskyMatch[2] };
		}

		const atMatch = input.match(
			/at:\/\/(did:[^/\s?#]+)\/app\.bsky\.feed\.post\/([a-zA-Z0-9]+)/
		);
		if (atMatch) {
			return { handle: atMatch[1], rkey: atMatch[2] };
		}

		return null;
	}

	function validateHttpsUrl(candidate: string): string | null {
		try {
			const parsedUrl = new URL(candidate);
			if (parsedUrl.protocol === 'https:') {
				return parsedUrl.toString();
			}
		} catch {
			// Malformed URL
		}
		return null;
	}

	let parsedRef = $derived(parsePostUrl(url));

	let safeHttpsUrl = $derived.by(() => {
		if (parsedRef) {
			const profileSegment = post?.author.handle || parsedRef.handle;
			return validateHttpsUrl(
				`https://bsky.app/profile/${encodeURIComponent(profileSegment)}/post/${encodeURIComponent(parsedRef.rkey)}`
			);
		}
		return validateHttpsUrl(url);
	});

	$effect(() => {
		const ref = parsedRef;
		if (!ref) {
			post = null;
			failed = true;
			loading = false;
			return;
		}

		const controller = new AbortController();
		loading = true;
		failed = false;
		post = null;

		(async () => {
			try {
				let atUri: string;
				if (ref.handle.startsWith('did:')) {
					atUri = `at://${ref.handle}/app.bsky.feed.post/${ref.rkey}`;
				} else {
					const resolveRes = await fetch(
						`https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(ref.handle)}`,
						{ signal: controller.signal }
					);
					if (!resolveRes.ok) throw new Error('Handle lookup failed');
					const resolved = (await resolveRes.json()) as { did?: string };
					if (!resolved.did) throw new Error('Missing DID');
					atUri = `at://${resolved.did}/app.bsky.feed.post/${ref.rkey}`;
				}

				const threadRes = await fetch(
					`https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=${encodeURIComponent(atUri)}&depth=0`,
					{ signal: controller.signal }
				);
				if (!threadRes.ok) throw new Error('Post lookup failed');
				const data = (await threadRes.json()) as {
					thread?: {
						post?: {
							author?: { displayName?: string; handle?: string; avatar?: string };
							record?: { text?: string; createdAt?: string };
							indexedAt?: string;
							likeCount?: number;
							repostCount?: number;
							replyCount?: number;
						};
					};
				};

				const p = data.thread?.post;
				if (!p) throw new Error('Post missing from thread');
				if (controller.signal.aborted) return;

				post = {
					author: {
						displayName: p.author?.displayName,
						handle: p.author?.handle ?? ref.handle,
						avatar: p.author?.avatar
					},
					text: p.record?.text ?? '',
					createdAt: p.record?.createdAt ?? p.indexedAt ?? '',
					likeCount: p.likeCount,
					repostCount: p.repostCount,
					replyCount: p.replyCount
				};
				loading = false;
			} catch {
				if (controller.signal.aborted) return;
				failed = true;
				loading = false;
			}
		})();

		return () => {
			controller.abort();
		};
	});

	function formatDate(iso: string): string {
		if (!iso) return '';
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '';
		return dateFormatter.format(d);
	}

	function formatCount(n: number | undefined): string {
		if (!n || n <= 0) return '';
		if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
		return String(n);
	}
</script>

{#if loading}
	<div class="bsky-embed bsky-embed-loading" class:own={inOwnBubble}>
		<progress class="catmos-progress bsky-progress" aria-label="Loading Bluesky post"></progress>
		<span class="bsky-loading-text">Loading Bluesky post</span>
	</div>
{:else if !failed && post && safeHttpsUrl}
	<a
		href={safeHttpsUrl}
		target="_blank"
		rel="noopener noreferrer"
		class="bsky-embed"
		class:own={inOwnBubble}
	>
		<div class="bsky-header">
			<Avatar
				src={post.author.avatar ?? null}
				name={post.author.displayName ?? post.author.handle}
				id={post.author.handle}
				size={32}
				shape="circle"
			/>
			<div class="bsky-author">
				{#if post.author.displayName}
					<span class="bsky-name">{post.author.displayName}</span>
				{/if}
				<span class="bsky-handle">@{post.author.handle}</span>
			</div>
			<svg
				width="16"
				height="16"
				viewBox="0 0 600 530"
				fill="currentColor"
				class="bsky-logo"
				aria-hidden="true"
				focusable="false"
			>
				<path
					d="M135.72 44.03C202.22 93.85 274.73 195.4 300 249.49c25.27-54.09 97.78-155.64 164.28-205.46C528.48-5.49 600-22.52 600 84.33c0 21.35-12.24 179.3-19.43 204.89-25.01 89.05-116.25 111.83-196.08 98.05 139.59 23.83 175.08 102.88 98.35 181.93C375.07 685.07 300 578.19 300 578.19s-75.07 106.88-182.84-9c-76.73-79.05-41.24-158.1 98.35-181.93-79.82 13.78-171.07-8.99-196.08-98.05C12.24 263.63 0 105.68 0 84.33 0-22.52 71.52-5.49 135.72 44.03z"
				/>
			</svg>
		</div>

		{#if post.text}
			<p class="bsky-text">{post.text}</p>
		{/if}

		<div class="bsky-footer">
			{#if post.createdAt}
				<span class="bsky-date tabular-nums">{formatDate(post.createdAt)}</span>
			{/if}
			<div class="bsky-stats">
				{#if post.replyCount}
					<span class="bsky-stat tabular-nums" aria-label={`${post.replyCount} replies`}>
						<Icon name="reply" size={13} />
						<span>{formatCount(post.replyCount)}</span>
					</span>
				{/if}
				{#if post.repostCount}
					<span class="bsky-stat tabular-nums" aria-label={`${post.repostCount} reposts`}>
						<Icon name="refresh" size={13} />
						<span>{formatCount(post.repostCount)}</span>
					</span>
				{/if}
				{#if post.likeCount}
					<span class="bsky-stat tabular-nums" aria-label={`${post.likeCount} likes`}>
						<svg
							width="13"
							height="13"
							viewBox="0 0 24 24"
							fill="none"
							stroke="currentColor"
							stroke-width="1.75"
							stroke-linecap="round"
							stroke-linejoin="round"
							aria-hidden="true"
							focusable="false"
						>
							<path
								d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"
							/>
						</svg>
						<span>{formatCount(post.likeCount)}</span>
					</span>
				{/if}
			</div>
		</div>
	</a>
{:else if safeHttpsUrl}
	<a
		href={safeHttpsUrl}
		target="_blank"
		rel="noopener noreferrer"
		class="bsky-embed-link"
		class:own={inOwnBubble}
	>
		<svg
			width="15"
			height="15"
			viewBox="0 0 600 530"
			fill="currentColor"
			class="bsky-logo"
			aria-hidden="true"
			focusable="false"
		>
			<path
				d="M135.72 44.03C202.22 93.85 274.73 195.4 300 249.49c25.27-54.09 97.78-155.64 164.28-205.46C528.48-5.49 600-22.52 600 84.33c0 21.35-12.24 179.3-19.43 204.89-25.01 89.05-116.25 111.83-196.08 98.05 139.59 23.83 175.08 102.88 98.35 181.93C375.07 685.07 300 578.19 300 578.19s-75.07 106.88-182.84-9c-76.73-79.05-41.24-158.1 98.35-181.93-79.82 13.78-171.07-8.99-196.08-98.05C12.24 263.63 0 105.68 0 84.33 0-22.52 71.52-5.49 135.72 44.03z"
			/>
		</svg>
		<span>View post on Bluesky</span>
		<Icon name="external-link" size={14} />
	</a>
{:else}
	<span class="bsky-fallback-text" class:own={inOwnBubble}>{url}</span>
{/if}

<style>
	.bsky-embed {
		display: block;
		margin-block-start: var(--space-2);
		padding: var(--space-3);
		background: color-mix(in oklab, var(--bg-app) 55%, transparent);
		border-radius: var(--radius-md);
		color: var(--text-primary);
		text-decoration: none;
		max-inline-size: 22rem;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.bsky-embed:hover {
		background: color-mix(in oklab, var(--bg-app) 75%, transparent);
		text-decoration: none;
	}

	.bsky-embed.own {
		background: rgba(255, 255, 255, 0.14);
		color: var(--text-on-bubble-own);
	}

	.bsky-embed.own:hover {
		background: rgba(255, 255, 255, 0.22);
	}

	.bsky-embed-loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-block-size: 5.5rem;
		justify-content: center;
	}

	.bsky-loading-text {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.bsky-embed.own .bsky-loading-text {
		color: var(--text-on-bubble-own-muted);
	}

	.bsky-embed.own :global(.bsky-progress) {
		border-color: rgba(255, 255, 255, 0.35);
		border-top-color: var(--text-on-bubble-own);
	}

	.bsky-header {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-block-end: var(--space-2);
	}

	.bsky-author {
		flex: 1;
		min-inline-size: 0;
		display: flex;
		flex-direction: column;
	}

	.bsky-name {
		font-size: var(--text-body);
		font-weight: 600;
		line-height: 1.3;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.bsky-handle {
		font-size: var(--text-sm);
		line-height: 1.35;
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.bsky-logo {
		flex-shrink: 0;
		color: var(--text-link);
	}

	.bsky-embed.own .bsky-name,
	.bsky-embed.own .bsky-text,
	.bsky-embed.own .bsky-logo {
		color: var(--text-on-bubble-own);
	}

	.bsky-embed.own .bsky-handle,
	.bsky-embed.own .bsky-date,
	.bsky-embed.own .bsky-stat {
		color: var(--text-on-bubble-own-muted);
	}

	.bsky-text {
		font-size: var(--text-body);
		line-height: 1.48;
		color: var(--text-primary);
		white-space: pre-wrap;
		word-break: break-word;
		text-wrap: pretty;
		margin-block-end: var(--space-2);
		user-select: text;
	}

	.bsky-footer {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		flex-wrap: wrap;
	}

	.bsky-date {
		font-size: var(--text-sm);
		color: var(--text-muted);
	}

	.bsky-stats {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}

	.bsky-stat {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.bsky-embed-link {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		margin-block-start: var(--space-2);
		padding-block: var(--space-2);
		padding-inline: var(--space-3);
		background: color-mix(in oklab, var(--bg-app) 55%, transparent);
		border-radius: var(--radius-sm);
		color: var(--text-link);
		font-size: var(--text-sm);
		font-weight: 500;
		text-decoration: none;
		transition: background-color var(--dur-fast) var(--ease-out);
	}

	.bsky-embed-link:hover {
		background: color-mix(in oklab, var(--bg-app) 80%, transparent);
		text-decoration: underline;
	}

	.bsky-embed-link.own {
		background: rgba(255, 255, 255, 0.16);
		color: var(--text-on-bubble-own);
	}

	.bsky-embed-link.own:hover {
		background: rgba(255, 255, 255, 0.24);
	}

	.bsky-embed-link.own .bsky-logo {
		color: var(--text-on-bubble-own);
	}

	.bsky-fallback-text {
		display: inline-block;
		margin-block-start: var(--space-1);
		font-size: var(--text-sm);
		word-break: break-all;
		color: var(--text-secondary);
	}

	.bsky-fallback-text.own {
		color: var(--text-on-bubble-own-muted);
	}
</style>
