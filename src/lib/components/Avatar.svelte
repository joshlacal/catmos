<script lang="ts">
	/**
	 * Deterministic Catbird avatar component with high-contrast initial fallback.
	 * Circular for 1:1 conversations/people, squircle for groups.
	 */
	let {
		src = null,
		name,
		id,
		size = 40,
		shape = 'circle',
		alt = '',
		class: className = ''
	}: {
		src?: string | null;
		name: string;
		id?: string;
		size?: number;
		shape?: 'circle' | 'squircle';
		alt?: string;
		class?: string;
	} = $props();

	// All 7 Catbird palette fills verified >= 4.5:1 against #FFFFFF
	const AVATAR_TONES = [
		'#005EFF',
		'#4A48C4',
		'#7B4FB5',
		'#B84A14',
		'#117A78',
		'#B03A6B',
		'#3154A5'
	] as const;

	let imgFailed = $state(false);

	$effect(() => {
		// Reset load error whenever src changes
		void src;
		imgFailed = false;
	});

	function hashSeed(input: string): number {
		let hash = 2166136261;
		for (let i = 0; i < input.length; i++) {
			hash ^= input.charCodeAt(i);
			hash = Math.imul(hash, 16777619);
		}
		return hash >>> 0;
	}

	function extractInitials(raw: string): string {
		const cleaned = raw.trim().replace(/^@+/, '');
		if (!cleaned) return '?';
		const parts = cleaned.split(/[\s._-]+/).filter(Boolean);
		if (parts.length >= 2) {
			const first = Array.from(parts[0])[0] ?? '';
			const last = Array.from(parts[parts.length - 1])[0] ?? '';
			return `${first}${last}`.toUpperCase();
		}
		const chars = Array.from(cleaned);
		return chars.slice(0, 2).join('').toUpperCase();
	}

	const seed = $derived(id && id.trim().length > 0 ? id.trim() : name.trim() || 'catmos');
	const bgTone = $derived(AVATAR_TONES[hashSeed(seed) % AVATAR_TONES.length]);
	const initials = $derived(extractInitials(name));
	const showImage = $derived(Boolean(src && src.trim().length > 0 && !imgFailed));
	const isDecorative = $derived(alt === '');
	const radiusPx = $derived(shape === 'squircle' ? Math.max(8, Math.round(size * 0.28)) : 9999);
	const fontSizeRem = $derived(Math.max(0.8125, Number(((size * 0.38) / 16).toFixed(4))));
</script>

<span
	class={`catmos-avatar ${shape === 'squircle' ? 'squircle' : ''} ${className}`.trim()}
	style={`width: ${size}px; height: ${size}px; border-radius: ${radiusPx}px; ${
		showImage ? '' : `background-color: ${bgTone};`
	}`}
	role={showImage || isDecorative ? undefined : 'img'}
	aria-label={showImage || isDecorative ? undefined : alt}
	aria-hidden={showImage ? undefined : isDecorative ? 'true' : undefined}
>
	{#if showImage}
		<img
			src={src ?? ''}
			{alt}
			width={size}
			height={size}
			loading="lazy"
			decoding="async"
			onerror={() => {
				imgFailed = true;
			}}
		/>
	{:else}
		<span class="catmos-avatar-initials" style={`font-size: ${fontSizeRem}rem;`}>
			{initials}
		</span>
	{/if}
</span>

<style>
	.catmos-avatar {
		position: relative;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		overflow: hidden;
		color: #ffffff;
		user-select: none;
		vertical-align: middle;
	}

	.catmos-avatar img {
		display: block;
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	.catmos-avatar-initials {
		font-weight: 650;
		line-height: 1;
		letter-spacing: -0.01em;
		color: #ffffff;
	}
</style>
