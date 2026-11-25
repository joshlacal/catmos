<script module lang="ts">
	export const ICON_NAMES = [
		'catbird',
		'shield',
		'search',
		'plus',
		'settings',
		'sidebar',
		'info',
		'send',
		'paperclip',
		'mic',
		'smile',
		'reply',
		'more-horizontal',
		'more-vertical',
		'x',
		'check',
		'check-double',
		'chevron-left',
		'chevron-down',
		'chevron-right',
		'pin',
		'bell',
		'bell-off',
		'lock',
		'alert-triangle',
		'refresh',
		'trash',
		'copy',
		'download',
		'log-out',
		'user-plus',
		'users',
		'user',
		'flag',
		'ban',
		'shield-alert',
		'play',
		'pause',
		'square',
		'edit',
		'external-link',
		'command',
		'keyboard',
		'sun',
		'moon',
		'contrast',
		'wifi-off',
		'arrow-down'
	] as const;

	export type IconName = (typeof ICON_NAMES)[number];
</script>

<script lang="ts">
	let {
		name,
		size = 18,
		class: className = '',
		label
	}: {
		name: IconName;
		size?: number;
		class?: string;
		label?: string;
	} = $props();

	const isLabeled = $derived(Boolean(label && label.trim().length > 0));
</script>

{#if name === 'catbird'}
	<svg
		width={size}
		height={size}
		viewBox="0 0 108 108"
		fill="none"
		class={`catmos-icon ${className}`.trim()}
		role={isLabeled ? 'img' : undefined}
		aria-label={isLabeled ? label : undefined}
		aria-hidden={isLabeled ? undefined : 'true'}
		focusable="false"
	>
		<g transform="translate(54 55) scale(1.38) translate(-53.99 -53.76)">
			<path
				fill="#A6ABB3"
				d="M48.85,30.75 L55.32,32.66 L61.71,36.50 L66.43,41.29 L70.82,48.01 L87.20,53.28 L71.86,60.47 L69.30,68.14 L66.59,72.94 L63.55,75.34 L58.91,76.77 L49.80,76.30 L38.46,71.98 L27.27,63.35 L21.36,54.24 L20.48,47.05 L23.83,40.81 L31.35,34.10 L40.30,30.75 Z"
			/>
			<path fill="#1C1C1E" d="M58.90,48.40 L87.50,53.80 L62.00,61.10 Z" />
			<path
				fill="#1C1C1E"
				d="M38.78,45.93 a6.95,6.95 0 1,0 13.90,0 a6.95,6.95 0 1,0 -13.90,0 Z"
			/>
			<path
				fill="#FFFFFF"
				d="M46.13,43.61 a2.40,2.40 0 1,0 4.80,0 a2.40,2.40 0 1,0 -4.80,0 Z"
			/>
		</g>
	</svg>
{:else}
	<svg
		width={size}
		height={size}
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="1.75"
		stroke-linecap="round"
		stroke-linejoin="round"
		class={`catmos-icon ${className}`.trim()}
		role={isLabeled ? 'img' : undefined}
		aria-label={isLabeled ? label : undefined}
		aria-hidden={isLabeled ? undefined : 'true'}
		focusable="false"
	>
		{#if name === 'shield'}
			<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
		{:else if name === 'search'}
			<circle cx="11" cy="11" r="8" />
			<path d="m21 21-4.3-4.3" />
		{:else if name === 'plus'}
			<path d="M5 12h14" />
			<path d="M12 5v14" />
		{:else if name === 'settings'}
			<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
			<circle cx="12" cy="12" r="3" />
		{:else if name === 'sidebar'}
			<rect x="3" y="3" width="18" height="18" rx="2" />
			<path d="M9 3v18" />
		{:else if name === 'info'}
			<circle cx="12" cy="12" r="10" />
			<path d="M12 16v-4" />
			<path d="M12 8h.01" />
		{:else if name === 'send'}
			<path d="m22 2-7 20-4-9-9-4Z" />
			<path d="M22 2 11 13" />
		{:else if name === 'paperclip'}
			<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48" />
		{:else if name === 'mic'}
			<path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z" />
			<path d="M19 10v2a7 7 0 0 1-14 0v-2" />
			<line x1="12" x2="12" y1="19" y2="22" />
		{:else if name === 'smile'}
			<circle cx="12" cy="12" r="10" />
			<path d="M8 14s1.5 2 4 2 4-2 4-2" />
			<line x1="9" x2="9.01" y1="9" y2="9" />
			<line x1="15" x2="15.01" y1="9" y2="9" />
		{:else if name === 'reply'}
			<polyline points="9 17 4 12 9 7" />
			<path d="M20 18v-2a4 4 0 0 0-4-4H4" />
		{:else if name === 'more-horizontal'}
			<circle cx="12" cy="12" r="1" />
			<circle cx="19" cy="12" r="1" />
			<circle cx="5" cy="12" r="1" />
		{:else if name === 'more-vertical'}
			<circle cx="12" cy="12" r="1" />
			<circle cx="12" cy="5" r="1" />
			<circle cx="12" cy="19" r="1" />
		{:else if name === 'x'}
			<path d="M18 6 6 18" />
			<path d="m6 6 12 12" />
		{:else if name === 'check'}
			<path d="M20 6 9 17l-5-5" />
		{:else if name === 'check-double'}
			<path d="M18 6 7 17l-5-5" />
			<path d="m22 10-7.5 7.5L13 16" />
		{:else if name === 'chevron-left'}
			<path d="m15 18-6-6 6-6" />
		{:else if name === 'chevron-down'}
			<path d="m6 9 6 6 6-6" />
		{:else if name === 'chevron-right'}
			<path d="m9 18 6-6-6-6" />
		{:else if name === 'pin'}
			<path d="M12 17v5" />
			<path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z" />
		{:else if name === 'bell'}
			<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
			<path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
		{:else if name === 'bell-off'}
			<path d="M8.7 3A6 6 0 0 1 18 8a21.3 21.3 0 0 0 .6 5" />
			<path d="M17 17H3s3-2 3-9a4.67 4.67 0 0 1 .3-1.7" />
			<path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
			<path d="m2 2 20 20" />
		{:else if name === 'lock'}
			<rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
			<path d="M7 11V7a5 5 0 0 1 10 0v4" />
		{:else if name === 'alert-triangle'}
			<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
			<path d="M12 9v4" />
			<path d="M12 17h.01" />
		{:else if name === 'refresh'}
			<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
			<path d="M21 3v5h-5" />
			<path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
			<path d="M3 21v-5h5" />
		{:else if name === 'trash'}
			<path d="M3 6h18" />
			<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" />
			<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" />
			<line x1="10" x2="10" y1="11" y2="17" />
			<line x1="14" x2="14" y1="11" y2="17" />
		{:else if name === 'copy'}
			<rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
			<path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
		{:else if name === 'download'}
			<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
			<polyline points="7 10 12 15 17 10" />
			<line x1="12" x2="12" y1="15" y2="3" />
		{:else if name === 'log-out'}
			<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
			<polyline points="16 17 21 12 16 7" />
			<line x1="21" x2="9" y1="12" y2="12" />
		{:else if name === 'user-plus'}
			<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
			<circle cx="9" cy="7" r="4" />
			<line x1="19" x2="19" y1="8" y2="14" />
			<line x1="22" x2="16" y1="11" y2="11" />
		{:else if name === 'users'}
			<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
			<circle cx="9" cy="7" r="4" />
			<path d="M22 21v-2a4 4 0 0 0-3-3.87" />
			<path d="M16 3.13a4 4 0 0 1 0 7.75" />
		{:else if name === 'user'}
			<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
			<circle cx="12" cy="7" r="4" />
		{:else if name === 'flag'}
			<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" />
			<line x1="4" x2="4" y1="22" y2="15" />
		{:else if name === 'ban'}
			<circle cx="12" cy="12" r="10" />
			<path d="m4.9 4.9 14.2 14.2" />
		{:else if name === 'shield-alert'}
			<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
			<path d="M12 8v4" />
			<path d="M12 16h.01" />
		{:else if name === 'play'}
			<polygon points="6 3 20 12 6 21 6 3" />
		{:else if name === 'pause'}
			<rect x="6" y="4" width="4" height="16" rx="1" />
			<rect x="14" y="4" width="4" height="16" rx="1" />
		{:else if name === 'square'}
			<rect x="5" y="5" width="14" height="14" rx="2" />
		{:else if name === 'edit'}
			<path d="M12 20h9" />
			<path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
		{:else if name === 'external-link'}
			<path d="M15 3h6v6" />
			<path d="M10 14 21 3" />
			<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
		{:else if name === 'command'}
			<path d="M15 6v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3" />
		{:else if name === 'keyboard'}
			<rect width="20" height="16" x="2" y="4" rx="2" />
			<path d="M6 8h.01" />
			<path d="M10 8h.01" />
			<path d="M14 8h.01" />
			<path d="M18 8h.01" />
			<path d="M8 12h.01" />
			<path d="M12 12h.01" />
			<path d="M16 12h.01" />
			<path d="M7 16h10" />
		{:else if name === 'sun'}
			<circle cx="12" cy="12" r="4" />
			<path d="M12 2v2" />
			<path d="M12 20v2" />
			<path d="m4.93 4.93 1.41 1.41" />
			<path d="m17.66 17.66 1.41 1.41" />
			<path d="M2 12h2" />
			<path d="M20 12h2" />
			<path d="m6.34 17.66-1.41 1.41" />
			<path d="m19.07 4.93-1.41 1.41" />
		{:else if name === 'moon'}
			<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
		{:else if name === 'contrast'}
			<circle cx="12" cy="12" r="10" />
			<path d="M12 18a6 6 0 0 0 0-12v12z" />
		{:else if name === 'wifi-off'}
			<path d="M12 20h.01" />
			<path d="M8.5 16.429a5 5 0 0 1 7 0" />
			<path d="M5 12.859a10 10 0 0 1 5.17-2.69" />
			<path d="M19 12.859a10 10 0 0 0-2.007-1.523" />
			<path d="M2 8.82a15 15 0 0 1 4.177-2.643" />
			<path d="M22 8.82a15 15 0 0 0-11.288-3.764" />
			<path d="m2 2 20 20" />
		{:else if name === 'arrow-down'}
			<path d="M12 5v14" />
			<path d="m19 12-7 7-7-7" />
		{/if}
	</svg>
{/if}

<style>
	.catmos-icon {
		display: inline-block;
		flex-shrink: 0;
		vertical-align: middle;
	}
</style>
