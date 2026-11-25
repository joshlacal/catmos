<script lang="ts">
	import { liveMessages } from '#lib/utils/announcer.ts';

	// Alternating zero-width suffix forces screen readers to announce identical repeated messages
	// without unmounting or recreating the pre-mounted live region elements.
	const politeText = $derived(
		$liveMessages.polite
			? $liveMessages.politeSeq % 2 === 0
				? $liveMessages.polite
				: `${$liveMessages.polite}\u200B`
			: ''
	);

	const assertiveText = $derived(
		$liveMessages.assertive
			? $liveMessages.assertiveSeq % 2 === 0
				? $liveMessages.assertive
				: `${$liveMessages.assertive}\u200B`
			: ''
	);
</script>

<div class="visually-hidden" aria-live="polite" aria-atomic="true">
	{politeText}
</div>
<div class="visually-hidden" role="alert" aria-live="assertive" aria-atomic="true">
	{assertiveText}
</div>
