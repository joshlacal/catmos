/* Pre-paint Catmos theme bootstrap (CSP script-src 'self' compliant, zero inline script) */
(function () {
	try {
		var raw = localStorage.getItem('catmos-prefs');
		var prefs = raw ? JSON.parse(raw) : null;
		var legacyTheme = !prefs ? localStorage.getItem('catmos-theme') : null;
		var scheme = prefs && typeof prefs.scheme === 'string'
			? prefs.scheme
			: legacyTheme === 'light' || legacyTheme === 'dark'
				? (legacyTheme === 'dark' ? 'dim' : 'light')
				: 'system';
		var accent = prefs && typeof prefs.accent === 'string' ? prefs.accent : 'catbird';
		var contrast = prefs && prefs.contrast === 'more' ? 'more' : 'system';
		var density = prefs && prefs.density === 'compact' ? 'compact' : 'comfortable';
		var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
		var effective = scheme === 'system' ? (prefersDark ? 'dim' : 'light') : scheme;
		if (effective !== 'light' && effective !== 'dim' && effective !== 'black') {
			effective = prefersDark ? 'dim' : 'light';
		}
		var validAccents = {
			catbird: 1,
			twilight: 1,
			lavender: 1,
			sunrise: 1,
			aurora: 1,
			dusk: 1,
			midnight: 1
		};
		if (!validAccents[accent]) accent = 'catbird';
		var root = document.documentElement;
		root.setAttribute('data-theme', effective);
		root.setAttribute('data-accent', accent);
		root.setAttribute('data-contrast', contrast);
		root.setAttribute('data-density', density);
		var csMeta = document.querySelector('meta[name="color-scheme"]');
		if (csMeta) csMeta.setAttribute('content', effective === 'light' ? 'light' : 'dark');
		var tcMeta = document.querySelector('meta[name="theme-color"]');
		if (tcMeta) {
			var bg = effective === 'light' ? '#ffffff' : effective === 'black' ? '#000000' : '#111318';
			tcMeta.setAttribute('content', bg);
		}
	} catch (e) {
		document.documentElement.setAttribute('data-theme', 'dim');
	}
})();
