import adapter from '@sveltejs/adapter-static';
import { resolve } from 'path';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		adapter: adapter({
			fallback: 'index.html'
		}),
		// Point tsserver (via svelte-check) at the real wasm-bindgen types.
		// Vite's resolve.alias already maps this for bundling; this mirrors
		// it for type-checking so we don't need a hand-declared .d.ts shim.
		alias: {
			'catbird-mls-web': resolve('../catbird-mls-web/pkg/catbird_mls_web.d.ts')
		}
	}
};

export default config;
