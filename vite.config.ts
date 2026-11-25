import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { wasmPkgEntry } from './scripts/wasm-package.ts';
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import { CATMOS_SVELTEKIT_CSP_DIRECTIVES } from './src/lib/csp.ts';

const host = process.env.TAURI_DEV_HOST;
export default defineConfig({
	plugins: [
		sveltekit({
			adapter: adapter({ fallback: 'index.html' }),
			csp: {
				mode: 'hash',
				directives: CATMOS_SVELTEKIT_CSP_DIRECTIVES
			}
		}),
		// Serve .wasm files with the correct application/wasm MIME type
		// so WebAssembly.instantiateStreaming works without falling back.
		{
			name: 'wasm-content-type',
			configureServer(server) {
				server.middlewares.use((req, res, next) => {
					if (req.url?.endsWith('.wasm')) {
						res.setHeader('Content-Type', 'application/wasm');
					}
					next();
				});
			}
		}
	],
	clearScreen: false,
	resolve: {
		alias: {
			'catbird-mls-web': wasmPkgEntry
		}
	},
	worker: {
		format: 'es'
	},
	server: {
		port: 1420,
		strictPort: true,
		host: host || false,
		fs: {
			// Allow serving files from the catbird-mls-web package outside project root
			allow: [resolve(import.meta.dirname, '..')]
		},
		hmr: host
			? {
					protocol: 'ws',
					host,
					port: 1421
				}
			: undefined,
		watch: {
			ignored: ['**/src-tauri/**']
		}
	}
});
