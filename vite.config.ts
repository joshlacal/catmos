import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import { resolve } from 'path';

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
	plugins: [
		sveltekit({ adapter: adapter({ fallback: 'index.html' }) }),
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
			'catbird-mls-web': resolve(import.meta.dirname, '../catbird-mls-web/pkg/catbird_mls_web.js')
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
