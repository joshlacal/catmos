import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import { resolve } from 'path';

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
	plugins: [
		sveltekit(),
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
			'catmos-web': resolve(__dirname, 'src/lib/wasm-pkg/catmos_web.js'),
			'catbird-mls-web': resolve(__dirname, '../catbird-mls-web/pkg/catbird_mls_web.js')
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
			allow: [resolve(__dirname, '..')]
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
