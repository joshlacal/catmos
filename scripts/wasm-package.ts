import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// The tests and the Vite bundle must load the same generated package.
const sibling = new URL('../../catbird-mls-web/pkg/catbird_mls_web.js', import.meta.url);
const standalone = new URL('../src/lib/wasm-pkg/catbird_mls_web.js', import.meta.url);
export const wasmPkgEntry = fileURLToPath(existsSync(sibling) ? sibling : standalone);
