import { assets, immutable } from '$app/manifest';
import { version } from '$app/env';
import { self } from '$app/service-worker';

const CACHE_NAME = `catmos-cache-${version}`;

// Cache only content-hashed immutable bundles and static assets (never HTML documents or OAuth endpoints).
const APP_SHELL = [...immutable, ...assets]
  .filter(({ path }) => !path.startsWith('/auth/') && !path.startsWith('/oauth/'))
  .map(({ path }) => new URL(path, self.registration.scope).href);

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;

  // Skip cross-origin requests
  if (url.origin !== self.location.origin) return;

  // Never intercept or cache OAuth callbacks, client metadata, or web manifest.
  if (
    url.pathname.startsWith('/auth/') ||
    url.pathname.startsWith('/oauth/') ||
    url.pathname === '/manifest.json'
  ) {
    return;
  }

  // Network-first for HTML navigations so deploys take effect immediately and
  // returning users never initiate OAuth from a stale cached HTML shell.
  const acceptsHtml = request.headers.get('accept')?.includes('text/html') ?? false;
  if (request.mode === 'navigate' || acceptsHtml) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok && !url.search) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        })
        .catch(() =>
          caches
            .match(request)
            .then((cached) => cached ?? new Response('Offline', { status: 503 }))
        )
    );
    return;
  }

  // Network-first for API routes
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          return response;
        })
        .catch(() => caches.match(request).then((r) => r ?? new Response('Offline', { status: 503 })))
    );
    return;
  }

  // Cache-first only for content-hashed immutable bundles
  if (url.pathname.startsWith('/_app/immutable/')) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  // Network-first fallback for other same-origin static files (theme-init.js, icons, etc.)
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
        }
        return response;
      })
      .catch(() => caches.match(request).then((r) => r ?? new Response('Offline', { status: 503 })))
  );
});
