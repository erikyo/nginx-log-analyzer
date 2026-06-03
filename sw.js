const GEO_CACHE = "geoip-cache-v1";
const GEO_ENDPOINT_ORIGIN = "https://free.freeipapi.com";
const GEO_ENDPOINT_PATH = "/api/json/";

self.addEventListener("install", (event) => {
	event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
	event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
	const request = event.request;
	if (request.method !== "GET") return;

	const url = new URL(request.url);
	if (url.origin !== GEO_ENDPOINT_ORIGIN || !url.pathname.startsWith(GEO_ENDPOINT_PATH)) {
		return;
	}

	event.respondWith(cacheGeoIPRequest(request));
});

async function cacheGeoIPRequest(request) {
	const cache = await caches.open(GEO_CACHE);
	const cached = await cache.match(request, { ignoreSearch: false });
	if (cached) return withCacheStatus(cached, "hit");

	const response = await fetch(request);
	if (response.ok) {
		await cache.put(request, response.clone());
	}

	return withCacheStatus(response, "miss");
}

function withCacheStatus(response, status) {
	const headers = new Headers(response.headers);
	headers.set("X-GeoIP-Cache", status);

	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}
