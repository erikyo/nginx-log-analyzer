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

self.addEventListener("message", (event) => {
	if (event.data?.type !== "GET_CACHED_GEOIPS" || !event.ports[0]) return;

	event.waitUntil(
		getCachedGeoIPs(event.data.ips).then((results) => {
			event.ports[0].postMessage({ type: "CACHED_GEOIPS", results });
		}),
	);
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

async function getCachedGeoIPs(ips) {
	if (!Array.isArray(ips) || ips.length === 0) return [];

	const cache = await caches.open(GEO_CACHE);
	const cached = [];

	for (const ip of ips) {
		const requestUrl = `${GEO_ENDPOINT_ORIGIN}${GEO_ENDPOINT_PATH}${encodeURIComponent(ip)}`;
		const response = await cache.match(requestUrl, { ignoreSearch: false });
		if (!response) continue;

		try {
			const data = await response.json();
			cached.push({
				...data,
				ipAddress: data.ipAddress || ip,
			});
		} catch (error) {
			console.warn(`Cached GeoIP data could not be read for ${ip}:`, error);
		}
	}

	return cached;
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
