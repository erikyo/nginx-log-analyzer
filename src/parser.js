// Parses nginx combined/common/custom log formats
// Returns structured array of log entries

const NGINX_COMBINED =
	/^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*?)"\s+"([^"]*?)"\s*(.*)$/;
const NGINX_COMMON =
	/^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\d+|-)(.*)$/;

function parseLogLine(line) {
	const trimmed = line.trim();
	if (!trimmed) return null;

	let m = NGINX_COMBINED.exec(trimmed);
	if (m) {
		return {
			ip: m[1],
			user: m[2] === "-" ? null : m[2],
			time: m[3],
			request: m[4],
			status: parseInt(m[5]),
			bytes: m[6] === "-" ? 0 : parseInt(m[6]),
			referer: m[7] === "-" ? null : m[7],
			userAgent: m[8],
			extra: m[9] || "",
		};
	}

	m = NGINX_COMMON.exec(trimmed);
	if (m) {
		return {
			ip: m[1],
			user: m[2] === "-" ? null : m[2],
			time: m[3],
			request: m[4],
			status: parseInt(m[5]),
			bytes: m[6] === "-" ? 0 : parseInt(m[6]),
			referer: null,
			userAgent: null,
			extra: m[7] || "",
		};
	}

	return null;
}

function parseLogs(text) {
	const lines = text.split("\n");
	const entries = [];
	let skipped = 0;

	for (const line of lines) {
		const entry = parseLogLine(line);
		if (entry) entries.push(entry);
		else if (line.trim()) skipped++;
	}

	return { entries, skipped, total: lines.filter((l) => l.trim()).length };
}

// Group entries by IP
function groupByIP(entries) {
	const map = {};
	for (const e of entries) {
		if (!map[e.ip]) {
			map[e.ip] = {
				ip: e.ip,
				requests: 0,
				bytes: 0,
				statuses: {},
				userAgents: new Set(),
				paths: [],
				firstSeen: e.time,
				lastSeen: e.time,
				errors: 0,
				scanPatterns: 0,
			};
		}
		const g = map[e.ip];
		g.requests++;
		g.bytes += e.bytes || 0;
		g.statuses[e.status] = (g.statuses[e.status] || 0) + 1;
		if (e.userAgent) g.userAgents.add(e.userAgent);
		if (g.paths.length < 20) g.paths.push(e.request); // sample
		g.lastSeen = e.time;
		if (e.status >= 400) g.errors++;
		if (isScanPath(e.request)) g.scanPatterns++;
	}

	// Convert sets
	for (const ip of Object.keys(map)) {
		map[ip].userAgents = [...map[ip].userAgents];
	}

	return map;
}

// Subnet grouping: /24 for IPv4, /48 for IPv6
function getSubnet(ip) {
	if (ip.includes(":")) {
		// IPv6 - group by /48 (first 3 groups)
		const parts = ip.split(":");
		return parts.slice(0, 3).join(":") + "::/48";
	}
	// IPv4 - group by /24
	const parts = ip.split(".");
	if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
	return ip;
}

function groupBySubnet(ipGroups) {
	const map = {};
	for (const [ip, data] of Object.entries(ipGroups)) {
		const subnet = getSubnet(ip);
		if (!map[subnet]) {
			map[subnet] = {
				subnet,
				ips: [],
				requests: 0,
				bytes: 0,
				errors: 0,
				scanPatterns: 0,
			};
		}
		map[subnet].ips.push(ip);
		map[subnet].requests += data.requests;
		map[subnet].bytes += data.bytes;
		map[subnet].errors += data.errors;
		map[subnet].scanPatterns += data.scanPatterns;
	}
	return map;
}

const SCAN_PATTERNS = [
	/\.(php|asp|aspx|env|git|bak|sql|sh|cgi|pl|py)($|\?)/i,
	/\/(wp-admin|wp-login|phpmyadmin|admin|manager|shell|c99|r57|eval)/i,
	/\/(etc\/passwd|proc\/self|\.ssh|\.bash_history)/i,
	/\/(xmlrpc|config\.xml|web\.config)/i,
	/union.*select/i,
	/\.\.\//,
	/\/?(setup|install|update)\.php/i,
];

function isScanPath(request) {
	if (!request) return false;
	return SCAN_PATTERNS.some((p) => p.test(request));
}

// Threat scoring: 0-100
function threatScore(data) {
	let score = 0;
	const errorRate = data.requests > 0 ? data.errors / data.requests : 0;
	const scanRate = data.requests > 0 ? data.scanPatterns / data.requests : 0;

	if (data.requests > 500) score += 25;
	else if (data.requests > 100) score += 15;
	else if (data.requests > 30) score += 5;

	score += Math.min(30, Math.round(errorRate * 50));
	score += Math.min(30, Math.round(scanRate * 60));

	if (data.userAgents.length === 0) score += 5; // no UA
	if (
		data.userAgents.some((ua) =>
			/bot|crawl|spider|scan|nikto|sqlmap|nmap|masscan|zgrab/i.test(ua),
		)
	)
		score += 15;

	return Math.min(100, score);
}

function classify(score) {
	if (score >= 70) return "attacker";
	if (score >= 35) return "suspicious";
	return "legitimate";
}

function analyze(text) {
	const { entries, skipped, total } = parseLogs(text);
	const ipGroups = groupByIP(entries);
	const subnetGroups = groupBySubnet(ipGroups);

	const ips = Object.values(ipGroups)
		.map((d) => ({
			...d,
			threatScore: threatScore(d),
			classification: classify(threatScore(d)),
			subnet: getSubnet(d.ip),
		}))
		.sort((a, b) => b.requests - a.requests);

	const subnets = Object.values(subnetGroups).sort(
		(a, b) => b.requests - a.requests,
	);

	return {
		meta: {
			totalLines: total,
			parsedEntries: entries.length,
			skippedLines: skipped,
			uniqueIPs: ips.length,
			uniqueSubnets: subnets.length,
			totalRequests: entries.length,
			totalBytes: entries.reduce((s, e) => s + (e.bytes || 0), 0),
			timeRange: entries.length
				? { first: entries[0].time, last: entries[entries.length - 1].time }
				: null,
		},
		ips,
		subnets,
	};
}

export { analyze, parseLogs, groupByIP, groupBySubnet, threatScore, classify };
