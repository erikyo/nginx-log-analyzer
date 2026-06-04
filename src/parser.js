// Parses nginx combined/common/custom log formats
// Returns structured array of log entries

const NGINX_COMBINED =
	/^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*?)"\s+"([^"]*?)"\s*(.*)$/;
const NGINX_COMMON =
	/^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\d+|-)(.*)$/;
const APACHE_ERROR_LINE = /^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)$/;

function parseLogLine(line) {
	const trimmed = line.trim();
	if (!trimmed) return null;

	let m = NGINX_COMBINED.exec(trimmed);
	if (m) {
		return {
			ip: m[1],
			user: m[2] === "-" ? null : m[2],
			time: m[3],
			timestamp: parseNginxTime(m[3]),
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
			timestamp: parseNginxTime(m[3]),
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

const MONTHS = {
	Jan: 0,
	Feb: 1,
	Mar: 2,
	Apr: 3,
	May: 4,
	Jun: 5,
	Jul: 6,
	Aug: 7,
	Sep: 8,
	Oct: 9,
	Nov: 10,
	Dec: 11,
};

function parseNginxTime(value) {
	const match = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(value);
	if (!match) return null;

	const [, day, monthName, year, hour, minute, second, sign, offsetHour, offsetMinute] = match;
	const month = MONTHS[monthName];
	if (month == null) return null;

	const offsetMs = (Number(offsetHour) * 60 + Number(offsetMinute)) * 60 * 1000;
	const localAsUtc = Date.UTC(Number(year), month, Number(day), Number(hour), Number(minute), Number(second));
	return sign === "+" ? localAsUtc - offsetMs : localAsUtc + offsetMs;
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

function parseErrorLogLine(line) {
	const trimmed = line.trim();
	if (!trimmed) return null;

	const match = APACHE_ERROR_LINE.exec(trimmed);
	if (!match) return null;

	const [, time, moduleInfo, rest] = match;
	const client = /\[client\s+([^\]:\s]+)(?::\d+)?\]/.exec(trimmed);
	if (!client) return null;

	const fields = {};
	for (const field of trimmed.matchAll(/\[([a-z_]+)\s+"([^"]*)"\]/gi)) {
		fields[field[1].toLowerCase()] = field[2];
	}

	const [module = "", level = ""] = moduleInfo.split(":");
	const isWafBlock = /ModSecurity:\s+Access denied/i.test(trimmed);
	const isTimeout = /timeout specified has expired|AH01075|polling/i.test(trimmed);
	const statusMatch = /Access denied with code\s+(\d{3})/i.exec(trimmed);

	return {
		ip: client[1],
		time,
		timestamp: parseApacheErrorTime(time),
		module,
		level,
		status: statusMatch ? Number(statusMatch[1]) : null,
		message: fields.msg || summarizeErrorMessage(rest),
		ruleId: fields.id || "",
		severity: fields.severity || "",
		hostname: fields.hostname || "",
		uri: fields.uri || "",
		file: fields.file || "",
		line: fields.line || "",
		tags: [...trimmed.matchAll(/\[tag\s+"([^"]*)"\]/gi)].map((m) => m[1]),
		isWafBlock,
		isTimeout,
		raw: trimmed,
	};
}

function summarizeErrorMessage(value) {
	const withoutMeta = value.replace(/\s*\[[^\]]+\]/g, " ").replace(/\s+/g, " ").trim();
	return withoutMeta.slice(0, 240);
}

function parseErrorLogs(text = "") {
	const lines = text.split("\n");
	const entries = [];
	let skipped = 0;

	for (const line of lines) {
		const entry = parseErrorLogLine(line);
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
				serverErrors: 0,
				wafBlocks: 0,
				timeoutErrors: 0,
				errorSamples: [],
				errorUris: new Set(),
				wafRules: new Set(),
				wafMessages: new Set(),
				errorModules: new Set(),
				errorSeverities: {},
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

function mergeErrorEntries(ipGroups, errorEntries) {
	for (const e of errorEntries) {
		if (!ipGroups[e.ip]) {
			ipGroups[e.ip] = {
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
				serverErrors: 0,
				wafBlocks: 0,
				timeoutErrors: 0,
				errorSamples: [],
				errorUris: new Set(),
				wafRules: new Set(),
				wafMessages: new Set(),
				errorModules: new Set(),
				errorSeverities: {},
			};
		}

		const group = ipGroups[e.ip];
		group.serverErrors++;
		group.lastSeen = e.time;
		if (e.isWafBlock) group.wafBlocks++;
		if (e.isTimeout) group.timeoutErrors++;
		if (e.uri) group.errorUris.add(e.uri);
		if (e.ruleId) group.wafRules.add(e.ruleId);
		if (e.message) group.wafMessages.add(e.message);
		if (e.module) group.errorModules.add(e.module);
		if (e.severity) group.errorSeverities[e.severity] = (group.errorSeverities[e.severity] || 0) + 1;
		if (group.errorSamples.length < 20) group.errorSamples.push(e);
	}

	for (const ip of Object.keys(ipGroups)) {
		const group = ipGroups[ip];
		if (group.userAgents instanceof Set) group.userAgents = [...group.userAgents];
		if (group.errorUris instanceof Set) group.errorUris = [...group.errorUris];
		if (group.wafRules instanceof Set) group.wafRules = [...group.wafRules];
		if (group.wafMessages instanceof Set) group.wafMessages = [...group.wafMessages];
		if (group.errorModules instanceof Set) group.errorModules = [...group.errorModules];
	}

	return ipGroups;
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

	if (data.wafBlocks > 0) score += Math.min(65, 40 + data.wafBlocks * 10);
	if (data.timeoutErrors > 0) score += Math.min(15, data.timeoutErrors * 5);
	if (data.wafRules?.length > 1) score += Math.min(15, data.wafRules.length * 3);
	if (data.errorSeverities?.CRITICAL) score += 15;

	return Math.min(100, score);
}

function classify(score) {
	if (score >= 70) return "attacker";
	if (score >= 35) return "suspicious";
	return "legitimate";
}

function analyzeEntries(entries, skipped = 0, total = entries.length, errorEntries = [], errorSkipped = 0, errorTotal = errorEntries.length) {
	const ipGroups = mergeErrorEntries(groupByIP(entries), errorEntries);
	const subnetGroups = groupBySubnet(ipGroups);
	const requestTimeRange = buildTimeRange(entries);
	const errorTimeRange = buildTimeRange(errorEntries);
	const combinedTimeRange = buildTimeRange([...entries, ...errorEntries]);

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
			errorLogLines: errorTotal,
			parsedErrorEntries: errorEntries.length,
			skippedErrorLines: errorSkipped,
			wafBlocks: errorEntries.filter((e) => e.isWafBlock).length,
			timeoutErrors: errorEntries.filter((e) => e.isTimeout).length,
			uniqueIPs: ips.length,
			uniqueSubnets: subnets.length,
			totalRequests: entries.length,
			totalBytes: entries.reduce((s, e) => s + (e.bytes || 0), 0),
			requestTimeRange,
			errorTimeRange,
			timeRange: entries.length || errorEntries.length
				? combinedTimeRange
				: null,
		},
		ips,
		subnets,
		entries,
		errorEntries,
	};
}

function analyze(text, errorText = "") {
	const { entries, skipped, total } = parseLogs(text);
	const errorLog = parseErrorLogs(errorText);
	return analyzeEntries(entries, skipped, total, errorLog.entries, errorLog.skipped, errorLog.total);
}

function buildTimeRange(entries) {
	const timedEntries = entries.filter((e) => Number.isFinite(e.timestamp));
	const firstTimed = timedEntries.length ? Math.min(...timedEntries.map((e) => e.timestamp)) : null;
	const lastTimed = timedEntries.length ? Math.max(...timedEntries.map((e) => e.timestamp)) : null;

	return entries.length
		? {
			first: firstTimed != null ? firstTimed : entries[0]?.time,
			last: lastTimed != null ? lastTimed : entries[entries.length - 1]?.time,
			hasTimestamps: firstTimed != null && lastTimed != null,
		}
		: null;
}

function parseApacheErrorTime(value) {
	const match = /^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(\d{4})$/.exec(value);
	if (!match) return null;

	const [, monthName, day, hour, minute, second, year] = match;
	const month = MONTHS[monthName];
	if (month == null) return null;

	return Date.UTC(Number(year), month, Number(day), Number(hour), Number(minute), Number(second));
}

export { analyze, analyzeEntries, parseLogs, parseErrorLogs, groupByIP, groupBySubnet, threatScore, classify, parseNginxTime, parseApacheErrorTime };
