# nginx-log-analyzer

A fast, client-side log analysis utility designed to transform raw Nginx access and error logs into actionable security and operational insights. By executing entirely within the browser, it eliminates the complexity of heavyweight log aggregation stacks (such as ELK or Splunk) and ensures complete data privacy—**your log data never leaves your machine.**

[Start nginx-log-analyzer now!](https://erikyo.github.io/nginx-log-analyzer/)

<img width="1610" height="950" alt="image" src="https://github.com/user-attachments/assets/cdcac74e-0937-48a4-aa25-89b0c6f59abd" />


## Key Features

* **Zero-Backend Parsing:** Fully client-side parsing supporting Nginx `combined`, `common`, and standard Apache/Nginx error log formats up to 50 MB directly through the browser.
* **Bi-Directional Correlation:** Automatically pairs HTTP access requests with ModSecurity WAF events, `proxy_fcgi` timeouts, and upstream server errors by client IP addresses.
* **Intelligent Threat Scoring:** Features a heuristic evaluation engine (scoring 0–100) that automatically classifies IP addresses into *Legitimate*, *Suspicious*, or *Attacker* profiles based on request volume, error ratios, security log matches, and known malicious patterns.
* **Interactive Visual Timeline:** A custom canvas-based request timeline supporting drag-to-select range filters to granularly isolate automated traffic spikes or active Layer 7 DDoS windows.
* **Subnet Aggregation:** Groups client infrastructure into IPv4 `/24` and IPv6 `/48` topologies to identify distributed botnets and coordinated scanner blocks.
* **Asynchronous Privacy-First Enrichment:** Client-side GeoIP tracking via a background Service Worker that queries localized caches before using delayed, throttled micro-batches to pull geolocation metrics safely.
* **Automated Reverse DNS Analytics:** Resolves network-level targets using asynchronous, parallelized Pointer Record (PTR) lookups via JSON-over-DNS endpoints to uncover underlying network hostnames.

---

## Technical Architecture & Core Log Handling

### Algorithmic Threat Heuristics

The core engine computes an aggregate danger coefficient (`threatScore`) for each unique client profile using the following algorithmic weights:

1. **Traffic Velocity Metrics:**
* Base penalties applied asynchronously as request volumes hit structural threshold steps ($>30$, $>100$, $>500$ entries).


2. **Path Scan Detection:**
* Live RegEx scanning matches high-risk request paths and common signature footprints, including explicit extensions (`.env`, `.bak`, `.php`), specific management control panels (`/wp-admin`, `/phpmyadmin`), structural directory traversal techniques (`../`), or SQL Injection/XSS patterns (`union select`).


3. **Server-Side Security Anomalies:**
* Active Web Application Firewall (WAF) blocks automatically trigger an immediate critical threat tier bump ($+40$ points baseline, increasing scaling metrics by $+10$ points per discrete block occurrence).
* Additional threat overhead points are dynamically injected for critical diagnostic log severities (e.g., ModSecurity `CRITICAL` levels).



### Privacy & Network Architecture

```
[ Raw Log Files ] ➔ Drop into Browser Engine
                        │
                        ▼
             [ Client-Side Parser ]
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
 [ UI Layout Logic ]         [ sw.js Service Worker ]
         │                             │
         │                      Check Local Cache
         │                             │
         │                   ┌─────────┴─────────┐
         │              (Hit)▼               (Miss)▼
         │            [ Return Data ]     [ FreeIPAPI (Throttled) ]
         │                                         │
         └──────────────────────┬──────────────────┘
                                ▼
                    [ Enriched Dashboard UI ]

```

---

## Project Structure

```text
├── index.html         # Semantic, markup-clean application entrypoint
├── package.json       # Minimal dev tooling configurations
├── sw.js              # Service Worker managing client-side GeoIP Cache persistence
└── src/
    ├── app.js         # UI State Coordination, Event loops & Timeline UI Logic
    ├── parser.js      # Stateless log parsers, aggregations & regex analytics
    └── style.css      # Dark-mode styling, fluid grid displays & component tokens

```

---

## Getting Started

### Prerequisites

A modern web browser supporting ES6 modules and Service Workers (Chrome, Firefox, Safari, Edge).

### Running Locally

1. Clone the repository to your local directory:
```bash
git clone https://github.com/yourusername/nginx-log-analyzer.git
cd nginx-log-analyzer

```


2. Spin up the application using any static file server module. For convenience, npm scripts are pre-configured:
```bash
npm install
npm start

```


*Alternatively, execute directly via `npx serve`, `python -m http.server 8000`, or simply open the workspace context through a local IDE live-server extension.*
3. Open your browser and navigate to `http://localhost:3000` (or the configured host port).

---

## Development Standards

* **Strict Vanilla Blueprint:** Designed entirely with raw Modern Vanilla JavaScript, HTML5 Canvas, and CSS Custom Properties. No bulky utility framework builds or heavy node dependencies required.
* **Globalization and Syntax Rules:** All configuration schemas, comments, internal variables, and logging outputs are written strictly in **English**.
* **Performance Constraints:** Textarea buffer splitting arrays operate sequentially using specialized matching routines to preserve performance across large input strings without blocking the main browser thread.

---

## License

This project is open-source software licensed under the [MIT License](https://www.google.com/search?q=LICENSE).
