# PRISM — Network & Security Toolkit

A Windows desktop app (Electron) that puts your everyday network/security workflow in one place:

- **Live Network Diagnostics** — ping, tracert, pathping, arp, netstat, nslookup, curl, and more, run directly from the app via safely-validated system commands
- **Live DNS Toolkit** — DNS lookups plus reference links for enumeration/intel tools
- **476+ tools mapped** across 26 categories (port scanning, packet capture, OSINT, threat intel, wireless, AD security, cloud, SIEM, and more) — color-coded by risk/severity, with guidance and official links
- **Live Intel APIs** — no-key lookups (Shodan InternetDB, crt.sh, DNS-over-HTTPS, SSL Labs, HackerTarget, RDAP, abuse.ch) plus optional free-tier API key integrations (IPinfo, AbuseIPDB, VirusTotal, OTX, GreyNoise, Censys, SecurityTrails)
- **Live system monitor** — CPU / memory / network throughput charts on the dashboard
- **User accounts + RBAC** — admin / analyst / viewer roles, local accounts with photo avatars
- **An embedded live MCQ quiz** — "The CyberSecurity Guy" — for streaming/practice

## Requirements

- [Node.js](https://nodejs.org) (LTS version)
- Windows, for the packaged `.exe` build (the app itself is cross-platform since it's Electron, but the diagnostic commands are written for Windows)

## Setup

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPO-NAME.git
cd YOUR-REPO-NAME
npm install
```

## Run it

```bash
npm start
```

## Build a distributable `.exe`

```bash
npm run dist
```

Output lands in `dist/` as a portable `.exe` — no installer needed, just double-click to run.

## Project structure

```
main.js       — Electron entry point: window creation, IPC handlers,
                the API service registry, diagnostic command execution,
                user management, and system stats
preload.js    — the narrow, safe bridge exposed to the page (window.prismAPI)
index.html    — the entire PRISM UI (sidebar, dashboard, all tool panels)
quiz.html     — the embedded live quiz, loaded in an iframe from index.html
package.json  — dependencies + electron-builder config
```

## Security notes

- API keys are encrypted at rest via Electron's `safeStorage` (OS keychain-backed) — never stored in plaintext, never exposed to the page.
- User passwords are hashed with PBKDF2 (100k iterations, per-user salt) — never stored in plaintext.
- All API calls and system commands are dispatched from the Electron **main process** through a fixed, pre-approved registry — the renderer (the web page) can never send an arbitrary URL or shell command, only a known service/command ID plus a validated target.
- Diagnostic command targets are validated against a strict hostname/IP pattern before ever reaching `execFile` (no shell interpolation — command injection is not possible through this input).

## License

See `LICENSE.txt`.
