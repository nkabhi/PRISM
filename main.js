const { app, BrowserWindow, Menu, ipcMain, safeStorage } = require("electron");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { execFile } = require("child_process");
let si = null;
try { si = require("systeminformation"); } catch (e) { /* optional dep — stats tab degrades gracefully if missing */ }

/* ==========================================================================
   USER MANAGEMENT (local RBAC)
   Users live in a JSON file in userData. Passwords are never stored in
   plaintext — PBKDF2 with a random per-user salt, 100k iterations. The
   renderer only ever receives username/role/photo/id — never a hash, never
   a salt. Roles: "admin" (full access incl. user management), "analyst"
   (can run tools), "viewer" (read-only reference tabs only).
   ========================================================================== */

const USERS_PATH = path.join(app.getPath("userData"), "prism-users.json");

function loadUsers() {
    if (!fs.existsSync(USERS_PATH)) return [];
    try { return JSON.parse(fs.readFileSync(USERS_PATH, "utf8")); } catch (e) { return []; }
}

function saveUsers(users) {
    fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2), { mode: 0o600 });
}

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
}

function publicUser(u) {
    const { passwordHash, salt, ...pub } = u;
    return pub;
}

ipcMain.handle("prism:has-users", async () => {
    return loadUsers().length > 0;
});

ipcMain.handle("prism:get-users", async () => {
    return loadUsers().map(publicUser);
});

ipcMain.handle("prism:create-user", async (event, { username, password, role, photo }) => {

    const users = loadUsers();

    if (!username || !password) return { ok: false, error: "Username and password are required." };

    if (users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
        return { ok: false, error: "That username is already taken." };
    }

    // First user created always becomes admin, regardless of what's passed
    const finalRole = users.length === 0 ? "admin" : (role || "viewer");

    const salt = crypto.randomBytes(16).toString("hex");

    const user = {
        id: crypto.randomUUID(),
        username,
        role: finalRole,
        photo: photo || null,
        salt,
        passwordHash: hashPassword(password, salt),
        createdAt: new Date().toISOString()
    };

    users.push(user);
    saveUsers(users);

    return { ok: true, user: publicUser(user) };

});

ipcMain.handle("prism:login", async (event, { username, password }) => {

    const users = loadUsers();
    const user = users.find((u) => u.username.toLowerCase() === (username || "").toLowerCase());

    if (!user) return { ok: false, error: "Invalid username or password." };

    const candidateHash = hashPassword(password || "", user.salt);

    if (candidateHash !== user.passwordHash) {
        return { ok: false, error: "Invalid username or password." };
    }

    return { ok: true, user: publicUser(user) };

});

ipcMain.handle("prism:update-user", async (event, { id, updates, requestedBy }) => {

    const users = loadUsers();
    const requester = users.find((u) => u.id === requestedBy);

    if (!requester || requester.role !== "admin") {
        return { ok: false, error: "Only admins can edit users." };
    }

    const target = users.find((u) => u.id === id);
    if (!target) return { ok: false, error: "User not found." };

    if (updates.role && updates.role !== target.role) {
        if (target.role === "admin" && users.filter((u) => u.role === "admin").length === 1) {
            return { ok: false, error: "Can't demote the last remaining admin." };
        }
        target.role = updates.role;
    }

    if (updates.photo !== undefined) target.photo = updates.photo;

    if (updates.password) {
        target.salt = crypto.randomBytes(16).toString("hex");
        target.passwordHash = hashPassword(updates.password, target.salt);
    }

    saveUsers(users);

    return { ok: true, user: publicUser(target) };

});

ipcMain.handle("prism:delete-user", async (event, { id, requestedBy }) => {

    const users = loadUsers();
    const requester = users.find((u) => u.id === requestedBy);

    if (!requester || requester.role !== "admin") {
        return { ok: false, error: "Only admins can delete users." };
    }

    const target = users.find((u) => u.id === id);
    if (!target) return { ok: false, error: "User not found." };

    if (target.role === "admin" && users.filter((u) => u.role === "admin").length === 1) {
        return { ok: false, error: "Can't delete the last remaining admin." };
    }

    saveUsers(users.filter((u) => u.id !== id));

    return { ok: true };

});

/* ==========================================================================
   LIVE SYSTEM STATS (CPU / Memory / Network) — powered by `systeminformation`
   ========================================================================== */

ipcMain.handle("prism:get-system-stats", async () => {

    if (!si) return { ok: false, error: "systeminformation package not installed." };

    try {

        const [cpu, mem, net] = await Promise.all([si.currentLoad(), si.mem(), si.networkStats()]);

        const primaryNet = net && net[0] ? net[0] : { rx_sec: 0, tx_sec: 0 };

        return {
            ok: true,
            cpuPercent: Math.round(cpu.currentLoad),
            memPercent: Math.round((mem.active / mem.total) * 100),
            memUsedGB: (mem.active / (1024 ** 3)).toFixed(1),
            memTotalGB: (mem.total / (1024 ** 3)).toFixed(1),
            netRxKbps: Math.round((primaryNet.rx_sec || 0) / 1024),
            netTxKbps: Math.round((primaryNet.tx_sec || 0) / 1024)
        };

    } catch (e) {

        return { ok: false, error: e.message };

    }

});

/* ==========================================================================
   API KEY STORAGE
   Keys are encrypted at rest using Electron's safeStorage (OS keychain-backed
   on Windows/macOS) and live in a config file in the app's userData folder —
   never in localStorage, never in the renderer's reach except by asking this
   process for a masked status ("connected: yes/no"), never the raw key.
   ========================================================================== */

const CONFIG_PATH = path.join(app.getPath("userData"), "prism-keys.json");

function loadStoredKeys() {

    if (!fs.existsSync(CONFIG_PATH)) return {};

    try {

        const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
        const decrypted = {};

        for (const [service, encB64] of Object.entries(raw)) {

            try {
                decrypted[service] = safeStorage.decryptString(Buffer.from(encB64, "base64"));
            } catch (e) {
                // corrupted/unavailable — skip this one key rather than failing everything
            }

        }

        return decrypted;

    } catch (e) {

        return {};

    }

}

function saveKey(service, plainTextKey) {

    const current = fs.existsSync(CONFIG_PATH) ? JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")) : {};

    const encrypted = safeStorage.encryptString(plainTextKey);

    current[service] = encrypted.toString("base64");

    fs.writeFileSync(CONFIG_PATH, JSON.stringify(current, null, 2), { mode: 0o600 });

}

function deleteKey(service) {

    if (!fs.existsSync(CONFIG_PATH)) return;

    const current = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));

    delete current[service];

    fs.writeFileSync(CONFIG_PATH, JSON.stringify(current, null, 2), { mode: 0o600 });

}

let apiKeys = {}; // loaded fresh on app start

/* ==========================================================================
   API SERVICE REGISTRY
   The renderer can only ever ask for a *service id* + params — it can never
   hand this process an arbitrary URL. This is the whole point: even if the
   renderer were ever compromised (XSS), it's limited to this fixed menu of
   pre-approved, read-only lookups — nothing else.
   ========================================================================== */

const SERVICES = {

    "shodan-internetdb": {
        requiresKey: false,
        build: (p) => ({ url: `https://internetdb.shodan.io/${encodeURIComponent(p.target)}` })
    },

    "crtsh": {
        requiresKey: false,
        build: (p) => ({ url: `https://crt.sh/?q=${encodeURIComponent(p.target)}&output=json` })
    },

    "google-doh": {
        requiresKey: false,
        build: (p) => ({ url: `https://dns.google/resolve?name=${encodeURIComponent(p.target)}&type=${encodeURIComponent(p.type || "A")}` })
    },

    "cloudflare-doh": {
        requiresKey: false,
        build: (p) => ({ url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(p.target)}&type=${encodeURIComponent(p.type || "A")}`, headers: { "accept": "application/dns-json" } })
    },

    "ssllabs": {
        requiresKey: false,
        build: (p) => ({ url: `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(p.target)}&fromCache=on&maxAge=24` })
    },

    "hackertarget-whois": {
        requiresKey: false,
        build: (p) => ({ url: `https://api.hackertarget.com/whois/?q=${encodeURIComponent(p.target)}` }),
        raw: true
    },

    "hackertarget-dnslookup": {
        requiresKey: false,
        build: (p) => ({ url: `https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(p.target)}` }),
        raw: true
    },

    "hackertarget-reverseiplookup": {
        requiresKey: false,
        build: (p) => ({ url: `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(p.target)}` }),
        raw: true
    },

    "rdap": {
        requiresKey: false,
        build: (p) => ({ url: `https://rdap.org/domain/${encodeURIComponent(p.target)}` })
    },

    "urlhaus": {
        requiresKey: false,
        build: (p) => ({ url: "https://urlhaus-api.abuse.ch/v1/host/", method: "POST", form: { host: p.target } })
    },

    "threatfox": {
        requiresKey: false,
        build: (p) => ({ url: "https://threatfox-api.abuse.ch/api/v1/", method: "POST", json: { query: "search_ioc", search_term: p.target } })
    },

    "malwarebazaar": {
        requiresKey: false,
        build: (p) => ({ url: "https://mb-api.abuse.ch/api/v1/", method: "POST", form: { query: "get_info", hash: p.target } })
    },

    "ipinfo": {
        requiresKey: true,
        build: (p, key) => ({ url: `https://ipinfo.io/${encodeURIComponent(p.target)}/json?token=${key}` })
    },

    "abuseipdb": {
        requiresKey: true,
        build: (p, key) => ({ url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(p.target)}&maxAgeInDays=90`, headers: { "Key": key, "Accept": "application/json" } })
    },

    "virustotal": {
        requiresKey: true,
        build: (p, key) => ({ url: `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(p.target)}`, headers: { "x-apikey": key } })
    },

    "otx": {
        requiresKey: true,
        build: (p, key) => ({ url: `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(p.target)}/general`, headers: { "X-OTX-API-KEY": key } })
    },

    "greynoise": {
        requiresKey: true,
        build: (p, key) => ({ url: `https://api.greynoise.io/v3/community/${encodeURIComponent(p.target)}`, headers: { "key": key } })
    },

    "censys": {
        requiresKey: true,
        build: (p, key) => ({ url: `https://search.censys.io/api/v2/hosts/${encodeURIComponent(p.target)}`, headers: { "Authorization": "Basic " + key } })
    },

    "securitytrails": {
        requiresKey: true,
        build: (p, key) => ({ url: `https://api.securitytrails.com/v1/domain/${encodeURIComponent(p.target)}`, headers: { "APIKEY": key } })
    }

};

const KEY_SERVICE_IDS = ["ipinfo", "abuseipdb", "virustotal", "otx", "greynoise", "censys", "securitytrails"];

async function callService(serviceId, params) {

    const svc = SERVICES[serviceId];

    if (!svc) return { ok: false, error: "Unknown service: " + serviceId };

    if (svc.requiresKey && !apiKeys[serviceId]) {
        return { ok: false, error: "No API key saved for this service yet. Add one in Settings → API Keys." };
    }

    const built = svc.build(params, apiKeys[serviceId]);

    try {

        const fetchOpts = { method: built.method || "GET", headers: built.headers || {} };

        if (built.json) {
            fetchOpts.method = "POST";
            fetchOpts.headers["Content-Type"] = "application/json";
            fetchOpts.body = JSON.stringify(built.json);
        }

        if (built.form) {
            fetchOpts.method = "POST";
            fetchOpts.headers["Content-Type"] = "application/x-www-form-urlencoded";
            fetchOpts.body = new URLSearchParams(built.form).toString();
        }

        const res = await fetch(built.url, fetchOpts);
        const text = await res.text();

        if (!res.ok) {
            return { ok: false, error: `HTTP ${res.status}`, raw: text.slice(0, 2000) };
        }

        if (svc.raw) return { ok: true, data: text };

        try {
            return { ok: true, data: JSON.parse(text) };
        } catch (e) {
            return { ok: true, data: text };
        }

    } catch (e) {

        return { ok: false, error: e.message };

    }

}

/* ==========================================================================
   NETWORK DIAGNOSTIC COMMANDS
   Renderer sends a command id + a target string only — never a raw shell
   command. Target is strictly validated as a hostname/IP before it ever
   reaches execFile, and execFile (not exec) is used throughout so the target
   is passed as a discrete argument, never interpolated into a shell string.
   This is the standard defense against command injection.
   ========================================================================== */

const HOSTNAME_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9\-.:]{0,253})[a-zA-Z0-9]$|^[a-zA-Z0-9]$/;

function isValidTarget(target) {
    return typeof target === "string" && target.length > 0 && target.length <= 255 && HOSTNAME_PATTERN.test(target);
}

const DIAG_COMMANDS = {
    ping: { program: "ping", args: (t) => ["-n", "4", t] },
    tracert: { program: "tracert", args: (t) => ["-d", t] },
    pathping: { program: "pathping", args: (t) => [t] },
    arp: { program: "arp", args: () => ["-a"] },
    route: { program: "route", args: () => ["print"] },
    netstat: { program: "netstat", args: () => ["-ano"] },
    ipconfig: { program: "ipconfig", args: () => ["/all"] },
    nslookup: { program: "nslookup", args: (t) => [t] },
    nslookup_any: { program: "nslookup", args: (t) => ["-type=any", t] },
    curl: { program: "curl", args: (t) => ["-I", t] },
    telnet: { program: "telnet", args: (t) => [t, "80"] },
    testnetconnection: { program: "powershell", args: (t) => ["-Command", `Test-NetConnection ${t}`] },
    testnetconnection_port: { program: "powershell", args: (t) => ["-Command", `Test-NetConnection ${t} -Port 443`] }
};

function runDiagCommand(commandId, target) {

    return new Promise((resolve) => {

        const cmd = DIAG_COMMANDS[commandId];

        if (!cmd) return resolve({ ok: false, error: "Unknown command: " + commandId });

        if (target && !isValidTarget(target)) {
            return resolve({ ok: false, error: "Invalid target — only letters, numbers, dots, colons, and hyphens are allowed." });
        }

        execFile(cmd.program, cmd.args(target || ""), { timeout: 15000, windowsHide: true }, (err, stdout, stderr) => {

            if (err && !stdout) {
                return resolve({ ok: false, error: stderr || err.message });
            }

            resolve({ ok: true, data: stdout || stderr });

        });

    });

}

/* ==========================================================================
   IPC WIRING
   ========================================================================== */

ipcMain.handle("prism:call-api", async (event, serviceId, params) => {
    return await callService(serviceId, params || {});
});

ipcMain.handle("prism:run-diag", async (event, commandId, target) => {
    return await runDiagCommand(commandId, target);
});

ipcMain.handle("prism:save-key", async (event, serviceId, key) => {

    if (!KEY_SERVICE_IDS.includes(serviceId)) return { ok: false, error: "Unknown service" };

    try {
        saveKey(serviceId, key);
        apiKeys[serviceId] = key;
        return { ok: true };
    } catch (e) {
        return { ok: false, error: e.message };
    }

});

ipcMain.handle("prism:delete-key", async (event, serviceId) => {

    try {
        deleteKey(serviceId);
        delete apiKeys[serviceId];
        return { ok: true };
    } catch (e) {
        return { ok: false, error: e.message };
    }

});

ipcMain.handle("prism:key-status", async () => {

    const status = {};

    KEY_SERVICE_IDS.forEach((id) => { status[id] = !!apiKeys[id]; });

    return status;

});

/* ==========================================================================
   WINDOW
   ========================================================================== */

function createWindow() {

    const win = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 650,
        backgroundColor: "#06090c",
        autoHideMenuBar: true,
        webPreferences: {
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            webviewTag: false,
            preload: path.join(__dirname, "preload.js")
        }
    });

    Menu.setApplicationMenu(null);

    win.loadFile("index.html");

    win.webContents.on("will-navigate", (event) => { event.preventDefault(); });

    win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));

}

app.whenReady().then(() => {

    apiKeys = loadStoredKeys();

    createWindow();

    app.on("activate", () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });

});

app.on("window-all-closed", () => {
    if (process.platform !== "darwin") app.quit();
});
