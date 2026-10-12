# WirePeek

A lightweight, Fiddler-like HTTP(S) capture tool for Windows and macOS. It runs a local
man-in-the-middle proxy and shows every outgoing request in a clean, readable
web UI — where it's going, full headers, and decoded request/response bodies.

> ⚠️ **Responsible use.** WirePeek decrypts HTTPS by installing a local root
> CA, so it can read traffic that is normally encrypted. Use it **only on machines
> you own and to inspect your own traffic.** Intercepting other people's traffic
> may be illegal. The CA is trusted only for your user (Windows *CurrentUser* store /
> macOS login keychain) and never machine-wide; untrust it when you're done.

## Features
- Capture **all outgoing HTTP and HTTPS** traffic from the machine (via system proxy)
- **HTTPS decryption** using a locally-generated, trusted root CA (like Fiddler)
- Live request list: timestamp, method, status, host, path, content-type, size, timing
- Detail tabs: **Overview / Request / Response / Raw**, with pretty-printed JSON
- Global search, **per-column filters** (method/status/host/path/type), "errors only" filter, pause/resume, clear
- **Copy as cURL**
- In-memory ring buffer (last 5000 requests) — nothing written to disk

## Requirements
- .NET SDK 10 (the runtime ships with the SDK, so `dotnet tool` users need it too)
- Windows 10/11, or macOS (uses the OS system proxy and the per-user certificate store)

## Install
WirePeek is published as a .NET global tool:
```powershell
dotnet tool install --global WirePeek
```
Then launch it from anywhere:
```powershell
wirepeek
```
Update with `dotnet tool update --global WirePeek`; remove with
`dotnet tool uninstall --global WirePeek`.

## Run from source
```powershell
cd WirePeek
dotnet run
```
Then open the UI: <http://127.0.0.1:5266>

The proxy listens on `127.0.0.1:8888`. The web UI is on `127.0.0.1:5266`.
Both ports can be changed:
```powershell
dotnet run -- --ui-port 5300 --proxy-port 9999   # from source
wirepeek --ui-port 5300 --proxy-port 9999        # installed tool
```

## How to capture traffic
1. Open the UI and click **Trust Cert** so HTTPS can be decrypted. On Windows this
   installs the root CA into your *CurrentUser* store; on macOS it adds it to your
   login keychain with "Always Trust" (macOS asks for your password). You can also
   click **⬇ Cert** to download the `.cer` and inspect/import it manually.
2. Either:
   - Click **System Proxy: Off → On** to route the whole machine through WirePeek, **or**
   - Point a single app at `http://127.0.0.1:8888` (e.g.
     `Invoke-WebRequest <url> -Proxy http://127.0.0.1:8888`).
3. Generate traffic and watch it appear live. Click a row to inspect it.

When you're done, click **System Proxy: On → Off**. The proxy and system-proxy
settings are also restored automatically when the app exits.

### macOS notes
- **System Proxy** sets the HTTP and HTTPS proxy of every enabled network service
  (Wi-Fi, Ethernet, …) via `networksetup` and adds loopback to the bypass list. Your
  original settings are saved and restored exactly when you switch it off.
- Safari, Chrome, Edge and most native apps follow the system proxy and the keychain.
  Command-line tools don't: point them at the proxy yourself, e.g.
  `export HTTPS_PROXY=http://127.0.0.1:8888 HTTP_PROXY=http://127.0.0.1:8888`, and give
  them the CA (`curl --cacert`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`) — it's at
  `~/Library/Application Support/WirePeek/rootCert.pem`.
- Unlike on Windows, `HTTP_PROXY`/`HTTPS_PROXY` are **not** set for you on macOS.

## Security notes
- The root CA can decrypt **your** HTTPS traffic. Install/remove is **explicit and
  reversible** (Trust Cert button → uninstall via `POST /api/cert/uninstall`).
  The cert is only ever placed in the CurrentUser store, never silently machine-wide.
- **CA private key is protected.** On Windows it is stored under
  `%LOCALAPPDATA%\WirePeek\` in a directory whose ACL is restricted to your user
  account + SYSTEM (inheritance disabled), encrypted with a random 32-byte password
  that is itself DPAPI-protected (CurrentUser scope). On macOS it lives in
  `~/Library/Application Support/WirePeek/` (directory `0700`, key and password files
  `0600`); there is no DPAPI equivalent, so the file mode is what protects the password.
  It is **not** the old unencrypted, world-readable pfx in the build folder.
- **Upstream certificates are validated.** The proxy→server leg rejects invalid/
  untrusted server certificates instead of blindly trusting them, so it can't be
  silently MITM'd between you and the real site.
- **Loopback API is hardened** against malicious web pages: requests to `/api` and
  `/hub` must carry an expected `Host` header (blocks DNS-rebinding) and state-changing
  requests (POST/PUT/DELETE/PATCH) must carry an allowed `Origin` (blocks CSRF).
  Note: other *native* processes on this machine can still reach the loopback API —
  that is inherent to any local loopback service (Fiddler included).
- When you're done, click **Disable** on the system proxy and **uninstall** the CA so
  the machine isn't left able to decrypt your HTTPS.
- **Abnormal-exit recovery.** On a clean shutdown (or Ctrl+C) WirePeek restores the
  system proxy automatically. If the process is *hard-killed* (e.g. `Stop-Process -Force`,
  `kill -9`, power loss), the OS can't run cleanup, so the system proxy may stay enabled.
  WirePeek detects this on the next launch: it reconciles its state with the OS setting,
  shows the proxy as **On**, and restores it on clean shutdown or when you click
  **Disable**. (Fiddler has the same inherent limitation and likewise reconciles on launch.)
- Apps that ignore the system proxy or use certificate pinning won't be
  captured/decrypted — the same limitation Fiddler has.

## Architecture
A single ASP.NET Core process hosts:
- **ProxyService** — wraps [`Titanium.Web.Proxy`](https://github.com/justcoding121/titanium-web-proxy);
  generates/trusts the CA, intercepts requests/responses, decodes gzip/deflate/brotli.
- **SessionStore** — thread-safe capped in-memory store.
- **CaptureHub** (SignalR) — pushes captures to the browser in real time.
- **REST API** — `/api/sessions`, `/api/status`, `/api/clear`, `/api/cert*`, `/api/system-proxy`.
- **Static web UI** — `wwwroot/` (vanilla JS, no build step).

## API quick reference
| Method | Route | Purpose |
|--------|-------|---------|
| GET | `/api/status` | Proxy/cert/system-proxy state + counts |
| GET | `/api/sessions` | List captured request summaries |
| GET | `/api/sessions/{id}` | Full session incl. bodies |
| POST | `/api/clear` | Clear all captures |
| POST | `/api/capture` | `{ "enabled": true|false }` pause/resume |
| GET | `/api/cert` | Download root CA (`.cer`) |
| POST | `/api/cert/install` / `/api/cert/uninstall` | Trust / untrust the root CA |
| POST | `/api/system-proxy` | `{ "enabled": true|false }` toggle system proxy |

## License

Licensed under the [MIT License](LICENSE). Third-party components and their
licenses are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
