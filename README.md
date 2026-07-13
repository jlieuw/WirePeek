# WirePeek

A lightweight, Fiddler-like HTTP(S) capture tool for Windows. It runs a local
man-in-the-middle proxy and shows every outgoing request in a clean, readable
web UI — where it's going, full headers, and decoded request/response bodies.

> ⚠️ **Responsible use.** WirePeek decrypts HTTPS by installing a local root
> CA, so it can read traffic that is normally encrypted. Use it **only on machines
> you own and to inspect your own traffic.** Intercepting other people's traffic
> may be illegal. The CA is installed only into your *CurrentUser* store and never
> machine-wide; untrust it when you're done.

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
- Windows (uses the WinINET system proxy + Windows cert store)

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

## How to capture traffic
1. Open the UI and click **Trust Cert** (installs the root CA into your
   *CurrentUser* store so HTTPS can be decrypted). You can also click **⬇ Cert**
   to download the `.cer` and inspect/import it manually.
2. Either:
   - Click **System Proxy: Off → On** to route the whole machine through WirePeek, **or**
   - Point a single app at `http://127.0.0.1:8888` (e.g.
     `Invoke-WebRequest <url> -Proxy http://127.0.0.1:8888`).
3. Generate traffic and watch it appear live. Click a row to inspect it.

When you're done, click **System Proxy: On → Off**. The proxy and system-proxy
settings are also restored automatically when the app exits.

## Security notes
- The root CA can decrypt **your** HTTPS traffic. Install/remove is **explicit and
  reversible** (Trust Cert button → uninstall via `POST /api/cert/uninstall`).
  The cert is only ever placed in the CurrentUser store, never silently machine-wide.
- **CA private key is protected.** It is stored under
  `%LOCALAPPDATA%\WirePeek\` in a directory whose ACL is restricted to your user
  account + SYSTEM (inheritance disabled), encrypted with a random 32-byte password
  that is itself DPAPI-protected (CurrentUser scope). It is **not** the old
  unencrypted, world-readable pfx in the build folder.
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
  Windows proxy automatically. If the process is *hard-killed* (e.g. `Stop-Process -Force`,
  power loss), the OS can't run cleanup, so the system proxy may stay enabled in the
  registry. WirePeek detects this on the next launch: it reconciles its state with the
  registry, shows the proxy as **On**, and disables it on clean shutdown or when you click
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

## Releasing

Releases publish to [nuget.org](https://www.nuget.org/packages/WirePeek) via the
[`.github/workflows/publish.yml`](.github/workflows/publish.yml) workflow, which uses
**Trusted Publishing (OIDC)** — no API key is stored in the repo. One-time setup:

1. On nuget.org → your username → **Trusted Publishing**, add a policy:
   - **Repository Owner:** `jlieuw`
   - **Repository:** `WirePeek`
   - **Workflow File:** `publish.yml`
   - **Environment:** *(leave blank)*
2. In GitHub → repo **Settings → Secrets and variables → Actions**, add a secret
   `NUGET_USER` set to your nuget.org **username** (profile name, not your email).

Then release by publishing a **GitHub Release** (Releases → Draft a new release →
create a tag like `v0.1.0` → Publish). The workflow packs `WirePeek` at the release's
version and pushes it to nuget.org. (First publish of a private repo's policy is
provisionally active for 7 days until the first successful push locks it to the repo —
see the nuget.org docs.) You can also trigger it manually from the **Actions** tab with
an optional version override.

## License

Licensed under the [MIT License](LICENSE). Third-party components and their
licenses are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
