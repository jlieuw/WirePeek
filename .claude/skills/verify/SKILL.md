---
name: verify
description: How to run and verify WirePeek's web UI locally
---

# Verifying WirePeek

## Launching

- App: `dotnet run` — UI defaults to `http://127.0.0.1:5266`, proxy to `127.0.0.1:8888`. Override with `dotnet run -- --ui-port 5300 --proxy-port 9999` (`ASPNETCORE_URLS`/`--urls` are ignored; the app parses its own args and exits with a clear error if a port is taken or an option is unknown).
- If the default ports are busy, it's usually the globally installed tool: `Get-NetTCPConnection -LocalPort 5266 -State Listen` → `wirepeek.exe` from `~\.dotnet\tools`. Don't kill it blindly — it may hold the user's capture session and system-proxy setting; just pick other ports.
- In Development, static files are served from the physical `wwwroot/` (edits show live); otherwise from files embedded in the assembly — an already-running installed tool serves **stale** UI.

## Frontend-only changes

`wwwroot/` is plain static HTML/CSS/JS. When the backend isn't needed (styling, theming, rendering), serve it directly and drive with Playwright MCP:

```powershell
python -m http.server 5390 --directory wwwroot   # run_in_background
```

API/SignalR calls 404 (status shows "backend unreachable") — the UI still renders. To populate the table, inject fake sessions in the page via `browser_evaluate`:

```js
sessions.set("a1", { Id: "a1", Index: 1, Method: "GET", StatusCode: 200, HasResponse: true,
  Scheme: "https", Host: "x.test", Path: "/a", Url: "https://x.test/a",
  ResponseContentType: "application/json", ResponseBodySize: 10, DurationMs: 5,
  StartedUtc: "2026-07-15T10:01:01.120Z" });
renderList();
```

## Gotchas

- Theme: initial `data-theme` is set by an inline `<head>` script (localStorage `theme`, else OS preference). Use Playwright `page.emulateMedia({colorScheme})` (via `browser_run_code_unsafe`) to test auto-follow.
- Playwright screenshots/snapshots land in `.playwright-mcp/` and the repo root — delete them before finishing.
