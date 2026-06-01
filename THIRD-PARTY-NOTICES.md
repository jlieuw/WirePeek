# Third-Party Notices

MiniFiddler includes and depends on the following third-party components. All are
used under permissive licenses compatible with this project's MIT license.

## Bundled in this repository

### @microsoft/signalr
- File: `wwwroot/lib/signalr.min.js`
- Project: https://github.com/dotnet/aspnetcore (SignalR TypeScript client)
- Copyright (c) .NET Foundation and Contributors
- License: MIT — https://github.com/dotnet/aspnetcore/blob/main/LICENSE.txt

This is the official, unmodified minified browser client, vendored so the UI
needs no build step or CDN.

## NuGet package dependencies (restored at build time, not committed)

| Package | License | Project |
|---------|---------|---------|
| Titanium.Web.Proxy | MIT | https://github.com/justcoding121/titanium-web-proxy |
| System.Security.Cryptography.ProtectedData | MIT | https://github.com/dotnet/runtime |
| Portable.BouncyCastle (transitive) | MIT | https://www.bouncycastle.org/csharp/ |
| BrotliSharpLib (transitive) | MIT | https://github.com/master131/BrotliSharpLib |

Each package retains its own copyright and license; refer to the linked projects
for full license text.
