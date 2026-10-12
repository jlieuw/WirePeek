# Releasing

Releases publish to [nuget.org](https://www.nuget.org/packages/WirePeek) via the
[`.github/workflows/publish.yml`](.github/workflows/publish.yml) workflow, which uses
**Trusted Publishing (OIDC)** — no API key is stored in the repo.

## One-time setup

1. On nuget.org → your username → **Trusted Publishing**, add a policy:
   - **Repository Owner:** `jlieuw`
   - **Repository:** `WirePeek`
   - **Workflow File:** `publish.yml`
   - **Environment:** *(leave blank)*
2. In GitHub → repo **Settings → Secrets and variables → Actions**, add a secret
   `NUGET_USER` set to your nuget.org **username** (profile name, not your email).

(First publish of a private repo's policy is provisionally active for 7 days until the
first successful push locks it to the repo — see the nuget.org docs.)

## Cutting a release

1. Bump `<Version>` in [`WirePeek.csproj`](WirePeek.csproj) and commit.
2. Publish a **GitHub Release** (Releases → Draft a new release → create a tag like
   `v0.2.0` → Publish).

The workflow packs `WirePeek` at the release's version (the tag, minus the leading `v`)
and pushes it to nuget.org. You can also trigger it manually from the **Actions** tab
with an optional version override.

## Standalone binaries and winget

Publishing a release also runs
[`.github/workflows/release-binaries.yml`](.github/workflows/release-binaries.yml), which:

1. Builds self-contained, single-file `WirePeek.exe` for `win-x64` and `win-arm64`,
   smoke-tests the x64 build, and attaches `WirePeek-<version>-win-<arch>.zip` to the release.
2. Renders the winget manifests from [`packaging/winget/`](packaging/winget/) with that
   release's URLs and SHA256 hashes, and uploads them as the workflow artifact
   `winget-manifests-<tag>`.
3. If enabled, opens the winget-pkgs PR for the new version (see below).

To build binaries for a release that already exists, run the workflow manually from the
**Actions** tab with its tag. Don't delete and re-upload a zip after it has been submitted
to winget — a changed file no longer matches the hash in the published manifest.

### First winget submission (once)

The package has to exist in [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)
before updates can be automated:

1. Download the `winget-manifests-<tag>` artifact from the workflow run and extract it.
2. Optionally test locally on Windows: `winget settings --enable LocalManifestFiles`, then
   `winget install --manifest manifests\j\jlieuw\WirePeek\<version>`.
3. Submit it: `wingetcreate submit --token <PAT> manifests\j\jlieuw\WirePeek\<version>`
   (or copy the folder into a fork of winget-pkgs and open the PR by hand).
4. Wait for validation and moderator review. An unsigned binary that installs a root CA
   can get flagged by the Defender scan; explain what the tool does in the PR if it does.

### Automatic winget updates

After the first submission is merged:

1. Fork [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) to your account.
2. Create a classic GitHub PAT with the `public_repo` scope and add it as the repository
   secret `WINGET_TOKEN`.
3. Add the repository **variable** `WINGET_AUTOPUBLISH` = `true`
   (Settings → Secrets and variables → Actions → Variables).

From then on, each release opens the winget-pkgs PR for the new version via
[winget-releaser](https://github.com/vedantmgoyal9/winget-releaser).
