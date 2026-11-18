# NKeeper Linux plugin

The official `linux` plugin for [NKeeper](https://github.com/OpenCraft-Solutions/NKeeper) 2.0: tools for Linux hosts over their SSH service. It lives in a repository of its own and is released on its own, so releasing it isn't a release of NKeeper (NKeeper's `docs/architecture.md` §9). Its design is §7.25 there.

## What it does

It contributes no service type: its tools open on the ssh plugin's `ssh` services, with the service's credential. Core opens the connection, checks the server's key against its trust store, asks the user about a new one and signs in; the plugin never sees a password or a key. Each tool is a stream session, so core counts it toward the user's sessions and ends it when their access changes. It needs SDK 1.3 (`>=1.3.0 <2.0.0`), for SFTP and commands that stream.

- **Files** (`linux.files`): browse, create folders, upload (in acknowledged chunks of up to 1 MB, at most 2 GB), rename, delete (files, and empty folders only), folder sizes as each is known, and downloads through one-time links that stream from the host, a folder as a zip. Works on any SSH server with SFTP, Windows' OpenSSH included.
- **Journal** (`linux.journal`): `journalctl`, newest first, 200 entries a page, filtered by time, priority, unit, program and a regular expression, and followed live. As root when the login is root or may use `sudo` without a password; otherwise as much as the login may read, and it says so.
- **SELinux** (`linux.selinux`): the mode, policy modules and denials from the audit log; a policy generated from chosen denials with `audit2allow`, to read and edit before installing; installing and removing local modules. Needs root, or `sudo` without a password. The distribution's modules are never overridden or removed.
- **Scan** (`linux.scan`, a scan action, SDK 1.4): 1.x's internal scan. One SSH login runs one read-only script, which reads:
  - the hostname, operating system, MAC address, CPU cores, memory, serial number and virtualization;
  - the listening ports;
  - the accounts that can log in;
  - the neighbour table.

  It answers the SDK's `ScanFindings`, and NKeeper's Scan dialog proposes changes from them. It needs Manage on the host.
- Journal, SELinux and the scan check `uname -s` first and say so on a host that isn't Linux.
- Changes are audited: `linux.files-mkdir`, `-delete`, `-rename`, `-upload`, `-download`, `linux.journal-read`, `linux.journal-follow`, `linux.selinux-install`, `linux.selinux-remove`, `linux.scan`.

The plugin's ID is `linux`, and it is built in: it is signed with NKeeper's official key and installed with NKeeper.

Not yet: turning each tool on or off per service, and the Linux internal scanner (NKeeper's `docs/v2-plan.md` §4.2, ServiceTool and Scanner).

## Layout

```text
backend/        the plugin: LinuxPlugin.cs, the three tools, nkeeper-plugin.json (the manifest), the project
frontend/       the Files, Journal and SELinux views: a Vite library build to dist/index.js
tests/          the backend tests, which start NKeeper's test server with this plugin loaded; tests/Linux, the fake tools
.github/        CI and the release workflow
```

It builds against NKeeper's published SDK, never core's source:

| Package | Registry | Used for |
| --- | --- | --- |
| `NKeeper.Abstractions` | GitHub Packages (NuGet) | the backend SDK |
| `NKeeper.Plugin.Build` | GitHub Packages (NuGet) | builds, packs and signs the plugin |
| `NKeeper.Testing` | GitHub Packages (NuGet) | the test server and PostgreSQL fixture |
| `@opencraft-solutions/nkeeper-sdk` | GitHub Packages (npm) | the frontend SDK, imported as `@nkeeper/sdk` |

## Building

You need the .NET 10 SDK (see `global.json`), Node.js 24 (see `.nvmrc`) and Docker for the tests.

GitHub Packages needs a token even for public packages. Make a GitHub personal access token that can read packages (`read:packages`) and give it to the build in the environment. It is never written to the repository:

```bash
export NUGET_USERNAME=<your GitHub user name>
export NUGET_AUTH_TOKEN=<token>
export NODE_AUTH_TOKEN=<token>
```

Then, from the repository root:

```bash
(cd frontend && npm ci && npm run lint && npm run typecheck)
dotnet restore NKeeper.Plugins.Linux.slnx
dotnet build NKeeper.Plugins.Linux.slnx --configuration Release
```

Building the plugin builds its frontend, packs `linux-<version>.nkp` into `artifacts/plugins/` and signs it with a development key, which the build creates under `.dev/keys/` on first use. Both are ignored by git. To load the package in a development NKeeper, point `Plugins:Directory` at `artifacts/plugins` and `Plugins:DevelopmentTrustDirectory` at `.dev/keys`.

Pinned versions: NuGet packages are locked in `packages.lock.json` (CI restores with `--locked-mode`), and npm packages in `frontend/package-lock.json`. Run `dotnet restore --force-evaluate` after changing a version.

## Testing

```bash
dotnet test NKeeper.Plugins.Linux.slnx --configuration Release
```

The tests need Docker and the internet. They start PostgreSQL and an OpenSSH server in containers, and NKeeper's test server (from `NKeeper.Testing`) with this plugin's built package and the released ssh plugin loaded (downloaded from its GitHub release and checked against the SHA-256 that NKeeper's `deploy/plugins.lock` pins). The OpenSSH server is dressed as a Linux host with fake `journalctl`, `getenforce`, `semodule`, `ausearch`, `audit2allow`, `checkmodule` and `semodule_package` (`tests/Linux/`, ported from 1.x), which answer in the real tools' formats and need root, as the real ones do; the test user gets it with `sudo`. A fake `uname` can say the host is Windows.

They cover each tool end to end: Files (list, folders, chunked uploads, rename, delete, folder sizes, one-time download links for files and folders, and who can use them), Journal (filters, paging, errors, without `sudo`, following and stopping), SELinux (status, generating, installing and removing policies, and what it refuses), the scan (trusting the key, then reading the host), a host that isn't Linux, and a user without access. The parsers have their own tests, ported from 1.x.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull request: it restores from GitHub Packages with the workflow's token, lints and type-checks the frontend, checks formatting, builds, runs the tests and packs the plugin signed with a development key, which it keeps as a build artifact.

## Releasing

1. Raise `version` in `backend/nkeeper-plugin.json` (and keep `frontend/package.json` in step), and merge it to `main`.
2. Tag the merge commit `v<version>`, for example `v0.2.0`, and push the tag.
3. `.github/workflows/release.yml` runs. It checks that the tag matches the manifest's version and is on `main`, builds and tests, and then, in the protected `release` environment, which needs an owner's approval, packs `linux-<version>.nkp` signed with the official key and publishes a GitHub release with the package and its SHA-256.

The official key's private half, `NKEEPER_RELEASE_KEY` (a PEM), is a secret of the `release` environment. It is available only to the signing job, goes to memory-backed storage for the packing step alone, and is removed when that step ends. It is never in the repository or in a log.

NKeeper's installer picks the release up when its `deploy/plugins.lock` is updated with the new URL and SHA-256.

## License

MIT, as NKeeper. See [LICENSE](LICENSE).
