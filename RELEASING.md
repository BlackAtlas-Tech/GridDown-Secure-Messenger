<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Releasing

How a firmware release reaches <https://flash.blackatlas.tech>.

---

## Short answer: do I have to run the scripts every time?

**No. CI runs them for you, and it will refuse to publish if any of them fail.**

`.github/workflows/release.yml` runs all of the following on every tag, in order,
and **stops the release if any step fails**:

| Step | What it catches |
|---|---|
| Version parity | Tag vs `GRIDDOWN_FW_VERSION` mismatch |
| `pio run -e tdeck` | Compile errors |
| `tools/verify_licenses.sh` | A dependency that changed to an incompatible licence |
| `tools/preflight.sh --quick` | Missing docs, secrets in the tree, SPDX gaps, stale claims |
| Host test harnesses | Logic regressions in crypto, Remote ID, image send |
| Manifest validation | An entry pointing at a file that isn't there |

A failed job publishes **nothing** — no release, no manifest change, no site push.
So a broken build cannot reach the flasher.

### What CI cannot do, and you must

| | Why |
|---|---|
| **Bump `GRIDDOWN_FW_VERSION` in `src/ui.h`** | CI checks it matches the tag; it will not edit it for you |
| **Test on real hardware** | Compiling proves it links. It proves nothing about radio behaviour |
| **Update docs when behaviour changes** | CI checks for *stale claims* it knows about, not for things you forgot to document |

### When to run them locally anyway

- **Before your first publish** — the full `tools/preflight.sh` (no `--quick`)
  checks git history hygiene and runs the real build. CI runs `--quick` because
  the git-history and tag checks are meaningless in a detached CI checkout, so
  **the clean-history check only ever happens locally.**
- **After changing `platformio.ini` dependencies** — run
  `tools/verify_licenses.sh` yourself so you find a licence problem before CI
  does.
- **Any time you want a faster loop** than pushing a tag.

---

## Routine release (you have already published once)

### 1. Bump the version

```bash
# src/ui.h
#define GRIDDOWN_FW_VERSION "6.71.0"
```

Add a changelog entry under `## Changelog` in `README.md`. Note any change that
breaks interoperability — packet format, key derivation, or the frequency-hop
sequence — because operators need to upgrade the whole cluster together.

### 2. Build and flash locally, then test on hardware

```bash
pio run -e tdeck -t upload
pio device monitor -b 115200
```

**This is the step CI cannot replace.** Minimum on two radios:

- [ ] Messaging both directions; voice both directions
- [ ] Tablet connects (AP password from Settings → `G`)
- [ ] **KCV matches** on both radios (Settings screen)
- [ ] FHOP converges — both radios agree on a channel
- [ ] Duress PIN strips cleanly and alerts the other radio
- [ ] Anything you changed in this release

### 3. Sanity check locally (optional but cheap)

```bash
tools/preflight.sh          # full run, includes the build
```

### 4. Commit and tag

```bash
git add -A
git commit -m "v6.71.0: <summary>"
git push

git tag v6.71.0
git push origin v6.71.0     # <-- this is what triggers the release
```

**Release candidates:** tag `v6.71.0-rc1`. The workflow strips the `-rc1` suffix
before the version-parity check (so `GRIDDOWN_FW_VERSION` stays `"6.71.0"`), marks
it a GitHub **pre-release**, and labels it `6.71.0-rc1 (Pre-release)` in the
manifest. Recommended for anything you have not field-tested extensively.

### 5. Watch the workflow

**Actions → Release.** Two jobs:

1. **Build, test and publish release** — the gates above, then creates the GitHub
   Release with the `.bin` and its `.sha256`.
2. **Publish to blackatlas.tech** — pushes the firmware and a regenerated
   `manifest.json` into the website repo under `firmware/messenger/`. Cloudflare
   Pages deploys it automatically.

### 6. Verify it actually landed

```bash
# Manifest updated, newest version first
curl -s https://blackatlas.tech/firmware/messenger/manifest.json | jq '.versions[0]'

# The served binary matches what CI built
curl -sL -o /tmp/fw.bin https://blackatlas.tech/firmware/messenger/griddown-messenger-6.71.0.bin
sha256sum /tmp/fw.bin        # compare against the SHA-256 in the GitHub Release notes
```

Then open <https://flash.blackatlas.tech> and confirm the new version appears in
the list. Flash one device from the browser end-to-end.

> Cloudflare Pages usually deploys within a minute or two. If the manifest is
> stale, check the website repo for the release-bot commit before assuming the
> workflow failed.

---

## First-time setup

Done once. Steps 1–3 are required for the site publish to work at all.

### 1. Create the publish token

A **fine-grained personal access token** with:

- Repository access: **the website repo only**
- Permissions: **Contents: Read and write**

Add it to the firmware repo as secret **`SITE_REPO_TOKEN`**
(Settings → Secrets and variables → Actions).

### 2. Confirm the website repo name

The workflow defaults to `BlackAtlas-Tech/blackatlas-site`. If that is wrong, add
a secret **`SITE_REPO`** with the correct `owner/repo`.

### 3. Confirm the flasher's manifest URL

The flasher (a separate Cloudflare Pages project) must read:

```
https://blackatlas.tech/firmware/messenger/manifest.json
```

CORS for this is already configured in the website repo's `_headers`:

```
/firmware/*
    Access-Control-Allow-Origin: https://flash.blackatlas.tech
```

Nothing to change unless you move the firmware path — in which case update
`_headers`, the flasher, and `FW_SUBDIR` in the workflow together.

### 4. Dry run before tagging anything

**Actions → Release → Run workflow**, enter a version. This builds and runs every
gate but publishes nothing. Use it to shake out workflow errors without creating a
release you have to delete.

### 5. Repository hygiene (first publish only)

```bash
rm -rf .git && git init && git add -A
git commit -m "GridDown Secure Messenger v6.70.0"
gitleaks detect --no-banner
tools/preflight.sh
```

Publish from a repository with **no prior commit history** — git history is not
retractable, and the old history very likely contains `psk.key` or populated
`.cfg` files.

---

## Manifest and version retention

`manifest.json` is regenerated from the files **actually present** in
`firmware/messenger/`, so it can never advertise a version that would 404.

The site keeps the **5 most recent** binaries (`KEEP_VERSIONS` in the workflow);
older ones are pruned to bound the website repo's git size. Pruned versions remain
permanently downloadable as **GitHub Release assets** — only the flasher's list is
trimmed.

Ordering is semver-correct: `6.71.0` ranks **above** `6.71.0-rc1`, so a release
candidate never appears above the release it precedes.

---

## If something goes wrong

| Symptom | Cause and fix |
|---|---|
| `Version mismatch — tag 'X' vs GRIDDOWN_FW_VERSION 'Y'` | Bump `src/ui.h`, delete the tag (`git tag -d v6.71.0 && git push origin :v6.71.0`), re-tag |
| Licence verification fails | A dependency changed licence. Run `tools/verify_licenses.sh` locally and resolve before re-tagging |
| Pre-flight fails on a doc check | Fix the doc, amend, force-push the tag |
| `SITE_REPO_TOKEN not set — skipping` | Expected before setup. The GitHub Release still published; upload manually (see `release.sh`) or add the secret |
| Site publish fails with 403 | Token lacks `Contents: write`, or has expired |
| Manifest updated but flasher shows the old list | Cloudflare Pages still deploying, or the flasher is caching. Hard-refresh; check the website repo for the bot commit |
| Need to withdraw a release | Delete the GitHub Release **and** revert the website-repo commit. The next release regenerates the manifest from whatever files remain |

**Re-running a release is safe.** The manifest is rebuilt from the directory, not
appended to, so a re-published tag self-heals rather than duplicating entries.

---

## One-line summary

Bump the version, test on hardware, `git push origin vX.Y.Z`. CI does the rest and
refuses to publish if anything is wrong.
