#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Pre-publication pre-flight. Runs every gate that can be checked mechanically
# and reports a single verdict. Run this from the repository root immediately
# before the first public push, and again in CI thereafter.
#
#   tools/preflight.sh            Full check
#   tools/preflight.sh --quick    Skip the firmware build (fast iteration)
#
# Exit 0 = every mechanical gate passed. Exit 1 = at least one blocker.
#
# What this CANNOT check, and you must confirm yourself:
#   * counsel sign-off on FHOP non-standard-crypto and ITAR questions
#   * hardware smoke test on two or more radios
#   * that the repository has no prior commit history containing secrets

set -uo pipefail
QUICK=0; [ "${1:-}" = "--quick" ] && QUICK=1

BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; NC=$'\033[0m'
fails=0; warns=0
pass(){ printf "  ${GRN}PASS${NC}  %s\n" "$1"; }
fail(){ printf "  ${RED}FAIL${NC}  %s\n" "$1"; fails=$((fails+1)); }
warn(){ printf "  ${YEL}WARN${NC}  %s\n" "$1"; warns=$((warns+1)); }
sect(){ printf "\n${BOLD}%s${NC}\n" "$1"; }

echo "${BOLD}GridDown — pre-publication pre-flight${NC}"

# ─────────────────────────────────────────────────────────────
sect "1. Required files present"
for f in LICENSE SECURITY.md PRIVACY.md THIRD_PARTY_NOTICES.md EXPORT_CONTROL.md \
         TRADEMARK.md CONTRIBUTING.md CODE_OF_CONDUCT.md RELEASING.md README.md .gitignore \
         tools/verify_licenses.sh .github/workflows/release.yml \
         .github/PULL_REQUEST_TEMPLATE.md; do
    [ -f "$f" ] && pass "$f" || fail "$f missing"
done

# ─────────────────────────────────────────────────────────────
sect "2. LICENSE is real GPL-3.0 (not a stub)"
if [ -f LICENSE ] && grep -q "GNU GENERAL PUBLIC LICENSE" LICENSE \
   && grep -q "Version 3, 29 June 2007" LICENSE \
   && [ "$(wc -l < LICENSE)" -gt 600 ]; then
    pass "LICENSE contains full GPL-3.0 text ($(wc -l < LICENSE) lines)"
else
    fail "LICENSE is missing, truncated, or not GPL-3.0"
fi

# ─────────────────────────────────────────────────────────────
sect "3. No secrets in the tree"
# Real credentials only — deliberately excludes identifiers that merely NAME a
# config file, and excludes test assertions that prove a secret is absent.
PAT='BEGIN [A-Z ]*PRIVATE KEY|griddown900|api[_-]?key[[:space:]]*=[[:space:]]*["'"'"'][^"'"'"']{8,}|aws_secret|-----BEGIN CERTIFICATE'
HITS=$(grep -rniE "$PAT" --include='*.cpp' --include='*.h' --include='*.md' \
       --include='*.sh' --include='*.yml' --include='*.ini' --include='*.json' . 2>/dev/null \
       | grep -vE '/\.pio/|/dist/|/build/|/node_modules/' \
       | grep -v 'test_crypto_hardening.cpp' | grep -v 'PUBLICATION_CHECKLIST' | grep -v 'preflight.sh' || true)
if [ -z "$HITS" ]; then pass "no credentials, keys, or the retired default password"
else fail "possible secret(s) found:"; echo "$HITS" | sed 's/^/          /'; fi

for f in psk.key psk_v2.bin duress.cfg appass.cfg batcal.cfg wifi_sta.cfg; do
    if find . -name "$f" -not -path './.git/*' | grep -q .; then
        fail "runtime secret file present in tree: $f"
    fi
done
[ "$fails" -eq 0 ] && pass "no runtime secret/config files in tree"

sect "3b. Secret patterns are gitignored"
for p in '\*\.key' '\*\.pem' 'duress\.cfg' 'appass\.cfg'; do
    grep -qE "^${p}$" .gitignore && pass ".gitignore covers ${p//\\/}" || fail ".gitignore missing ${p//\\/}"
done

# ─────────────────────────────────────────────────────────────
sect "3c. No internal-only or confidential documents"
# The hazard is committing these ONCE: git history is not retractable, so an
# internal competitive analysis or a working reconciliation memo that lands in a
# commit is public forever.
INTERNAL_FOUND=""
while IFS= read -r f; do
    case "$(basename "$f")" in
      *Competitive_Comparison*|*Reconciliation*|*CONFIDENTIAL*|*INTERNAL*|*Export_Classification*|PUBLICATION_CHECKLIST*)
        INTERNAL_FOUND="$INTERNAL_FOUND $f" ;;
    esac
done < <(find . -type f -print 2>/dev/null | grep -vE '/\.git/|/\.pio/|/dist/|/build/|/node_modules/')
if [ -n "$INTERNAL_FOUND" ]; then
    fail "internal-only document(s) present — remove before publishing:$INTERNAL_FOUND"
else
    pass "no competitive/reconciliation/export-classification documents in tree"
fi
# Scan document bodies for confidentiality markings too (catches renamed files)
CONF=$(grep -rliE 'INTERNAL / CONFIDENTIAL|NOT FOR DISTRIBUTION|INTERNAL USE ONLY' \
       --include='*.md' --include='*.txt' . 2>/dev/null | grep -v 'preflight.sh' || true)
[ -z "$CONF" ] && pass "no confidentiality markings in tracked text files" \
              || fail "confidentiality marking found in: $CONF"

sect "4. SPDX headers"
# Only OUR files — exclude build artefacts and vendored dependencies, which are
# gitignored and never published. EXCLUDE_RE must stay in sync with .gitignore.
EXCLUDE_RE='/\.git/|/\.pio/|/dist/|/build/|/node_modules/|/\.vscode/'
tot=0; cov=0; miss=""
while IFS= read -r f; do
    tot=$((tot+1))
    if head -6 "$f" | grep -q 'SPDX-License-Identifier'; then cov=$((cov+1)); else miss="$miss $f"; fi
done < <(find . \( -name '*.cpp' -o -name '*.h' -o -name '*.md' -o -name '*.sh' -o -name '*.yml' \) -print 2>/dev/null | grep -vE "$EXCLUDE_RE")
if [ -n "$miss" ]; then fail "missing SPDX ($cov/$tot):$miss"; else pass "SPDX on all $tot files"; fi

sect "4b. SPDX declares GPL-3.0 (consistent with LICENSE)"
BADLIC=$(find . \( -name '*.cpp' -o -name '*.h' \) -print 2>/dev/null \
         | grep -vE "$EXCLUDE_RE" \
         | xargs grep -h 'SPDX-License-Identifier:' 2>/dev/null \
         | grep -v 'GPL-3.0-or-later' || true)
[ -z "$BADLIC" ] && pass "all source SPDX tags say GPL-3.0-or-later" \
                 || { fail "inconsistent SPDX tag(s):"; echo "$BADLIC" | sed 's/^/          /'; }

sect "4c. No residual proprietary / all-rights-reserved claim"
# The point of this check is to catch OUR OWN licence claim contradicting GPL-3.0
# (e.g. a leftover "Proprietary. All rights reserved."). It must not fire on a
# third-party notice we are obliged to reproduce verbatim — the LGPL/BSD notices
# for TinyGPSPlus and others legitimately contain "All rights reserved."
# Restrict to lines that read as a licence declaration for THIS project.
PROP=$(grep -rniE '^[[:space:]]*(\*\*)?(Licence|License)[[:space:]]*:?[[:space:]]*(\*\*)?[[:space:]]*Proprietary|^[[:space:]]*Proprietary\.[[:space:]]*All rights reserved' \
       --include='*.md' . 2>/dev/null \
       | grep -vE '/\.pio/|/dist/|/build/' \
       | grep -v TRADEMARK.md | grep -v THIRD_PARTY_NOTICES.md | grep -v 'preflight.sh' || true)
[ -z "$PROP" ] && pass "no contradictory proprietary claim" \
               || { fail "contradicts GPL-3.0:"; echo "$PROP" | sed 's/^/          /'; }

# ─────────────────────────────────────────────────────────────
sect "5. Version parity"
FW=$(grep -oE '#define[[:space:]]+GRIDDOWN_FW_VERSION[[:space:]]+"[^"]+"' src/ui.h 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"')
if [ -z "$FW" ]; then fail "GRIDDOWN_FW_VERSION not found in src/ui.h"
else
    echo "$FW" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' && pass "firmware version $FW is semver" \
                                                    || fail "version '$FW' is not semver X.Y.Z"
    TAG=$(git describe --tags --exact-match 2>/dev/null || true)
    if [ -n "$TAG" ]; then
        [ "${TAG#v}" = "$FW" ] && pass "git tag $TAG matches firmware version" \
                               || fail "git tag $TAG != firmware $FW"
    else
        warn "no exact git tag on HEAD (expected before tagging a release)"
    fi
fi

# ─────────────────────────────────────────────────────────────
sect "6. Claim consistency (docs vs SECURITY.md)"
# Heuristic: flag lines that mention jam resistance WITHOUT any negation nearby.
# Disclaimers ("NOT jam resistance", "confers no meaningful anti-jam", "do not
# rely on") are the desired wording, so exclude lines carrying a negation token.
JAM=$(grep -rniE 'jam.resist|anti.?jam' --include='*.md' --include='*.cpp' --include='*.h' . 2>/dev/null \
      | grep -viE '\bnot\b|\bno\b|\bnever\b|\bdo not\b|\bdon.t\b|rather than|instead of|neither|preflight\.sh' || true)
[ -z "$JAM" ] && pass "no unqualified anti-jam claim for FHOP" \
              || { fail "FHOP anti-jam overclaim contradicts SECURITY.md:"; echo "$JAM" | sed 's/^/          /'; }

UNDET=$(grep -rniE 'undetectable|low probability of intercept' --include='*.md' . 2>/dev/null || true)
[ -z "$UNDET" ] && pass "no 'undetectable' claim" \
               || warn "review concealment claim(s): $(echo "$UNDET" | head -2)"

# ─────────────────────────────────────────────────────────────
sect "7. Third-party notices verified"
if grep -q '\[VERIFY\]' THIRD_PARTY_NOTICES.md 2>/dev/null; then
    fail "THIRD_PARTY_NOTICES.md still has [VERIFY] markers — run tools/verify_licenses.sh against .pio/libdeps and clear them"
else
    pass "no [VERIFY] markers remain"
fi
if [ -d .pio/libdeps ]; then
    if bash tools/verify_licenses.sh >/dev/null 2>&1; then pass "verify_licenses.sh passed"
    else fail "verify_licenses.sh reported problems — run it directly"; fi
else
    warn ".pio/libdeps absent — run 'pio run -e tdeck' then re-run to verify licenses"
fi

# ─────────────────────────────────────────────────────────────
sect "8. Host test harnesses"
if command -v g++ >/dev/null 2>&1; then
    ran=0
    for t in test_*.cpp; do
        [ -f "$t" ] || continue
        b="/tmp/pf_$(basename "$t" .cpp)"
        # Some harnesses compile the ACTUAL module under test as a second
        # translation unit (rather than re-implementing it, which is how an
        # earlier suite passed while the firmware would not build). Try linking
        # the matching src/ file before giving up.
        mod="src/$(basename "$t" .cpp | sed 's/^test_//').cpp"
        if g++ -std=c++17 -include algorithm -w -o "$b" "$t" -lmbedcrypto 2>/dev/null \
           || g++ -std=c++17 -include algorithm -w -o "$b" "$t" 2>/dev/null \
           || { [ -f "$mod" ] && g++ -std=c++17 -include algorithm -w -o "$b" "$t" "$mod" -lm 2>/dev/null; }; then
            if "$b" >/tmp/pf_out 2>&1; then pass "$t $(grep -oE 'Results: [0-9]+/[0-9]+ passed' /tmp/pf_out | tail -1)"
            else fail "$t FAILED: $(grep -oE 'Results: [0-9]+/[0-9]+ passed' /tmp/pf_out | tail -1)"; fi
            ran=$((ran+1))
        else
            warn "$t did not compile standalone (may need mbedtls dev headers) — skipped"
        fi
    done
    [ "$ran" -eq 0 ] && warn "no test harness ran"
else
    warn "g++ unavailable — cannot run host tests"
fi

# ─────────────────────────────────────────────────────────────
sect "9. Firmware build"
if [ "$QUICK" = "1" ]; then
    warn "skipped (--quick). THE BUILD IS A HARD GATE — never publish unverified."
elif command -v pio >/dev/null 2>&1; then
    if pio run -e tdeck >/tmp/pf_build 2>&1; then pass "pio run -e tdeck succeeded"
    else fail "FIRMWARE DOES NOT BUILD — last lines:"; tail -15 /tmp/pf_build | sed 's/^/          /'; fi
else
    fail "PlatformIO not installed — cannot verify the build (hard gate)"
fi

# ─────────────────────────────────────────────────────────────
sect "10. Git history hygiene"
if [ -d .git ]; then
    n=$(git rev-list --count HEAD 2>/dev/null || echo 0)
    if [ "$n" -le 1 ]; then pass "single commit — clean history"
    else
        warn "$n commits. Publishing must be from a repo with NO prior history."
        LEAK=$(git log --all --name-only --pretty=format: 2>/dev/null \
               | grep -E '\.key$|psk|duress\.cfg|appass\.cfg|\.pem$|secrets' | sort -u | head || true)
        [ -n "$LEAK" ] && fail "secret-like paths in history (unrecoverable — rebuild repo): $(echo "$LEAK" | tr '\n' ' ')"
    fi
    command -v gitleaks >/dev/null 2>&1 \
        && { gitleaks detect --no-banner -q >/dev/null 2>&1 && pass "gitleaks clean" || fail "gitleaks found secrets"; } \
        || warn "gitleaks not installed — install and scan history before publishing"
else
    warn "not a git repository yet"
fi

# ─────────────────────────────────────────────────────────────
printf "\n%s\n" "────────────────────────────────────────────────────────────"
if [ "$fails" -eq 0 ]; then
    printf "${GRN}${BOLD}PRE-FLIGHT PASSED${NC}  (%d warning(s))\n" "$warns"
    echo "Mechanical gates are clear. Still required before publishing:"
    echo "  * counsel sign-off: FHOP non-standard-crypto question, and ITAR"
    echo "    'specially designed' reviewed together with marketing collateral"
    echo "  * hardware smoke test on 2+ radios (tablet re-pair, duress, FHOP sync, KCV match)"
    echo "  * publish from a fresh repository with no prior commit history"
    exit 0
else
    printf "${RED}${BOLD}PRE-FLIGHT FAILED${NC}  %d blocker(s), %d warning(s)\n" "$fails" "$warns"
    echo "Do not publish until every blocker is resolved. Publication is irreversible."
    exit 1
fi
