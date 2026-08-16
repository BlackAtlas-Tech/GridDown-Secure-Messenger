#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Verify third-party license obligations against the libraries PlatformIO
# actually vendored, rather than against recollection or documentation.
#
#   tools/verify_licenses.sh            Report each dependency's license
#   tools/verify_licenses.sh --bundle   Also write dist/THIRD_PARTY_LICENSES.txt
#
# Exit status: 0 = every dependency has a license file and none is flagged
#              1 = a license file is missing, or a red-flag term was found
#
# Run `pio run -e tdeck` first so .pio/libdeps/ is populated.

set -uo pipefail

LIBDEPS="${LIBDEPS:-.pio/libdeps/tdeck}"
BUNDLE=0
[ "${1:-}" = "--bundle" ] && BUNDLE=1

BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; NC=$'\033[0m'
problems=0
missing=0

echo "${BOLD}GridDown — third-party license verification${NC}"
echo "Project license: GPL-3.0-or-later"
echo "Library tree:    ${LIBDEPS}"
echo

if [ ! -d "$LIBDEPS" ]; then
    echo "${RED}ERROR${NC}: ${LIBDEPS} not found. Run 'pio run -e tdeck' first."
    exit 1
fi

# Licenses that are INCOMPATIBLE with GPL-3.0, or that need a human decision.
#
# LIMITATION — the "or later" test below is WEAK for LGPL/GPL dependencies.
# The full LGPL-2.1 and GPL-2.0 licence texts both contain the phrase "any later
# version" inside their own "How to Apply These Terms" appendix, regardless of
# what the library author actually chose. So a bundled LICENSE file alone cannot
# tell you whether a dependency is "2.1-only" or "2.1-or-later".
# The authoritative statement is the library's OWN grant, in its source headers
# or README ("...either version 2.1 of the License, or (at your option) any
# later version"). Check that by hand for any LGPL/GPL dependency; a PASS here
# is not sufficient evidence on its own.

# GPL-2.0-only is the main hazard: it cannot be combined with GPL-3.0 code.
# License text puts the license name and its version on SEPARATE lines, e.g.
#     GNU GENERAL PUBLIC LICENSE
#        Version 2, June 1991
# grep is line-oriented, so patterns spanning that break silently. Flatten
# newlines to spaces and squeeze runs of whitespace before matching.
flatten() { tr '\n\r\t' '   ' <<<"$1" | tr -s ' '; }

is_red_flag() {
    local flat; flat="$(flatten "$1")"
    # GPL-2 (or LGPL-2/2.1) with no "or later" escape clause
    if grep -qiE '(GNU (LESSER )?GENERAL PUBLIC LICENSE ?,? ?V(ersion)? ?2)' <<<"$flat" \
       && ! grep -qiE '(either version 2(\.[01])? of the License, or|version 2(\.[01])? or (any )?later|any later version)' <<<"$flat"; then
        return 0
    fi
    # BSD-4-Clause advertising clause — GPL-incompatible
    if grep -qiE 'All advertising materials mentioning features' <<<"$flat"; then
        return 0
    fi
    # Non-commercial / non-free restrictions
    if grep -qiE 'non-?commercial use only|not for commercial|research purposes only' <<<"$flat"; then
        return 0
    fi
    return 1
}

guess_license() {
    local flat; flat="$(flatten "$1")"
    # NOTE: the version often does not sit next to the licence name, e.g.
    # "...GNU Lesser General Public License as published by the Free Software
    # Foundation; either version 2.1 of the License". Allow intervening text.
    if   grep -qiE 'Apache License ?,? ?Version 2\.0'                  <<<"$flat"; then echo "Apache-2.0"
    # ORDER MATTERS. The GPL-3.0 text's own closing section says "...use the GNU
    # Lesser General Public License instead of this License", so a bare
    # "mentions LGPL" test placed before the GPL checks misclassifies every
    # GPL-3.0 file as LGPL. Version-qualified matches run first; the bare LGPL
    # fallback runs LAST, only when nothing more specific matched.
    elif grep -qiE 'GNU LESSER GENERAL PUBLIC LICENSE.{0,80}?version ?2\.1' <<<"$flat"; then echo "LGPL-2.1"
    elif grep -qiE 'GNU LESSER GENERAL PUBLIC LICENSE.{0,80}?version ?3'     <<<"$flat"; then echo "LGPL-3.0"
    elif grep -qiE 'GNU GENERAL PUBLIC LICENSE.{0,80}?version ?3'       <<<"$flat"; then echo "GPL-3.0"
    elif grep -qiE 'GNU GENERAL PUBLIC LICENSE.{0,80}?version ?2'       <<<"$flat"; then echo "GPL-2.0"
    elif grep -qiE 'GNU LESSER GENERAL PUBLIC LICENSE'                  <<<"$flat"; then echo "LGPL-?"
    elif grep -qiE 'Permission is hereby granted, free of charge'       <<<"$flat"; then echo "MIT"
    elif grep -qiE 'Neither the name of'                                <<<"$flat"; then echo "BSD-3-Clause"
    elif grep -qiE 'Redistribution and use in source and binary'        <<<"$flat"; then echo "BSD-2-Clause"
    else echo "UNKNOWN"
    fi
}

mkdir -p dist
BUNDLE_FILE="dist/THIRD_PARTY_LICENSES.txt"
if [ "$BUNDLE" = "1" ]; then
    {
      echo "GridDown Secure Messenger — Third-Party Licenses"
      echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "Firmware license: GPL-3.0-or-later"
      echo "================================================================"
      echo
    } > "$BUNDLE_FILE"
fi

shopt -s nullglob
for dir in "$LIBDEPS"/*/; do
    lib="$(basename "$dir")"
    [ "$lib" = "__pycache__" ] && continue

    # Find a license file (varied naming across projects)
    lic=""
    for cand in LICENSE LICENSE.txt LICENSE.md license.txt license LICENCE \
                LICENSE-2.0.txt COPYING COPYING.LESSER COPYING.txt; do
        if [ -f "${dir}${cand}" ]; then lic="${dir}${cand}"; break; fi
    done
    if [ -z "$lic" ]; then
        lic="$(find "$dir" -maxdepth 2 -iname 'licen[cs]e*' -o -maxdepth 2 -iname 'copying*' 2>/dev/null | head -1)"
    fi

    # Many Arduino libraries ship no LICENSE file and carry the notice in the
    # source header instead (TinyGPSPlus does this). Fall back to scanning the
    # main headers/sources and library.properties before reporting "not found" —
    # a missing file is not the same as a missing licence.
    hdrsrc=""
    if [ -z "$lic" ] || [ ! -f "$lic" ]; then
        for cand in $(find "$dir" -maxdepth 3 \( -name '*.h' -o -name '*.cpp' -o -name 'library.properties' -o -iname 'readme*' \) 2>/dev/null | head -20); do
            if grep -qiE 'GNU (Lesser )?General Public License|Apache License|MIT License|Redistribution and use|Permission is hereby granted' <<<"$(flatten "$(cat "$cand" 2>/dev/null)")" 2>/dev/null; then
                hdrsrc="$cand"; lic="$cand"; break
            fi
        done
    fi

    # Version from PlatformIO metadata, if present
    ver="?"
    if [ -f "${dir}.piopm" ]; then
        ver="$(python3 -c "import json,sys;print(json.load(open('${dir}.piopm')).get('version','?'))" 2>/dev/null || echo '?')"
    fi

    if [ -z "$lic" ] || [ ! -f "$lic" ]; then
        printf "%-26s %-10s ${RED}NO LICENSE FILE FOUND${NC}\n" "$lib" "$ver"
        missing=$((missing+1)); problems=$((problems+1))
        continue
    fi

    txt="$(cat "$lic" 2>/dev/null)"
    name="$(guess_license "$txt")"

    # Count distinct copyright holders — matters for BSD attribution
    # Match (c), (C), the unicode (c) sign, or a bare "Copyright <year>". ArduinoJson
    # uses the unicode sign, which an ASCII-only pattern misses and reports as 0.
    holders="$(LC_ALL=C grep -ioE 'copyright[^0-9]{0,20}[0-9]{4}[^\n]*' <<<"$txt" | sed 's/[[:space:]]*$//' | sort -u | wc -l)"

    if is_red_flag "$txt"; then
        printf "%-26s %-10s ${RED}%-14s RED FLAG — review${NC} (%s)\n" "$lib" "$ver" "$name" "$(basename "$lic")"
        problems=$((problems+1))
    elif [ "$name" = "UNKNOWN" ]; then
        printf "%-26s %-10s ${YEL}%-14s manual review${NC} (%s)\n" "$lib" "$ver" "$name" "$(basename "$lic")"
        problems=$((problems+1))
    else
        if [ -n "$hdrsrc" ]; then
            printf "%-26s %-10s ${YEL}%-14s in-source notice${NC} (%s, %s holder(s))\n" "$lib" "$ver" "$name" "$(basename "$lic")" "$holders"
            printf "    ${YEL}note${NC}: no LICENCE file shipped — notice found in source. Record the source path in THIRD_PARTY_NOTICES.md and ship the notice text with binaries.\n"
        else
            printf "%-26s %-10s ${GRN}%-14s ok${NC} (%s, %s holder(s))\n" "$lib" "$ver" "$name" "$(basename "$lic")" "$holders"
        fi
    fi

    if [ "$holders" -gt 1 ]; then
        printf "    ${YEL}note${NC}: %s copyright holders — retain all notices verbatim\n" "$holders"
    fi

    if [ "$BUNDLE" = "1" ]; then
        {
          echo "----------------------------------------------------------------"
          echo "Library: $lib   Version: $ver   Detected: $name"
          echo "----------------------------------------------------------------"
          cat "$lic"
          echo
        } >> "$BUNDLE_FILE"
    fi
done

echo
if [ "$BUNDLE" = "1" ]; then
    echo "Bundled notices → ${BUNDLE_FILE} ($(wc -l < "$BUNDLE_FILE") lines)"
fi

if [ "$problems" -eq 0 ]; then
    echo "${GRN}PASS${NC} — every dependency has a recognised, GPL-3.0-compatible license."
    echo "Update THIRD_PARTY_NOTICES.md and clear the [VERIFY] markers."
    exit 0
else
    echo "${RED}ATTENTION${NC} — ${problems} item(s) need review (${missing} missing license file(s))."
    echo "Resolve these before publishing: a GPL-2.0-only or advertising-clause"
    echo "dependency is incompatible with GPL-3.0."
    exit 1
fi
