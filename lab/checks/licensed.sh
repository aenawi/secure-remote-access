#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Hashem Aldhaheri

# Does every source file still say what it is licensed under?
#
# The repository is two things under two licenses: the guide (chapters/,
# index.html, README) is CC BY-SA 4.0, and the code (assets/, lab/) is
# GPL-3.0-or-later. Directory is the rule, and README.md states it — but a
# directory rule only helps someone who reads the README, and files get
# copied out of repositories one at a time. So each source file carries an
# SPDX line, and the licence travels with the file.
#
# The failure this exists to catch is not a file losing its header. It is a
# file being BORN without one. Rebasing carries existing headers along for
# free; nothing carries a header onto a .go file that did not exist when the
# licence was applied. Miss that on enough branches and the repository ends
# up half-stamped, which is worse than not stamping at all — it makes the
# unstamped files look deliberate.
#
#     sh checks/licensed.sh
#
# `make check` runs it, and the pre-push hook runs `make check`, so the
# answer arrives before the code leaves the laptop. It needs no Go, no Node
# and no containers: it is grep and a file list, which is the point. It uses
# git to enumerate files when git is present so that new and unstaged files
# are seen, and falls back to `find` inside a tarball or an exported copy.

set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

SPDX='SPDX-License-Identifier: GPL-3.0-or-later'

# Two files are deliberately not stamped, and both are third-party code.
#
# hud/three.module.js is three.js r166, MIT, vendored and minified. Stamping
# someone else's library with our licence would be a false statement about
# who wrote it.
#
# design/five-gates.html inlines that same bundle rather than linking it, for
# the CORS reason the file explains at the top. It is mostly not ours, so it
# keeps three.js's MIT notice and no GPL line. README.md names both.
is_exempt() {
  case "$1" in
    lab/control/ui/hud/three.module.js) return 0 ;;
    lab/design/five-gates.html)         return 0 ;;
    *) return 1 ;;
  esac
}

# Code lives in assets/ and lab/. Everything else in the repository is the
# guide, and the guide is CC BY-SA by directory — chapters are prose, and a
# licence header above the doctype of a chapter would be the first thing a
# reader sees.
is_code() {
  case "$1" in
    assets/*|lab/*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *.go|*.js|*.mjs|*.css|*.sh|*.html|*/Makefile|Makefile|lab/hooks/*) return 0 ;;
    *) return 1 ;;
  esac
}

if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  # Tracked plus untracked-and-not-ignored: a file added but not yet
  # committed is exactly the file this check is for.
  files=$(git ls-files --cached --others --exclude-standard)
else
  files=$(find assets lab -type f 2>/dev/null | sed 's|^\./||')
fi

missing=0
checked=0

for f in $files; do
  is_code "$f" || continue
  is_exempt "$f" && continue
  [ -f "$f" ] || continue
  checked=$((checked + 1))

  # Head only. The line belongs at the top where a person opening the file
  # will see it, and a match four hundred lines down — inside a vendored
  # bundle, or a string — is not the header we asked for.
  if head -5 "$f" | grep -qF "$SPDX"; then
    continue
  fi

  if [ "$missing" -eq 0 ]; then
    printf '  Missing the SPDX header:\n'
  fi
  missing=$((missing + 1))
  printf '    %s\n' "$f"
done

if [ "$missing" -gt 0 ]; then
  cat <<EOF

$missing of $checked source files do not say what they are licensed under.

Add this at the top of each — after the shebang if there is one, and using
the comment syntax the file already uses:

    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright (C) 2026 Hashem Aldhaheri

If the file is third-party, leave its own licence in place and add it to
is_exempt() in this script instead, with a line saying where it came from.
EOF
  exit 1
fi

printf '  ok    all %s source files carry their licence\n' "$checked"
