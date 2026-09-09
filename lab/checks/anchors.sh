#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Hashem Aldhaheri

# Does every heading a document points at still exist?
#
# The repository's documents used to say the same things twice. README.md
# carried its own copy of the engine invariants, the branch model and — worst
# of the three — the disclaimer, all of which are stated properly somewhere
# else. Two hand-maintained copies of a liability statement is not a tidiness
# problem. So the copies went, and each one became a link.
#
# That trades one failure for another, and this check is the price of the
# trade. A duplicate goes stale silently and still reads as an answer; a link
# goes dead silently and reads as an answer that is one click away, which is
# worse, because the reader who follows it is the reader who wanted the detail.
# Rename a heading and every pointer at it breaks with nothing to say so.
#
#     sh checks/anchors.sh
#
# `make check` runs it, and the pre-push hook runs `make check`. It needs no
# Go, no Node and no containers: it is grep, awk and a file list.
#
# Scope is deliberately internal — links between files in this repository, to
# a heading. An http(s) link is somebody else's document and this check has no
# opinion about it, with one exception: the published site is this repository,
# served. README.md's disclaimer points at the guide's own disclaimer by its
# public URL, because a relative link to index.html renders as source on
# GitHub rather than as the page. That link is the reason this file exists, so
# the site URL is resolved back to index.html and checked like any other.

set -eu

LC_ALL=C
export LC_ALL

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

# Where main is published. `main` is the guide and nothing else, so this URL
# and index.html at the root of this repository are the same document.
SITE='https://aenawi.github.io/secure-remote-access'

if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  docs=$(git ls-files --cached --others --exclude-standard '*.md')
else
  docs=$(find . -name '*.md' -not -path './.git/*' | sed 's|^\./||')
fi

# The anchors a file offers.
#
# For Markdown that is GitHub's heading slug: lowercase, drop everything that
# is not a letter, digit, space, hyphen or underscore, then spaces to hyphens.
# Headings inside a fenced block are code and are skipped, which matters here
# because CONTRIBUTING.md and lab/README.md both fence shell that starts a
# line with `#`.
#
# For HTML it is the id attribute, which is what index.html's disclaimer is
# reached by.
anchors_of() {
  case "$1" in
    *.md)
      awk '
        /^```/ { fence = !fence; next }
        fence  { next }
        /^#{1,6}[ \t]/ {
          sub(/^#+[ \t]+/, "")
          sub(/[ \t]+$/, "")
          s = tolower($0)
          gsub(/[^a-z0-9 _-]/, "", s)
          gsub(/ /, "-", s)
          if (s != "") print s
        }
      ' "$1"
      ;;
    *.html)
      grep -o 'id="[^"]*"' "$1" 2>/dev/null | sed 's/id="//; s/"$//'
      ;;
  esac
}

broken=0
checked=0

for doc in $docs; do
  [ -f "$doc" ] || continue
  dir=$(dirname "$doc")

  # ](target#anchor) and ](#anchor). Angle-bracket and reference-style links
  # are not used in this repository; if one appears, it is simply not checked
  # rather than wrongly failed.
  links=$(grep -o '](\([^)# ]*\)#[^) ]*)' "$doc" 2>/dev/null | sed 's/^](//; s/)$//' || true)

  for link in $links; do
    target=${link%%#*}
    anchor=${link#*#}
    [ -n "$anchor" ] || continue

    # The published site is index.html, served. Everything else off this
    # host belongs to somebody else.
    case "$target" in
      "$SITE"|"$SITE"/) target=index.html ;;
      http:*|https:*|mailto:*) continue ;;
    esac

    # Resolve to a path from the root of the repository. `path` is set on
    # every branch or the link is skipped, so it can never carry a value
    # over from the link before it.
    if [ -z "$target" ]; then
      path="$doc"
    else
      abs=$(cd "$dir" 2>/dev/null && cd "$(dirname "$target")" 2>/dev/null && pwd) || continue
      path="$abs/$(basename "$target")"
      case "$path" in "$root"/*) path=${path#"$root"/} ;; esac
    fi
    [ -f "$path" ] || continue   # a missing file is a different problem

    checked=$((checked + 1))
    if anchors_of "$path" | grep -qxF "$anchor"; then
      continue
    fi

    if [ "$broken" -eq 0 ]; then
      printf '  Links to a heading that does not exist:\n'
    fi
    broken=$((broken + 1))
    printf '    %s  ->  %s#%s\n' "$doc" "$target" "$anchor"
  done
done

if [ "$broken" -gt 0 ]; then
  cat <<EOF

$broken of $checked internal links point at a heading that is not there.

Either the heading was renamed and the link did not follow, or the link was
written from memory. Fix whichever is wrong. If the heading moved to another
file, the link should follow it there rather than the text coming back.
EOF
  exit 1
fi

printf '  ok    all %s internal heading links resolve\n' "$checked"
