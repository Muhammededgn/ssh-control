#!/usr/bin/env bash
#
# Release notes for one tag, built from the commit range rather than from pull
# requests.
#
# This exists because `generate_release_notes: true` lists **only merged pull
# requests**. Most work in this repository goes straight to `main` — small,
# easily-revertable changes do, while anything touching the vault format, the
# crypto, the keyslots or the credential store goes through a PR — so the
# generated notes for v0.2.0 came out empty and v0.3.0 listed one of its nine
# issues.
#
# Two things it does that are worth knowing:
#
# * **It walks `--first-parent`.** A PR's internal commits are already
#   represented by the merge commit, and listing all five of the SFTP branch's
#   would bury the direct-to-main work this script exists to surface.
# * **An issue is credited from a `Closes #N` trailer, or from a merged PR's own
#   closing references** — those live in the PR description and appear in no
#   commit message at all. An issue closed by hand, with neither, cannot be
#   recovered from the range and will only appear under "Other changes" as
#   whatever commit did the work. Keep writing the trailers.
#
# Usage: release-notes.sh <tag> [previous-tag]
# Requires: git with full history (actions/checkout needs `fetch-depth: 0`),
#           and `gh` authenticated, for issue and PR titles.
set -euo pipefail

TAG="${1:?usage: release-notes.sh <tag> [previous-tag]}"
PREV="${2-}"

# The tag a release is measured against.
#
# A pre-release compares against whatever came last, including another
# pre-release — that is the point of it, a small diff to sanity-check. A stable
# release compares against the last *stable* tag, so v0.3.0 covers everything
# since v0.2.0 rather than only what landed after v0.3.0-rc1.
#
# `--merged "$TAG^"` deliberately looks from the tag's *parent*: v0.3.0-rc1 and
# v0.3.0 sit on the same commit here, and a tag on the commit itself is not a
# predecessor of it.
if [ -z "$PREV" ]; then
  if [ "$TAG" != "${TAG%%-*}" ]; then
    PREV=$(git tag --list 'v*' --sort=-v:refname --merged "$TAG^" | head -1 || true)
  else
    PREV=$(git tag --list 'v*' --sort=-v:refname --merged "$TAG^" | grep -v -- '-' | head -1 || true)
  fi
fi

RANGE="$TAG"
[ -n "$PREV" ] && RANGE="$PREV..$TAG"

repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

issues=""   # issue numbers closed by this release, one per line
others=""   # subjects of commits that closed nothing, one per line

for sha in $(git rev-list --reverse --first-parent "$RANGE"); do
  subject=$(git log -1 --format=%s "$sha")
  case "$subject" in
    # The version bump is bookkeeping, not a change anyone reads notes for.
    "chore: release "*|"chore: v"*) continue ;;
    "Merge pull request #"*)
      pr=$(printf '%s\n' "$subject" | grep -oE '#[0-9]+' | head -1 | tr -d '#')
      closed=$(gh pr view "$pr" --repo "$repo" --json closingIssuesReferences \
                 --jq '.closingIssuesReferences[].number' 2>/dev/null || true)
      if [ -n "$closed" ]; then
        issues+="$closed"$'\n'
      else
        others+="$subject"$'\n'
      fi
      continue ;;
  esac

  refs=$(git log -1 --format=%B "$sha" \
           | grep -oiE '(close[sd]?|fix(e[sd])?|resolve[sd]?) #[0-9]+' \
           | grep -oE '[0-9]+' || true)
  if [ -n "$refs" ]; then
    issues+="$refs"$'\n'
  else
    others+="$subject"$'\n'
  fi
done

issues=$(printf '%s\n' "$issues" | grep -E '^[0-9]+$' | sort -un || true)

if [ -n "$issues" ]; then
  echo "## Issues closed"
  echo
  while read -r n; do
    [ -z "$n" ] && continue
    # Never fatal: a reference to a deleted or cross-repository issue must not
    # fail the release.
    t=$(gh api "repos/$repo/issues/$n" --jq .title 2>/dev/null || true)
    if [ -n "$t" ]; then echo "* $t (#$n)"; else echo "* #$n"; fi
  done <<< "$issues"
  echo
fi

others=$(printf '%s\n' "$others" | grep -v '^$' || true)
if [ -n "$others" ]; then
  echo "## Other changes"
  echo
  while read -r s; do
    [ -z "$s" ] && continue
    echo "* $s"
  done <<< "$others"
  echo
fi

if [ -n "$PREV" ]; then
  echo "**Full Changelog**: https://github.com/$repo/compare/$PREV...$TAG"
else
  echo "**Full Changelog**: https://github.com/$repo/commits/$TAG"
fi
