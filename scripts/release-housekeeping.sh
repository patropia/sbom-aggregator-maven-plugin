#!/usr/bin/env bash
# Release housekeeping for sbom-aggregator-maven-plugin 1.1.0.
#
# Run this from a clone with push rights after the 1.1.0 release PR is merged
# into main. Requires git and an authenticated GitHub CLI (`gh auth login`).
#
# Prerequisites for the tag-triggered release workflow (.github/workflows/release.yml):
#   - repository secrets CENTRAL_TOKEN_USERNAME, CENTRAL_TOKEN_PASSWORD,
#     GPG_PRIVATE_KEY and GPG_PASSPHRASE exist;
#   - the nl.patropia namespace is verified on https://central.sonatype.com.
#
# Usage: scripts/release-housekeeping.sh [--dry-run]
#
# --dry-run still performs the read steps for real: `git fetch --prune --tags`,
# `git pull --ff-only` and `mvn help:evaluate` all run and touch your local clone.
# Only the remote-mutating steps (closing PRs, deleting branches, pushing the tag)
# are skipped, so the working tree stays as it is but the local refs may update.
set -euo pipefail

VERSION="1.1.0"
REMOTE="origin"
STALE_BRANCHES=(
  swarmcommand/run-16dce33a
  swarmcommand/run-c92b1527
  swarmcommand/run-cb6936cf
  wip/merge-fidelity-purls-input-hardening
)
# Dependabot branches folded into (or deliberately ignored by) the 1.1.0 release.
DEPENDABOT_BRANCHES=(
  dependabot/maven/maven-plugins-18e0db8601
  dependabot/maven/test-dependencies-4da523bee5
  dependabot/maven/maven.version-3.10.1
)

run() {
  if [[ "${DRY_RUN:-false}" == "true" ]]; then
    echo "[dry-run] $*"
  else
    echo "+ $*"
    "$@"
  fi
}

[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

git fetch "$REMOTE" --prune --tags
current="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current" != "main" ]]; then
  echo "Check out main first (currently on $current)." >&2
  exit 1
fi
git pull --ff-only "$REMOTE" main

pom_version="$(mvn -B -q -ntp help:evaluate -Dexpression=project.version -DforceStdout)"
if [[ "$pom_version" != "${VERSION}-SNAPSHOT" ]]; then
  echo "pom.xml version is $pom_version, expected ${VERSION}-SNAPSHOT." >&2
  exit 1
fi

# 1. Close the Dependabot PRs (their changes are in main or ignored by dependabot.yml).
for branch in "${DEPENDABOT_BRANCHES[@]}"; do
  if gh pr view "$branch" --json state -q .state 2>/dev/null | grep -q OPEN; then
    run gh pr close "$branch" --delete-branch \
      --comment "Folded into the ${VERSION} release (or now ignored in .github/dependabot.yml)."
  fi
done

# 2. Delete stale work branches.
for branch in "${STALE_BRANCHES[@]}"; do
  if git ls-remote --exit-code --heads "$REMOTE" "$branch" >/dev/null; then
    run git push "$REMOTE" --delete "$branch"
  fi
done

# 3. Tag the release; pushing the tag triggers the release workflow, which sets the
#    version, runs `verify -Prun-its`, deploys to the Central Portal and creates
#    the GitHub release. Central deployments cannot be undone.
if git rev-parse -q --verify "refs/tags/v${VERSION}" >/dev/null; then
  echo "Tag v${VERSION} already exists; not re-tagging." >&2
else
  run git tag -a "v${VERSION}" -m "Release ${VERSION}"
  run git push "$REMOTE" "v${VERSION}"
fi

echo "Done. Monitor https://github.com/patropia/sbom-aggregator-maven-plugin/actions"
echo "Afterwards bump main to the next SNAPSHOT (see RELEASE_CHECKLIST.md)."
