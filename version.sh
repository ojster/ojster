#!/usr/bin/env sh
set -eu

# Base version for this line of development
BASE_VERSION="0.0.0"

# --- Git availability check -----------------------------------------------
if ! command -v git >/dev/null 2>&1 || [ ! -d .git ]; then
    # No git available → fallback to dev version
    echo "${BASE_VERSION}-dev+no_git"
    exit 0
fi

# --- Determine nearest tag -------------------------------------------------
TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
if [ -z "$TAG" ]; then
    TAG="v${BASE_VERSION}"
fi
TAG_STRIPPED="${TAG#v}"

# --- Determine commit hash -------------------------------------------------
HASH="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"

# --- Detect dirty workspace (only ojster.go) ------------------------------
DIRTY=""
if ! git diff --quiet --ignore-submodules HEAD -- ojster.go 2>/dev/null; then
    DIRTY="-dirty"
fi

# --- Determine branch name -------------------------------------------------
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached")"
BRANCH_CLEAN="$(echo "$BRANCH" | tr '/' '-' | tr ' ' '-')"

# --- If exactly on a tag AND clean, return the tag -------------------------
if git describe --tags --exact-match >/dev/null 2>&1; then
    # Check if ojster.go is dirty
    if git diff --quiet --ignore-submodules HEAD -- ojster.go 2>/dev/null; then
        echo "${TAG_STRIPPED}"
        exit 0
    fi
    # Otherwise fall through and produce a dirty version
fi

# --- Determine commits since tag ------------------------------------------
COMMITS_SINCE_TAG="$(git rev-list "${TAG}"..HEAD --count 2>/dev/null || echo "0")"

# --- Construct SemVer pre-release + build metadata -------------------------
# Format: <tag>-<branch>.<commits_since_tag>+<hash>[-dirty]
# Example: 0.1.0-feature-login.3+abc1234-dirty
echo "${TAG_STRIPPED}-${BRANCH_CLEAN}.${COMMITS_SINCE_TAG}+${HASH}${DIRTY}"
