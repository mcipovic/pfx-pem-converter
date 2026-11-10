#!/usr/bin/env bash
#
# Installs the git hooks from .githooks/ into .git/hooks/.
# Run once after cloning, and again when the hook changes.
#
set -euo pipefail

cd "$(dirname "$0")/.."

git_dir="$(git rev-parse --git-dir)"
hooks_dir="$git_dir/hooks"
hook_src=".githooks/pre-push"
hook_dst="$hooks_dir/pre-push"

mkdir -p "$hooks_dir"
chmod +x "$hook_src"
cp "$hook_src" "$hook_dst"
chmod +x "$hook_dst"

# Remove a stale core.hooksPath so the installed hook is actually used.
if [ -n "$(git config --get core.hooksPath || true)" ]; then
    git config --unset core.hooksPath || true
    echo "Removed core.hooksPath (hooks now live in .git/hooks/)."
fi

echo "Git hook installed: $hook_dst"
echo "Protected branches: main, develop - direct pushes are rejected."
