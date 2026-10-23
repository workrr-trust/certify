#!/usr/bin/env bash
# Build the verifier from this action's own commit and run the consumer gate.
#
# This script does not certify. A composite action runs inside the caller's
# job, so Fulcio would record the caller's workflow. The trust policy accepts
# only certify.yml at v0.1.0 and v0.1.1. Signing here would not verify.
#
# The OIDC request variables are cleared before install and before verify, so
# this step cannot mint a GitHub token even when the job has one. Dependencies
# come from this commit's package-lock (npm ci), not from an npm dist-tag.
set -euo pipefail

unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL

src="${GITHUB_ACTION_PATH:-}"
if [[ -z "$src" || ! -f "$src/package.json" || ! -f "$src/package-lock.json" || ! -f "$src/action/run.mjs" ]]; then
  echo "workrr: GITHUB_ACTION_PATH does not point at the workrr verify action" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Copy off the action checkout so a read-only mount still builds, and so
# node_modules from a previous run in this job cannot satisfy npm ci.
tar -C "$src" \
  --exclude .git \
  --exclude node_modules \
  --exclude dist \
  -cf - . | tar -C "$work" -xf -

# NODE_ENV=production would skip typescript. The build needs it.
(
  cd "$work"
  npm ci --ignore-scripts --include=dev
  npm run build
)

# Relative artifact and bundle paths resolve in the caller's workspace.
node "$work/action/run.mjs"
