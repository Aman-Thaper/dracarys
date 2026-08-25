#!/usr/bin/env bash
# DRACARYS GitHub Action entrypoint. Runs a single scan, writes SARIF + a job
# summary, and sets the exit code from --fail-on.
set -uo pipefail

TARGET="${1:?target required}"; FAIL_ON="${2:-high}"; PASSIVE="${3:-false}"
AUTH="${4:-}"; AUTHORIZED="${5:-false}"; SARIF="${6:-dracarys.sarif}"; MAXP="${7:-60}"

ARGS=(scan "$TARGET" --format table --sarif "$SARIF" --md /tmp/dracarys-summary.md
      --fail-on "$FAIL_ON" --max-pages "$MAXP")
[ "$PASSIVE" = "true" ] && ARGS+=(--passive)
[ -n "$AUTH" ] && ARGS+=(--auth "$AUTH")
[ "$AUTHORIZED" = "true" ] && ARGS+=(--yes-i-am-authorized)

echo "::group::DRACARYS scan $TARGET"
dracarys "${ARGS[@]}"
CODE=$?
echo "::endgroup::"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f /tmp/dracarys-summary.md ]; then
  cat /tmp/dracarys-summary.md >> "$GITHUB_STEP_SUMMARY"
fi
echo "sarif-file=$SARIF" >> "${GITHUB_OUTPUT:-/dev/null}"
exit $CODE
