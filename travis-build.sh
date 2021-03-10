#!/usr/bin/env bash

if [[ "${TRAVIS_BUILD_SCRIPT_DEBUG_ENABLED:-false}" == 'true' ]]; then
  set -x
fi

set -e
set -o pipefail

RED="\033[31;1m"
GREEN="\033[32;1m"
RESET="\033[0m"

log_info() {
  echo -e "${GREEN}$1${RESET}"
}
log_error() {
  echo -e "${RED}$1${RESET}"
}

# Return true if branch matches the grep regexp pattern specified and false otherwise
branch_matches() {
  if grep -qE "$1" <(echo "$TRAVIS_BRANCH"); then return 0; else return 1; fi
}

# Prepare the test environment
pipenv sync --dev

# Run linters
pipenv run check-format
pipenv run check-flake8

# Run unit tests
pipenv run tests

# SNYK dependency scan - runs for master and RC branches, but not for PRs
if [[ "$TRAVIS_PULL_REQUEST" == 'false' ]] && branch_matches "^master$|^develop$|^SB_*|^RC_*"; then
  log_info "Scanning code with SNYK ..."
  npm install -g snyk
  snyk monitor --org=incountry --prune-repeated-subdependencies --remote-repo-url="${APP_NAME}" --project-name="${APP_NAME}:${TRAVIS_BRANCH}"
else
  log_info "Snyk dependency scan is skipped"
fi

# Bandit security scan
pip3 install bandit
BANDIT_OUTPUT="$(bandit -v --ini bandit.ini -r -o bandit.json -f json --exclude './venv,./tests,./.gitlint-rules,./queue_worker/test,./queue_watcher/test,./scripts,./setup.py' || cat bandit.json | jq -r '.results[] as $res | "[\($res.issue_severity)] File \($res.filename), line \($res.line_number) - \($res.issue_text)\nRelated code:\n\($res.code)Rationale: \($res.more_info)\n"')"
if [[ -z "${BANDIT_OUTPUT}" ]]; then
  log_info "No Bandit issues found"
else
  log_info "Some Bandit issues found. If Sonar Quality Gate will decide they are critical Sonar will fail the build:\n"
  log_info "${BANDIT_OUTPUT}"
fi
if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then # Fetch the PR branch with complete history for Travis PR builds in order to let Sonar properly display annotations in coverage details
  git fetch --no-tags https://github.com/${TRAVIS_PULL_REQUEST_SLUG}.git +refs/heads/${TRAVIS_BRANCH}:refs/remotes/origin/${TRAVIS_BRANCH}
fi

# Sonar Quality gate. If it fails, it fails the build due to 'sonar.qualitygate.wait=true' (but you could temporarily override this via Travis envvar)
sonar-scanner -Dsonar.qualitygate.wait=${SONAR_QUALITY_GATE_FAILS_BUILD:-true}
