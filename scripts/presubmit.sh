#!/bin/bash
#
# Presubmit checks for this repository.
#
# Checks for lint errors, spelling, licensing, correct builds / tests and so on.
# Flags may be specified to allow suppressing of checks or automatic fixes, try
# `scripts/presubmit.sh --help` for details.
#
# Globals:
#   GO_TEST_TIMEOUT: timeout for 'go test'. Optional (defaults to 5m).
set -eu

check_pkg() {
  local cmd="$1"
  local pkg="$2"
  check_cmd "$cmd" "try running 'go get -u $pkg'"
}

check_cmd() {
  local cmd="$1"
  local msg="$2"
  if ! type -p "${cmd}" > /dev/null; then
    echo "${cmd} not found, ${msg}"
    return 1
  fi
}

usage() {
  echo "$0 [--coverage] [--fix] [--no-mod-tidy] [--no-build] [--no-linters]"
}

main() {
  local coverage=0
  local fix=0
  local run_mod_tidy=1
  local run_build=1
  local run_lint=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --coverage)
        coverage=1
        ;;
      --fix)
        fix=1
        ;;
      --no-mod-tidy)
        run_mod_tidy=0
        ;;
      --help)
        usage
        exit 0
        ;;
      --no-build)
        run_build=0
        ;;
      --no-linters)
        run_lint=0
        ;;
      *)
        usage
        exit 1
        ;;
    esac
    shift 1
  done

  cd "$(dirname "$0")"  # at scripts/
  cd ..  # at top level

  go_srcs="$(find . -name '*.go' | \
    grep -v mock_ | \
    grep -v .pb.go | \
    grep -v _string.go | \
    grep -v .shims.go | \
    tr '\n' ' ')"

  if [[ "$fix" -eq 1 ]]; then
    check_pkg goimports golang.org/x/tools/cmd/goimports || exit 1

    echo 'running gofmt'
    gofmt -s -w ${go_srcs}
    echo 'running goimports'
    goimports -w ${go_srcs}
    if [[ "$run_mod_tidy" -eq 1 ]]; then
      echo 'running go mod tidy'
      go mod tidy
    fi
  fi

  if [[ "${run_build}" -eq 1 ]]; then
    echo 'running go build'
    go build ./...

    export TEST_FLAGS="-timeout=${GO_TEST_TIMEOUT:-5m}"

    if [[ ${coverage} -eq 1 ]]; then
      TEST_FLAGS+=" -covermode=atomic -coverprofile=coverage.txt"
    fi

    echo "running go test ${TEST_FLAGS} ./..."
    go test ${TEST_FLAGS} ./...
  fi

  if [[ "${run_lint}" -eq 1 ]]; then
    check_cmd golangci-lint \
      'have you installed github.com/golangci/golangci-lint?' || exit 1

    echo 'running golangci-lint'
    golangci-lint run --deadline=8m
    echo 'checking license headers'
    ./scripts/check_license.sh ${go_srcs}
  fi
}

main "$@"
