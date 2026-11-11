#!/bin/bash
# Runs the URL Evaluator test suite (pytest, see pytest.ini and tests/).
#
# Usage: install/run_tests.sh [options] [GROUP | PATH[::TEST] ...] [-- PYTEST_ARGS]
#
# Groups (several can be combined; default "all"):
#   all          every test except live ones
#   unit         tests/unit (common + bin)
#   common       tests/unit/common
#   bin          tests/unit/bin
#   web          tests/web (Flask test client)
#   integration  tests/integration (real DB, files and local HTTP server)
#   fast         everything except slow (real Magika) and integration tests
#   slow         only tests using the real Magika model
#   live         real external APIs (API keys in URLEVAL_*_KEY env variables)
#
# A specific file or test is selected by its path / pytest node id, e.g.
#   install/run_tests.sh tests/unit/bin/test_evaluator.py
#   install/run_tests.sh tests/unit/bin/test_evaluator.py::test_unknown_everywhere
#   install/run_tests.sh bin -k blacklist
#
# Options:
#   -k EXPR      only tests whose name matches EXPR (pytest -k)
#   -v           verbose output (one line per test)
#   -x           stop at the first failure
#   -c, --cov    print a coverage report for common/, bin/ and web/
#   -l, --list   only list the selected tests, do not run them
#   --install    install test dependencies (install/pip_requirements-dev.txt) first
#   -h, --help   show this help
# Arguments after "--" are passed to pytest unchanged.
#
# Python is taken from $PYTHON, else ./venv/bin/python, else python3.
# The exit code is the exit code of pytest (0 = all selected tests passed).

BASEDIR=$(dirname "$0")
. "$BASEDIR/common.sh"
ROOT=$(cd "$BASEDIR/.." && pwd)
cd "$ROOT" || exit 1

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
}

PATHS=()
MARKER=""
PYTEST_ARGS=()
INSTALL=0
LIST=0

set_marker() {
    if [ -n "$MARKER" ] && [ "$MARKER" != "$1" ]; then
        echor "Groups '$MARKER_GROUP' and '$2' cannot be combined"
        exit 2
    fi
    MARKER="$1"
    MARKER_GROUP="$2"
}

while [ $# -gt 0 ]; do
    case "$1" in
        all)          PATHS+=("tests") ;;
        unit)         PATHS+=("tests/unit") ;;
        common)       PATHS+=("tests/unit/common") ;;
        bin)          PATHS+=("tests/unit/bin") ;;
        web)          PATHS+=("tests/web") ;;
        integration)  PATHS+=("tests/integration") ;;
        fast)         set_marker "not slow and not integration" fast ;;
        slow)         set_marker "slow" slow ;;
        live)         set_marker "live" live; PYTEST_ARGS+=("--run-live") ;;
        -k)           [ -n "$2" ] || { echor "-k needs an expression"; exit 2; }
                      PYTEST_ARGS+=("-k" "$2"); shift ;;
        -v)           PYTEST_ARGS+=("-v") ;;
        -x)           PYTEST_ARGS+=("-x") ;;
        -c|--cov)     PYTEST_ARGS+=("--cov=common" "--cov=bin" "--cov=web" "--cov-report=term-missing") ;;
        -l|--list)    PYTEST_ARGS+=("--collect-only" "-q"); LIST=1 ;;
        --install)    INSTALL=1 ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; PYTEST_ARGS+=("$@"); break ;;
        -*)           echor "Unknown option: $1 (see $0 --help)"; exit 2 ;;
        *)
            # path to a test file/directory, optionally with ::test_name
            if [ ! -e "${1%%::*}" ]; then
                echor "Unknown group or test path: $1 (see $0 --help)"
                exit 2
            fi
            PATHS+=("$1") ;;
    esac
    shift
done

# Python interpreter
if [ -z "$PYTHON" ]; then
    if [ -x "$ROOT/venv/bin/python" ]; then
        PYTHON="$ROOT/venv/bin/python"
    else
        PYTHON=python3
    fi
fi

if [ "$INSTALL" -eq 1 ]; then
    echob "** Installing test dependencies **"
    "$PYTHON" -m pip install -r install/pip_requirements-dev.txt || exit 1
fi

if ! "$PYTHON" -c "import pytest, responses, pytest_httpserver, freezegun, pytest_socket" 2>/dev/null; then
    echor "Test dependencies are missing for $PYTHON, run: $0 --install"
    exit 1
fi

CMD=("$PYTHON" -m pytest "${PATHS[@]}")
[ -n "$MARKER" ] && CMD+=("-m" "$MARKER")
CMD+=("${PYTEST_ARGS[@]}")

echob "=============== Running tests ==============="
echo "${CMD[*]}"
"${CMD[@]}"
status=$?

[ "$LIST" -eq 1 ] && exit $status
case $status in
    0) echob "** All selected tests passed **" ;;
    5) echoy "** No tests were selected **" ;;
    *) echor "** Tests failed (pytest exit code $status) **" ;;
esac
exit $status
