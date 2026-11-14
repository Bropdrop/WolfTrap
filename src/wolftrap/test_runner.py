"""Standard-library unittest runner that emits machine-readable actual counts."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

from .report import write_json_report
from .revision import capture_source_revision


def run_tests(
    *, test_directory: str | Path = "tests", pattern: str = "test*.py", verbosity: int = 2
) -> tuple[dict[str, object], bool]:
    start_revision = capture_source_revision()
    suite = unittest.defaultTestLoader.discover(str(test_directory), pattern=pattern)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=verbosity).run(suite)
    end_revision = capture_source_revision()
    source_stable = start_revision == end_revision
    summary: dict[str, object] = {
        "run_by_research_engine": True,
        "framework": "unittest",
        "tests_run": result.testsRun,
        "skipped": len(result.skipped),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "successful": result.wasSuccessful() and source_stable,
        "source_revision": start_revision.to_dict(),
        "source_revision_end": end_revision.to_dict(),
        "source_stable": source_stable,
    }
    return summary, result.wasSuccessful() and source_stable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-directory", default="tests")
    parser.add_argument("--pattern", default="test*.py")
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)
    summary, successful = run_tests(
        test_directory=arguments.test_directory,
        pattern=arguments.pattern,
    )
    write_json_report(summary, arguments.output)
    return 0 if successful else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
