"""Prove that scripts/check.sh's fast and mutant parts together run the full gate.

Hosted CI runs `check.sh fast` and `check.sh mutants` as separate jobs. Each
part runs here with every command it calls replaced by a recorder, so the test
compares what the parts and the full gate actually execute, in order.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

FAST = [
    "dated advisory exceptions (design §8.3)",
    "unsafe guard",
    "vendored transport dependencies (design §3.4)",
    "cargo fmt --check",
    "cargo clippy",
    "cargo test",
    "release latency (design §7)",
    "cargo deny",
]
MUTANTS = ["mutants (SI-33)"]
LATENCY = "release latency (design §7)"

RECORDER = """#!/bin/sh
printf '%s\\n' "{name} $*" >> "$CHECK_CALLS"
[ "$(wc -l < "$CHECK_CALLS")" != "${{CHECK_FAIL_AT:-0}}" ]
"""


class CheckModes(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        (self.root / "scripts").mkdir()
        shutil.copy(ROOT / "scripts/check.sh", self.root / "scripts/check.sh")
        for recorder in [bin_dir / "cargo", bin_dir / "python3", self.root / "scripts/check-vendor.sh", self.root / "scripts/check-upstream-advisories.sh"]:
            recorder.write_text(RECORDER.format(name=recorder.name))
            recorder.chmod(0o755)
        # Just enough tree for the unsafe guard, which runs for real.
        for member in ["crates/example", "bins/example", "xtask"]:
            (self.root / member).mkdir(parents=True)
            (self.root / member / "Cargo.toml").write_text("[lints]\nworkspace = true\n")
        (self.root / "vendor").mkdir()
        (self.root / "vendor/example.patch").write_text("")
        self.calls = self.root / "calls"
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "CHECK_CALLS": str(self.calls), "TMPDIR": str(self.tmp)}

    def run_gate(self, *args, fail_at=0):
        self.calls.unlink(missing_ok=True)
        result = subprocess.run(["bash", "scripts/check.sh", *args], cwd=self.root, env=dict(self.env, CHECK_FAIL_AT=str(fail_at)), capture_output=True, text=True)
        steps = [line[3:] for line in result.stdout.splitlines() if line.startswith("== ")]
        # mktemp names differ between runs; compare them as one placeholder.
        recorded = self.calls.read_text() if self.calls.exists() else ""
        calls = re.sub(re.escape(str(self.tmp)) + r"/\S+", "$TMPFILE", recorded).splitlines()
        return result, steps, calls

    def passing(self, *args):
        result, steps, calls = self.run_gate(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return steps, calls

    def test_each_mode_runs_its_listed_steps(self):
        for args, expected in [((), FAST + MUTANTS), (("all",), FAST + MUTANTS), (("fast",), FAST), (("mutants",), MUTANTS)]:
            with self.subTest(args=args):
                self.assertEqual(self.passing(*args)[0], expected)

    def test_fast_then_mutants_is_exactly_the_full_gate(self):
        full = self.passing()
        fast = self.passing("fast")
        mutants = self.passing("mutants")
        self.assertEqual(self.passing("all"), full)
        self.assertEqual(full[0], fast[0] + mutants[0])
        self.assertEqual(full[1], fast[1] + mutants[1])

    def test_the_mutant_part_runs_every_registered_mutant_and_the_release_guard(self):
        self.assertEqual(self.passing("mutants")[1], [
            "cargo run --locked -q -p kickoff-xtask -- mutants",
            "cargo run --locked -q -p kickoff-xtask -- release-guard",
        ])

    def test_release_latency_never_runs_in_the_mutant_part(self):
        # CI runs the parts on separate runners; the wall-clock budgets must
        # not share a machine with the mutant builds.
        self.assertIn(LATENCY, FAST)
        self.assertNotIn(LATENCY, MUTANTS)
        self.assertFalse([call for call in self.passing("mutants")[1] if "--release" in call.split()])

    def test_any_failing_command_fails_its_mode_and_stops_it(self):
        for mode in ["all", "fast", "mutants"]:
            total = len(self.passing(mode)[1])
            for index in range(1, total + 1):
                with self.subTest(mode=mode, failing=index):
                    result, _, calls = self.run_gate(mode, fail_at=index)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(calls), index, "a command ran after a failure")
                    self.assertNotIn("passed", result.stdout)

    def test_unknown_modes_and_extra_arguments_are_refused_before_any_step(self):
        for args in [("mutant",), ("FAST",), ("",), ("fast", "mutants"), ("--fast",)]:
            with self.subTest(args=args):
                result, steps, calls = self.run_gate(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("usage", result.stderr)
                self.assertEqual((steps, calls), ([], []))

    def test_hosted_ci_runs_both_parts(self):
        # Text checks, since the runner's python3 is not guaranteed PyYAML.
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        parts = re.findall(r"^ +part: \[(.*)\]$", workflow, re.MULTILINE)
        self.assertEqual([[part.strip() for part in found.split(",")] for found in parts], [["fast", "mutants"]])
        self.assertEqual(re.findall(r"^ +run: .*check\.sh.*", workflow, re.MULTILINE), ["        run: scripts/check.sh \"$PART\""])
        self.assertIn("PART: ${{ matrix.part }}", workflow)
        self.assertIn('RESULT: ${{ needs.linux.result }}\n        run: test "$RESULT" = success', workflow)


if __name__ == "__main__":
    unittest.main()
