"""Exercise the generated deny policy and both existing advisory entry points."""
import json
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TODAY = "2026-10-12"
VALID = {"id": "RUSTSEC-2024-0436", "reason": "compile-time only", "issued": "2026-10-12", "expires": "2027-01-10"}


def metadata(entries):
    return "".join("[[exception]]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in entry.items()) for entry in entries)


class AdvisoryExceptions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        shutil.copy(ROOT / "deny.toml", self.root / "deny.toml")
        shutil.copy(ROOT / "Cargo.lock", self.root / "Cargo.lock")
        for member in ["crates/example", "bins/example", "xtask"]:
            directory = self.root / member
            directory.mkdir(parents=True)
            (directory / "Cargo.toml").write_text("[lints]\nworkspace = true\n")
        (self.root / "vendor").mkdir()
        (self.root / "vendor/example.patch").write_text("")
        (self.root / "vendor/crates.tsv").write_text("iroh\t1.3.0\thash\thash\n")
        (self.root / "scripts/check-vendor.sh").write_text("#!/bin/sh\nexit 0\n")
        fake = self.root / "cargo"
        fake.write_text("""#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import subprocess
if os.environ.get("KICKOFF_POLICY_RECORDER_ACTIVE"):
    sys.exit("recursive policy Cargo recorder invocation refused")
args = sys.argv[1:]
with Path(os.environ["CARGO_CALLS"]).open("a") as calls:
    calls.write(" ".join(args) + "\\n")
if args[0] == "deny":
    # Parse the recorded arguments with the installed CLI, without doing a scan.
    env = dict(os.environ, KICKOFF_POLICY_RECORDER_ACTIVE="1")
    parsed = subprocess.run([os.environ["REAL_CARGO_DENY"], *args, "--help"], env=env, cwd=os.environ["CARGO_DENY_WORKSPACE"], capture_output=True, text=True, timeout=10)
    if parsed.returncode:
        sys.stderr.write(parsed.stderr)
        sys.exit(parsed.returncode)
    if "--config" in args:
        config = Path(args[args.index("--config") + 1])
    else:
        config = Path(args[args.index("--manifest-path") + 1]).parent / "deny.toml"
    Path(os.environ["CARGO_SNAPSHOT"]).write_text(config.read_text())
""")
        fake.chmod(0o755)
        cargo_deny = shutil.which("cargo-deny")
        if cargo_deny is None:
            raise RuntimeError("policy tests require cargo-deny on PATH")
        self.env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}", CARGO_CALLS=str(self.root / "calls"), CARGO_SNAPSHOT=str(self.root / "deny-snapshot"), REAL_CARGO_DENY=cargo_deny, CARGO_DENY_WORKSPACE=str(ROOT))

    def prepare(self, entries, today=TODAY):
        (self.root / "advisory-exceptions.toml").write_text(metadata(entries))
        return subprocess.run(["python3", "scripts/advisory-exceptions.py", "--today", today, "--output", "generated.toml"], cwd=self.root, capture_output=True, text=True)

    def test_current_exception_generates_cargo_deny_schema(self):
        result = self.prepare([VALID])
        self.assertEqual(result.returncode, 0, result.stderr)
        import tomllib
        generated = tomllib.loads((self.root / "generated.toml").read_text())
        self.assertEqual(generated["advisories"]["ignore"], [{"id": VALID["id"], "reason": VALID["reason"]}])

    def test_missing_dates_are_refused(self):
        for field in ["issued", "expires"]:
            with self.subTest(field=field):
                entry = dict(VALID)
                del entry[field]
                result = self.prepare([entry])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("fields", result.stderr)

    def test_expiry_is_exclusive(self):
        result = self.prepare([VALID], today=VALID["expires"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expired", result.stderr)
        self.assertEqual(self.prepare([VALID], today="2027-01-09").returncode, 0)

    def test_over_90_days_and_future_issue_are_refused(self):
        for entry, diagnostic in [(dict(VALID, expires="2027-01-11"), "90 days"), (dict(VALID, issued="2026-10-13"), "future")]:
            with self.subTest(entry=entry):
                result = self.prepare([entry])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)

    def test_unknown_duplicate_and_invalid_entries_fail_closed(self):
        for entries in [[dict(VALID, surprise="ignored?")], [VALID, VALID], [dict(VALID, id="CVE-unknown")], [dict(VALID, expires="2026-10-11")], [dict(VALID, issued="bad-date")], [dict(VALID, reason=" ")]]:
            with self.subTest(entries=entries):
                self.assertNotEqual(self.prepare(entries).returncode, 0)
        (self.root / "advisory-exceptions.toml").write_text("unknown = []\n")
        result = subprocess.run(["python3", "scripts/advisory-exceptions.py", "--today", TODAY, "--output", "generated.toml"], cwd=self.root, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)

    def test_template_cannot_add_an_indefinite_ignore(self):
        (self.root / "deny.toml").write_text('[advisories]\nignore = ["RUSTSEC-2024-0436"]\n')
        result = self.prepare([VALID])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("template", result.stderr)

    def test_template_marker_cannot_be_a_comment(self):
        (self.root / "deny.toml").write_text('[advisories]\nignore = []\n# ignore = [] # generated dated exceptions\n')
        result = self.prepare([VALID])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("template", result.stderr)

    def test_both_gates_use_generated_ignores(self):
        import tomllib
        today = datetime.now(timezone.utc).date()
        entry = dict(VALID, issued=today.isoformat(), expires=(today + timedelta(days=90)).isoformat())
        (self.root / "advisory-exceptions.toml").write_text(metadata([entry]))
        # The script's nested test step is already being exercised by this suite.
        # Avoid recursively launching another copy inside the throwaway fixture.
        python = self.root / "python3"
        python.write_text(f'#!/bin/sh\nif [ "$1" = "-m" ]; then exit 0; fi\nexec "{sys.executable}" "$@"\n')
        python.chmod(0o755)
        for script in ["check.sh", "check-upstream-advisories.sh"]:
            with self.subTest(script=script):
                (self.root / "calls").unlink(missing_ok=True)
                (self.root / "deny-snapshot").unlink(missing_ok=True)
                result = subprocess.run(["bash", f"scripts/{script}"], cwd=self.root, env=self.env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                config = tomllib.loads((self.root / "deny-snapshot").read_text())
                self.assertEqual(config["advisories"]["ignore"], [{"id": entry["id"], "reason": entry["reason"]}])
                calls = (self.root / "calls").read_text()
                if script == "check-upstream-advisories.sh":
                    self.assertIn("metadata --manifest-path", calls)
                    self.assertNotIn("--offline", calls)
                else:
                    self.assertIn("deny --config", calls)

    def test_a_wrapper_cannot_reenter_the_policy_recorder(self):
        wrapper = self.root / "cargo-deny-wrapper"
        wrapper.write_text('#!/bin/sh\nexec "$POLICY_RECORDER" "$@"\n')
        wrapper.chmod(0o755)
        env = dict(self.env, REAL_CARGO_DENY=str(wrapper), POLICY_RECORDER=str(self.root / "cargo"))
        result = subprocess.run(
            [str(self.root / "cargo"), "deny", "--config", str(self.root / "deny.toml")],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recursive policy Cargo recorder invocation refused", result.stderr)
        self.assertEqual((self.root / "calls").read_text().splitlines(), [f"deny --config {self.root / 'deny.toml'}"])
        self.assertFalse((self.root / "deny-snapshot").exists())

    def test_recording_cargo_rejects_misplaced_global_config(self):
        result = subprocess.run([str(self.root / "cargo"), "deny", "check", "--config", str(self.root / "deny.toml"), "--hide-inclusion-graph"], cwd=self.root, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("unexpected argument '--config'", result.stderr)
        self.assertFalse((self.root / "deny-snapshot").exists())

    def test_both_gates_refuse_invalid_exceptions_before_cargo(self):
        today = datetime.now(timezone.utc).date()
        invalid = [
            ({k: v for k, v in VALID.items() if k != "expires"}, "fields"),
            (dict(VALID, issued="2020-01-01", expires="2020-01-02"), "expired"),
            (dict(VALID, issued=today.isoformat(), expires=(today + timedelta(days=91)).isoformat()), "90 days"),
            (dict(VALID, issued=(today + timedelta(days=1)).isoformat(), expires=(today + timedelta(days=2)).isoformat()), "future"),
        ]
        for script in ["check.sh", "check-upstream-advisories.sh"]:
            for entry, diagnostic in invalid:
                with self.subTest(script=script, diagnostic=diagnostic):
                    (self.root / "advisory-exceptions.toml").write_text(metadata([entry]))
                    (self.root / "calls").unlink(missing_ok=True)
                    result = subprocess.run(["bash", f"scripts/{script}"], cwd=self.root, env=self.env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(diagnostic, result.stderr)
                    self.assertFalse((self.root / "calls").exists(), "invalid exceptions reached cargo")


if __name__ == "__main__":
    unittest.main()
