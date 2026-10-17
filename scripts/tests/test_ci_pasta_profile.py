"""Policy rendering must preserve the package profile and forbid path injection."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "ci_pasta_profile", Path(__file__).resolve().parents[1] / "ci-pasta-profile.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PROFILE = """abi <abi/4.0>,
profile pasta /usr/bin/pasta{,.avx2} flags=(attach_disconnected) {
  include <abstractions/pasta>
  /tmp/** rw,
}
"""


class PastaProfile(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.workspace = Path(temp.name)

    def test_only_the_exact_link_is_added_and_existing_rules_survive(self):
        rendered = module.render(PROFILE, self.workspace)
        rule = f'  owner "{self.workspace}/target/debug/kickoff-box-link" Ux,\n'
        self.assertEqual(rendered.count(rule), 1)
        self.assertEqual(rendered.replace(rule, ""), PROFILE)
        self.assertEqual(module.render(rendered, self.workspace), rendered)

    def test_policy_metacharacters_in_workspace_are_refused(self):
        for name in ['wild*', 'wild?', '[path]', '{path}', 'quote"', 'line\nbreak', 'has space']:
            with self.subTest(name=name):
                path = self.workspace / name
                path.mkdir()
                with self.assertRaises(ValueError):
                    module.render(PROFILE, path)

    def test_an_unrecognized_or_ambiguous_profile_is_refused(self):
        for profile in ["", PROFILE.replace("profile pasta ", "profile passt "), PROFILE + PROFILE]:
            with self.subTest(profile=profile):
                with self.assertRaises(ValueError):
                    module.render(profile, self.workspace)
