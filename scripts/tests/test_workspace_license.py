"""Check owned package metadata without changing third-party declarations."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkspaceLicense(unittest.TestCase):
    def test_owned_packages_advertise_gpl_3_only(self):
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual(workspace["workspace"]["package"]["license"], "GPL-3.0-only")
        manifests = [*ROOT.glob("crates/*/Cargo.toml"), *ROOT.glob("bins/*/Cargo.toml"), ROOT / "xtask/Cargo.toml"]
        for manifest in manifests:
            with self.subTest(package=manifest.parent.name):
                package = tomllib.loads(manifest.read_text())["package"]
                self.assertEqual(package["license"], {"workspace": True})


if __name__ == "__main__":
    unittest.main()
