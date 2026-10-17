#!/usr/bin/env python3
"""Render the runner's pasta profile with one Cargo test-link allowance."""
import argparse
from pathlib import Path
import re


def render(profile: str, workspace: Path) -> str:
    root = workspace.resolve(strict=True)
    if not root.is_dir() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(root)):
        raise ValueError("workspace must be a directory without policy metacharacters")
    lines = profile.splitlines(keepends=True)
    headers = [i for i, line in enumerate(lines) if line.startswith("profile pasta ")]
    ends = [i for i, line in enumerate(lines) if line.strip() == "}"]
    if len(headers) != 1 or len(ends) != 1 or headers[0] >= ends[0]:
        raise ValueError("expected one pasta profile block")
    rule = f'  owner "{root}/target/debug/kickoff-box-link" Ux,\n'
    if rule not in lines:
        lines.insert(ends[0], rule)
    return "".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--profile", type=Path, default=Path("/etc/apparmor.d/usr.bin.pasta"))
    args = parser.parse_args()
    print(render(args.profile.read_text(), args.workspace), end="")
