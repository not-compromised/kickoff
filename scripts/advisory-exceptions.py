#!/usr/bin/env python3
"""Validate dated exceptions and emit a cargo-deny configuration."""
import argparse
from datetime import date, datetime, timezone
import json
from pathlib import Path
import re
import sys
import tomllib


def generate(root, today):
    source = tomllib.loads((root / "advisory-exceptions.toml").read_text())
    if set(source) != {"exception"} or not isinstance(source["exception"], list):
        raise ValueError("exception source must contain only [[exception]] entries")
    ignores = []
    seen = set()
    for entry in source["exception"]:
        if set(entry) != {"id", "reason", "issued", "expires"}:
            raise ValueError("exception fields must be id, reason, issued and expires")
        advisory = entry["id"]
        if not isinstance(advisory, str) or not re.fullmatch(r"RUSTSEC-[0-9]{4}-[0-9]{4}", advisory):
            raise ValueError("unknown advisory identifier")
        if advisory in seen:
            raise ValueError(f"duplicate exception: {advisory}")
        seen.add(advisory)
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise ValueError(f"{advisory}: reason must be nonempty")
        dates = []
        for field in ["issued", "expires"]:
            value = entry[field]
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
                raise ValueError(f"{advisory}: {field} must be a YYYY-MM-DD date")
            dates.append(date.fromisoformat(value))
        issued, expires = dates
        if issued > today:
            raise ValueError(f"{advisory}: issued date is in the future")
        if expires <= issued or (expires - issued).days > 90:
            raise ValueError(f"{advisory}: expiry must be after issue and at most 90 days later")
        if today >= expires:
            raise ValueError(f"{advisory}: exception expired on {expires}")
        ignores.append("{ id = " + json.dumps(advisory, ensure_ascii=False) + ", reason = " + json.dumps(entry["reason"], ensure_ascii=False) + " }")
    template = (root / "deny.toml").read_text()
    config = tomllib.loads(template)
    marker = "ignore = [] # generated dated exceptions"
    if config.get("advisories", {}).get("ignore") != [] or template.count(marker) != 1:
        raise ValueError("deny template must have exactly one empty generated exception list")
    generated = template.replace(marker, "ignore = [" + ", ".join(ignores) + "]")
    actual = tomllib.loads(generated)["advisories"]["ignore"]
    expected = [{"id": entry["id"], "reason": entry["reason"]} for entry in source["exception"]]
    if actual != expected:
        raise ValueError("deny template generated marker must be the advisory ignore list")
    return generated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--today", type=date.fromisoformat, help="controlled date for policy tests only")
    args = parser.parse_args()
    try:
        config = generate(Path(__file__).resolve().parent.parent, args.today or datetime.now(timezone.utc).date())
        args.output.write_text(config)
    except (OSError, ValueError, TypeError) as error:
        print(f"advisory exceptions: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
