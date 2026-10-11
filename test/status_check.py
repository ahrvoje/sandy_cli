"""Check only recovery state owned by the named test runs and profiles."""
import argparse
import glob
import json
from pathlib import Path
import re
import subprocess
import time


def owned_entries(status, instances, profiles, kind="all"):
    found = []
    if kind in ("all", "instances"):
        found += [e for e in status["instances"] if e["uuid"] in instances]
        found += [e for e in status["retry_containers"] if e["instance"] in instances]
    if kind in ("all", "tasks"):
        found += [e for e in status["tasks"] if e["instance"] in instances]
    if kind in ("all", "profiles"):
        containers = {("Sandy_" + name).lower() for name in instances}
        found += [e for e in status["profiles"] if e.lower() in containers]
        found += [e for e in status["saved_profiles"] if e["name"].lower() in profiles]
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sandy")
    parser.add_argument("--logs", action="append", default=[])
    parser.add_argument("--instance", action="append", default=[])
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--kind", choices=("all", "instances", "tasks", "profiles"), default="all")
    parser.add_argument("--wait", type=float, default=0, help="Bounded wait for test-owned state to clear")
    args = parser.parse_args()
    instances = set(args.instance)
    for pattern in args.logs:
        paths = glob.glob(pattern)
        if not paths:
            raise RuntimeError(f"Missing run logs: {pattern}")
        for path in paths:
            matches = re.findall(r"INSTANCE: ([\w-]+)", Path(path).read_text(encoding="utf-8-sig"))
            if not matches:
                raise RuntimeError(f"Missing instance ID: {path}")
            instances.update(matches)
    deadline = time.monotonic() + args.wait
    while True:
        result = subprocess.run([args.sandy, "--status", "--json"], check=True,
                                capture_output=True, encoding="utf-8", timeout=30)
        found = owned_entries(json.loads(result.stdout), instances,
                              {p.lower() for p in args.profile}, args.kind)
        if not found or time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    if found:
        print("[FAIL] Test-owned recovery state remains:", found)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
