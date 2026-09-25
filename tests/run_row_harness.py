#!/usr/bin/env python3
"""Runner for catmos-browser and browser-catmos live qualification rows.
Executes the cargo tests, captures logs, packages evidence, and validates.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path("/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919")

def run_row(row_id: str):
    print(f"=== Starting live qualification for {row_id} ===")
    test_name = "catmos_browser_live_row" if row_id == "catmos-browser" else "browser_catmos_live_row"
    log_name = f"{row_id}-live.log"
    log_path = Path(f"/tmp/{log_name}")
    evid_dir = ROOT / f"docs/generated-artifacts/encrypted-requests/evidence/{row_id}"
    evid_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "cargo", "test",
        "--features", "local-runtime-fixture",
        "--lib", test_name,
        "--", "--nocapture"
    ]
    env = os.environ.copy()
    env["RUST_BACKTRACE"] = "1"

    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT / "catmos/src-tauri"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log_file.write(line)
            log_file.flush()
        proc.wait()

    if proc.returncode != 0:
        print(f"FAILED: {row_id} exited with code {proc.returncode}")
        return False

    # Copy log to evidence directory
    target_log = evid_dir / log_name
    target_log.write_bytes(log_path.read_bytes())
    print(f"SUCCESS: {row_id} completed cleanly. Log saved to {target_log}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Run catmos live qualification rows")
    parser.add_argument("row", choices=["catmos-browser", "browser-catmos", "all"], help="Row to run")
    args = parser.parse_args()

    rows = ["catmos-browser", "browser-catmos"] if args.row == "all" else [args.row]
    for r in rows:
        ok = run_row(r)
        if not ok:
            sys.exit(1)

if __name__ == "__main__":
    main()
