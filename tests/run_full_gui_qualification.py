#!/usr/bin/env python3
"""Automated driver for Catmos Desktop GUI + Browser live qualification.
Implements all 7 legs of Validation Section 4.
Can be imported and driven directly from Python Eval.
"""
import os
import sys
import json
import uuid
import time
import shutil
import asyncio
import hashlib
import subprocess
from pathlib import Path

WORKSPACE = Path("/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919")
GATEWAY_BIN = str(WORKSPACE / "mls-ds/e2e-tests/target/debug/examples/client_runtime_gateway")
SERVER_BIN = str(WORKSPACE / "mls-ds/target/debug/encrypted_request_server_fixture")
VITE_BIN = str(WORKSPACE / "catmos/node_modules/vite/bin/vite.js")
CATMOS_DIR = str(WORKSPACE / "catmos")
DESKTOP_BIN = str(WORKSPACE / "catmos/src-tauri/target/debug/bundle/macos/Catmos Request Fixture.app/Contents/MacOS/catmos")
if not os.path.exists(DESKTOP_BIN):
    DESKTOP_BIN = str(WORKSPACE / "catmos/src-tauri/target/debug/catmos")

class BrowserController:
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.proc = subprocess.Popen(
            ["node", str(WORKSPACE / "catmos/tests/browser-live-controller.mjs")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )

    def call(self, req):
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        res = json.loads(line.strip())
        if not res.get("ok", False):
            raise RuntimeError(f"Browser controller error for {req.get('cmd')}: {res.get('error')}")
        return res

    def close(self):
        try:
            self.call({"cmd": "close"})
        except Exception:
            pass
        try:
            self.proc.kill()
        except Exception:
            pass

def clean_database(db_name):
    subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c",
        f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{db_name}' AND pid<>pg_backend_pid();"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c", f"DROP DATABASE IF EXISTS {db_name};"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
