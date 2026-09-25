#!/usr/bin/env python3
"""Desktop GUI + Playwright Interoperability Driver for catmos-browser and browser-catmos.
Drives the real Catmos desktop GUI app via the eval `computer` helpers,
and the Browser webapp via Playwright browser-live-controller.mjs.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import uuid

WORKSPACE = Path("/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919")
GATEWAY_BIN = str(WORKSPACE / "mls-ds/e2e-tests/target/debug/examples/client_runtime_gateway")
SERVER_BIN = str(WORKSPACE / "mls-ds/target/debug/encrypted_request_server_fixture")
VITE_BIN = str(WORKSPACE / "catmos/node_modules/vite/bin/vite.js")
CATMOS_DIR = str(WORKSPACE / "catmos")
DESKTOP_BIN = str(WORKSPACE / "catmos/src-tauri/target/debug/catmos")

def sha256_file(path: Path) -> tuple[int, str]:
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()

class DesktopLock:
    def __init__(self, owner="ClientWeb", lock_path="/tmp/desktop-ui.lock"):
        self.owner = owner
        self.lock_path = lock_path

    async def acquire(self):
        while True:
            try:
                os.mkdir(self.lock_path)
                with open(os.path.join(self.lock_path, "owner"), "w") as f:
                    f.write(f"{self.owner}\n")
                print(f"[LOCK] Acquired desktop lock for {self.owner}")
                return
            except FileExistsError:
                print("[LOCK] Desktop lock held by another agent, waiting 10s...")
                await asyncio.sleep(10)

    def release(self):
        try:
            if os.path.exists(self.lock_path):
                shutil.rmtree(self.lock_path)
                print(f"[LOCK] Released desktop lock for {self.owner}")
        except Exception as e:
            print(f"[LOCK] Error releasing lock: {e}")

class LiveEnvironment:
    def __init__(self, label="catmos-browser"):
        self.label = label
        self.run_id = str(uuid.uuid4())
        self.run_hex = self.run_id.replace("-", "")[:16]
        self.dedicated_db = f"catbird_direct_requests_fault_{self.run_hex}"
        self.db_url = f"postgresql://127.0.0.1:5432/{self.dedicated_db}"
        self.out_dir = f"/tmp/catbird-gw-{label}-{self.run_hex}"
        self.gw_proc = None
        self.vite_proc = None
        self.desktop_proc = None
        self.desktop_pid = None
        self.manifest = None
        self.sessions = None
        self.evid_dir = WORKSPACE / f"docs/generated-artifacts/encrypted-requests/evidence/{label}"
        self.evid_dir.mkdir(parents=True, exist_ok=True)

    def setup(self):
        print(f"1. Creating dedicated empty database: {self.dedicated_db}")
        subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c", f"CREATE DATABASE {self.dedicated_db};"], check=True)

        setup_env = dict(
            os.environ,
            REQUEST_TEST_DATABASE_URL=self.db_url,
            REQUEST_SERVER_FIXTURE_BINARY=SERVER_BIN
        )
        print("2. Installing 39 migrations...")
        subprocess.run([
            "cargo", "test", "--manifest-path", str(WORKSPACE / "mls-ds/e2e-tests/Cargo.toml"),
            "--test", "encrypted_direct_requests",
            "c01_real_router_auth_live_preparation_and_native_recipient_preview",
            "--", "--nocapture"
        ], env=setup_env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"3. Starting client_runtime_gateway at {self.out_dir}...")
        gw_env = os.environ.copy()
        gw_env["REQUEST_TEST_DATABASE_URL"] = self.db_url
        gw_env["REQUEST_SERVER_FIXTURE_BINARY"] = SERVER_BIN
        gw_env["RUST_LOG"] = "info,catbird_server=debug"

        self.gw_proc = subprocess.Popen(
            [GATEWAY_BIN],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=open(f"/tmp/gw-{self.run_hex}.stderr", "w"),
            env=gw_env,
            text=True
        )
        assert self.gw_proc.stdin is not None
        self.gw_proc.stdin.write(json.dumps({"output_dir": self.out_dir, "cors_origin": "http://127.0.0.1:5173", "lifetime_seconds": 1800}))
        self.gw_proc.stdin.close()

        assert self.gw_proc.stdout is not None
        line = self.gw_proc.stdout.readline().strip()
        manifest_path = json.loads(line)["manifest"]
        with open(manifest_path) as f:
            self.manifest = json.load(f)
        with open(f"{self.out_dir}/sessions.json") as f:
            self.sessions = json.load(f)

        assert self.manifest is not None
        print(f"Gateway running. Origin: {self.manifest['origin']}")
        return self

    def start_vite(self):
        print("4. Starting Vite on Catmos web...")
        assert self.manifest is not None
        vite_env = os.environ.copy()
        vite_env["VITE_LOCAL_REQUEST_FIXTURE_ORIGIN"] = self.manifest["origin"]
        vite_env["VITE_LOCAL_REQUEST_FIXTURE_RUN_ID"] = str(uuid.uuid4())
        vite_log = open(f"/tmp/vite-{self.run_hex}.log", "w")
        self.vite_proc = subprocess.Popen(
            ["node", VITE_BIN, "--host", "127.0.0.1", "--port", "5173", "--strictPort", "--mode", "local-runtime-fixture"],
            cwd=CATMOS_DIR,
            env=vite_env,
            stdout=vite_log,
            stderr=subprocess.STDOUT
        )

        for _ in range(60):
            try:
                with urllib.request.urlopen("http://127.0.0.1:5173/") as res:
                    if res.status == 200:
                        break
            except Exception:
                time.sleep(0.5)
        print("Vite is ready on http://127.0.0.1:5173/")

    def start_desktop(self, label="alice", desktop_bin=DESKTOP_BIN):
        desktop_profile = f"/tmp/catmos-desktop-profile-{label}-{self.run_hex}"
        desktop_config = f"/tmp/catmos-fixture-{label}-{self.run_hex}.json"
        with open(desktop_config, "w") as f:
            json.dump({
                "manifest": f"{self.out_dir}/manifest.json",
                "sessions": f"{self.out_dir}/sessions.json",
                "label": label,
                "profile": desktop_profile,
                "keychain_namespace": f"blue.catbird.catmos.fixture.{self.run_id}"
            }, f)
        os.chmod(desktop_config, 0o600)
        desktop_env = os.environ.copy()
        desktop_env["CATMOS_RUNTIME_FIXTURE_CONFIG"] = desktop_config
        desktop_stderr = open(f"/tmp/desktop-{label}-{self.run_hex}.stderr", "w")
        self.desktop_proc = subprocess.Popen(
            [desktop_bin],
            env=desktop_env,
            stdout=subprocess.DEVNULL,
            stderr=desktop_stderr,
            text=True
        )
        self.desktop_pid = self.desktop_proc.pid
        print(f"Catmos Desktop started (PID {self.desktop_pid}) for {label}")
        return self.desktop_pid

    def stop_desktop(self):
        if self.desktop_proc:
            pid = self.desktop_proc.pid
            print(f"Stopping Catmos Desktop (PID {pid})...")
            try:
                self.desktop_proc.terminate()
                self.desktop_proc.wait(timeout=5)
            except Exception:
                try:
                    self.desktop_proc.kill()
                except Exception:
                    pass
            self.desktop_proc = None
            print(f"Catmos Desktop (PID {pid}) stopped.")

    def teardown(self):
        print("Teardown live environment...")
        self.stop_desktop()
        if self.vite_proc:
            try:
                self.vite_proc.terminate()
            except Exception:
                pass
        if self.gw_proc:
            try:
                self.gw_proc.terminate()
            except Exception:
                pass
        subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c",
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{self.dedicated_db}' AND pid<>pg_backend_pid();"],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c", f"DROP DATABASE IF EXISTS {self.dedicated_db};"],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Dedicated database {self.dedicated_db} dropped cleanly.")
