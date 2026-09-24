#!/usr/bin/env python3
import os
import sys
import json
import uuid
import time
import subprocess
import signal
from pathlib import Path

WORKSPACE = "/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919"
GATEWAY_BIN = f"{WORKSPACE}/mls-ds/e2e-tests/target/debug/examples/client_runtime_gateway"
SERVER_BIN = f"{WORKSPACE}/mls-ds/target/debug/encrypted_request_server_fixture"
DESKTOP_BIN = f"{WORKSPACE}/catmos/src-tauri/target/debug/bundle/macos/Catmos Request Fixture.app/Contents/MacOS/catmos"
VITE_BIN = f"{WORKSPACE}/catmos/node_modules/vite/bin/vite.js"
CATMOS_DIR = f"{WORKSPACE}/catmos"

class LiveEnvironment:
    def __init__(self, label="catmos-browser"):
        self.run_id = str(uuid.uuid4())
        self.run_hex = self.run_id.replace("-", "")[:16]
        self.dedicated_db = f"catbird_direct_requests_fault_{self.run_hex}"
        self.db_url = f"postgresql://127.0.0.1:5432/{self.dedicated_db}"
        self.out_dir = f"/tmp/catbird-gw-{label}-{self.run_hex}"
        self.gw_proc = None
        self.vite_proc = None
        self.desktop_proc = None
        self.manifest = None
        self.sessions = None

    def setup(self):
        print(f"1. Creating dedicated empty database: {self.dedicated_db}")
        subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c", f"CREATE DATABASE {self.dedicated_db};"], check=True)

        setup_env = dict(
            os.environ,
            REQUEST_TEST_DATABASE_URL=self.db_url,
            REQUEST_SERVER_FIXTURE_BINARY=SERVER_BIN
        )
        subprocess.run([
            "cargo", "test", "--manifest-path", f"{WORKSPACE}/mls-ds/e2e-tests/Cargo.toml",
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
        self.gw_proc.stdin.write(json.dumps({"output_dir": self.out_dir, "cors_origin": "http://127.0.0.1:5173", "lifetime_seconds": 1800}))
        self.gw_proc.stdin.close()

        line = self.gw_proc.stdout.readline().strip()
        manifest_path = json.loads(line)["manifest"]
        with open(manifest_path) as f:
            self.manifest = json.load(f)
        with open(f"{self.out_dir}/sessions.json") as f:
            self.sessions = json.load(f)

        print(f"Gateway running. Origin: {self.manifest['origin']}")
        return self

    def start_vite(self):
        print("4. Starting Vite on Catmos web...")
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

        import urllib.request
        for _ in range(60):
            try:
                with urllib.request.urlopen("http://127.0.0.1:5173/") as res:
                    if res.status == 200:
                        break
            except Exception:
                time.sleep(0.5)
        print("Vite is ready on http://127.0.0.1:5173/")

    def start_desktop(self, label="alice"):
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
            [DESKTOP_BIN],
            env=desktop_env,
            stdout=subprocess.DEVNULL,
            stderr=desktop_stderr,
            text=True
        )
        self.desktop_pid = self.desktop_proc.pid
        print(f"Catmos Desktop started (PID {self.desktop_pid}) for {label}")
        return self.desktop_pid
    def teardown(self):
        print("Teardown live environment...")
        if self.desktop_proc:
            try:
                os.kill(self.desktop_proc.pid, signal.SIGINT)
                self.desktop_proc.wait(timeout=5)
            except Exception:
                pass
        if self.vite_proc:
            try:
                self.vite_proc.terminate()
            except Exception:
                pass
        if self.gw_proc:
            try:
                os.kill(self.gw_proc.pid, signal.SIGINT)
                self.gw_proc.wait(timeout=5)
            except Exception:
                pass
        # Terminate any remaining backends on the dedicated DB before DROP
        subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c",
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{self.dedicated_db}' AND pid<>pg_backend_pid();"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["psql", "postgresql://127.0.0.1:5432/postgres", "-X", "-c", f"DROP DATABASE IF EXISTS {self.dedicated_db};"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Dedicated database {self.dedicated_db} dropped cleanly.")

if __name__ == "__main__":
    env = LiveEnvironment()
    try:
        env.setup()
        env.start_vite()
        print("Setup verified successfully.")
    finally:
        env.teardown()
