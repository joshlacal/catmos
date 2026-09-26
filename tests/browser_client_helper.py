#!/usr/bin/env python3
import os
import sys
import json
import uuid
import time
import subprocess
import signal
import re
from pathlib import Path

WORKSPACE = "/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919"
sys.path.insert(0, f"{WORKSPACE}/catmos/tests")
from catmos_browser_live_harness import LiveEnvironment

class BrowserClient:
    def __init__(self, manifest_path, label, run_id):
        self.proc = subprocess.Popen(
            ["node", f"{WORKSPACE}/catmos/tests/browser-live-controller.mjs"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=open(f"/tmp/browser-controller-{label}.stderr", "w"),
            text=True
        )
        self.label = label
        res = self._req({"cmd": "init", "manifestPath": manifest_path, "label": label, "runId": run_id})
        assert res.get("ok"), f"Browser init failed: {res}"
        self.did = res["did"]

    def _req(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"Browser controller EOF for {self.label}")
        return json.loads(line)

    def await_preview(self, cid, text=None):
        return self._req({"cmd": "await_preview", "cid": cid, "text": text})

    def accept(self, cid):
        return self._req({"cmd": "accept", "cid": cid})

    def send_message(self, cid, text):
        return self._req({"cmd": "send_message", "cid": cid, "text": text})

    def send_request(self, recipient_did, text):
        self._req({"cmd": "compose_request", "recipientDid": recipient_did, "text": text})
        return self._req({"cmd": "send_introduction", "recipientDid": recipient_did, "text": text})

    def fetch_messages(self, cid):
        return self._req({"cmd": "fetch_messages", "cid": cid})

    def reload_and_check(self, cid):
        return self._req({"cmd": "reload_and_check", "cid": cid})

    def screenshot(self, path):
        return self._req({"cmd": "screenshot", "path": path})

    def close(self):
        try:
            self._req({"cmd": "close"})
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

print("BrowserClient defined.")
