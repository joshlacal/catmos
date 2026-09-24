#!/usr/bin/env python3
import asyncio, json, os, subprocess, time, uuid, sys, importlib, re
from pathlib import Path

WORKSPACE = "/Users/joshlacalamito/Developer/.workspaces/catbird-encrypted-requests-20260919"
sys.path.insert(0, f"{WORKSPACE}/catmos/tests")

import catmos_browser_live_harness
importlib.reload(catmos_browser_live_harness)
from catmos_browser_live_harness import LiveEnvironment
from browser_client_helper import BrowserClient

win = None

async def ref_of(pred):
    global win
    try:
        t = await win.ax(all=True)
        for l in t.splitlines():
            if pred(l) and "(disabled)" not in l:
                m = re.search(r'\[ref=(e\d+)\]', l)
                if m: return m.group(1)
    except Exception:
        pass
    return None

async def click(pred, wait=2.0, tries=10):
    global win
    for _ in range(tries):
        r = await ref_of(pred)
        if r:
            await (await win.ref(r)).press()
            await asyncio.sleep(wait)
            return True
        await asyncio.sleep(0.5)
    return False

async def texts(keys):
    global win
    t = await win.ax(all=True)
    return [l.strip() for l in t.splitlines() if any(k in l.lower() for k in keys)]

async def attach_desktop(pid):
    global win
    print(f"Attaching to desktop window for PID {pid}...")
    for attempt in range(25):
        try:
            ws = [w for w in await computer.windows(app="Catmos Request Fixture") if w.get('pid') == pid]
            if ws:
                win = await computer.window(ws[0]['id'])
                if await ref_of(lambda l: True):
                    print(f"Attached successfully to window {ws[0]['id']}!")
                    return win
        except Exception:
            pass
        await asyncio.sleep(1)
    raise RuntimeError(f"Attach failed for desktop PID {pid}")

print("Bidirectional live helpers defined.")
