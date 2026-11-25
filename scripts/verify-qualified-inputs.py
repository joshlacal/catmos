"""Verify the source, package and lockfile inputs of a qualified desktop build."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
pins = json.loads((root / "scripts/qualified-inputs.json").read_text())


def run(repo, *args):
    return subprocess.check_output(args, cwd=repo, text=True).strip()


def check_sources(name, revision):
    repo = root.parent / name
    if (repo / ".jj").is_dir():
        # An empty workspace-specific commit can sit above the sealed revision.
        if run(repo, "jj", "log", "-r", f"{revision} & ::@", "--no-graph", "-T", "commit_id") != revision:
            sys.exit(f"{name} does not contain qualified revision {revision}")
        edits = run(repo, "jj", "diff", "--from", revision, "--to", "@", "--summary")
    else:
        if run(repo, "git", "rev-parse", "HEAD") != revision:
            sys.exit(f"{name} is not at qualified revision {revision}")
        edits = run(repo, "git", "status", "--porcelain", "--untracked-files=all")
    if edits:
        sys.exit(f"{name} differs from the qualified source tree")


for name, revision in pins["sources"].items():
    check_sources(name, revision)

# Path dependencies have no repository identity in Cargo.lock. Check the selected
# manifests from the same desktop graph that the Tauri build will compile.
metadata = json.loads(run(root / "src-tauri", "cargo", "metadata", "--locked", "--format-version", "1"))
for package, relative in {
    "catbird_mls": "catbird-mls/Cargo.toml",
    "catbird-atproto": "catbird-atproto/Cargo.toml",
    "atproto-spaces": "catbird-atproto/atproto-spaces/Cargo.toml",
    "labyrinth": "labyrinth/Cargo.toml",
    "labyrinth-protocol": "labyrinth/labyrinth-protocol/Cargo.toml",
    "petrel": "Petrel/rust/petrel/Cargo.toml",
    "petrel-core": "Petrel/rust/petrel-core/Cargo.toml",
    "petrel-api": "Petrel/rust/petrel-api/Cargo.toml",
    "petrel-catbird": "PetrelCatbird/rust/petrel-catbird/Cargo.toml",
}.items():
    manifests = [Path(p["manifest_path"]).resolve() for p in metadata["packages"] if p["name"] == package]
    if manifests != [(root.parent / relative).resolve()]:
        sys.exit(f"Cargo selected an unexpected source for {package}")

for relative, digest in pins["sha256"].items():
    path = root / relative
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    if value != digest:
        sys.exit(f"{relative} differs from the qualified artifact")
print("Verified the desktop Rust sources, WASM package and package-manager locks.")
