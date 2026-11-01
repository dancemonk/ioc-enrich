"""`ioc-enrich keys`: ask for each API key and save it to the keys file.

Keys are typed into getpass, so they never appear on screen, and are never
printed afterwards. The file is written owner-only (0600) in an owner-only
folder (0700). Pressing Enter keeps the current key (or leaves it unset).
"""

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Callable, Mapping

from ioc_enrich.config import DEFAULT_KEYS_FILE, ENV_NAMES, KEY_NAMES, _read_keys_file

WHERE = {
    "vt": "VirusTotal community account → profile → API key",
    "abusech": "https://auth.abuse.ch/ (one key covers all three)",
    "otx": "https://otx.alienvault.com/ → Settings → API key",
    "abuseipdb": "https://www.abuseipdb.com/ → Account → API",
}


def _looks_like_key(value: str) -> bool:
    return bool(value) and not any(c.isspace() for c in value) and "=" not in value


def _write(path: Path, values: dict[str, str]) -> None:
    """Replace our NAME=value lines; keep comments and any other lines.

    The new file is written to a private (0600) temp file and swapped in with
    os.replace, so the keys never sit in a readable file, a crash never cuts
    the file short, and a symlink at `path` is replaced, never written through.
    """
    ours = set(ENV_NAMES.values())
    kept = []
    if path.exists() and not path.is_symlink():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            name = line.split("=", 1)[0].strip().removeprefix("export ").strip() if "=" in line else ""
            if name not in ours:
                kept.append(line)
    lines = kept + [f"{env}={values[env]}" for env in ENV_NAMES.values() if env in values]
    folder_is_new = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if folder_is_new or path.parent == DEFAULT_KEYS_FILE.parent:
        path.parent.chmod(0o700)         # our own folder; never chmod a folder the user picked
    temp = path.with_name(f".{path.name}.tmp")
    temp.unlink(missing_ok=True)         # left over from a crash
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def run(path: Path, *, ask: Callable[[str], str] = getpass.getpass, out=sys.stdout,
        env: Mapping[str, str] = os.environ) -> int:
    current = _read_keys_file(path)
    print(f"API keys for ioc-enrich, saved to {path}", file=out)
    print("Paste each key and press Enter (it is not shown). Press Enter alone to skip.\n", file=out)
    entered = {}
    try:
        for field, env_name in ENV_NAMES.items():
            state = "already set, Enter keeps it" if current.get(env_name) else "not set"
            prompt = f"{KEY_NAMES[field]} ({state})\n  get it: {WHERE[field]}\n  {env_name}: "
            value = ask(prompt).strip()
            if not value:
                continue
            if not _looks_like_key(value):
                print(f"  That doesn't look like a key (spaces or '='), so {env_name} was not changed.",
                      file=out)
                continue
            entered[env_name] = value
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled, nothing saved.", file=out)
        return 130

    print(file=out)
    if not entered:
        if path.exists() and not path.is_symlink():
            path.chmod(0o600)       # still make an existing file owner-only
        print("Nothing saved.", file=out)
    else:
        _write(path, {**current, **entered})
        noun = "key" if len(entered) == 1 else "keys"
        print(f"Saved {len(entered)} {noun} to {path} (only you can read it).", file=out)
    final = {**current, **entered}
    unset = [KEY_NAMES[f] for f, e in ENV_NAMES.items() if not final.get(e) and not env.get(e)]
    if unset:
        print(f"Not set: {', '.join(unset)}. Those sources show \"not checked (no key)\".", file=out)
    for env_name in entered:
        if env.get(env_name):
            print(f"Note: {env_name} is also set as an environment variable, and that one is used.",
                  file=out)
    print("The web page picks up new keys when you reload it.", file=out)
    return 0


def main(argv: list[str], *, out=sys.stdout, env: Mapping[str, str] = os.environ) -> int:
    parser = argparse.ArgumentParser(prog="ioc-enrich keys",
                                     description="Save your API keys to the keys file.")
    parser.add_argument("--keys", type=Path, default=DEFAULT_KEYS_FILE, help="keys file to write")
    args = parser.parse_args(argv)
    return run(args.keys, ask=getpass.getpass, out=out, env=env)
