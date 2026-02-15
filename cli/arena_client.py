#!/usr/bin/env python3
"""
Arena HTTP client helpers.

Supports:
- auth via /auth/challenge + clawpy wallet sign-message + /auth/verify
- submit UCI moves via /match/:id/move
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from urllib.request import Request, urlopen


DEFAULT_ARENA_URL = os.getenv("ARENA_URL", "http://127.0.0.1:8787").rstrip("/")
DEFAULT_CLAWPY = os.getenv("CLAWPY_BIN", "clawpy")


def http_json(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, method=method, data=data, headers=headers)
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return (proc.stdout + "\n" + proc.stderr).strip()


def clawpy_sign_message(clawpy_bin: str, pem: str, message: str) -> str:
    out = run([clawpy_bin, "wallet", "sign-message", "--pem", pem, "--message", message])
    m = re.search(r"(0x[0-9a-fA-F]+)", out)
    if not m:
        raise RuntimeError("unable to parse signature from clawpy output")
    return m.group(1)


def main() -> int:
    ap = argparse.ArgumentParser(description="Arena HTTP client")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_auth = sub.add_parser("auth")
    p_auth.add_argument("--arena", default=DEFAULT_ARENA_URL)
    p_auth.add_argument("--address", required=True)
    p_auth.add_argument("--pem", required=True)
    p_auth.add_argument("--clawpy", default=DEFAULT_CLAWPY)

    p_move = sub.add_parser("move")
    p_move.add_argument("--arena", default=DEFAULT_ARENA_URL)
    p_move.add_argument("--token", required=True)
    p_move.add_argument("--match-id", type=int, required=True)
    p_move.add_argument("--uci", required=True)

    args = ap.parse_args()

    if args.cmd == "auth":
        ch = http_json("POST", f"{args.arena}/auth/challenge", {"address": args.address})
        if not ch.get("ok"):
            print(json.dumps(ch, indent=2))
            return 2
        msg = ch["message"]
        sig = clawpy_sign_message(args.clawpy, args.pem, msg)
        resp = http_json("POST", f"{args.arena}/auth/verify", {"address": args.address, "message": msg, "signature": sig})
        print(json.dumps(resp, indent=2))
        return 0

    if args.cmd == "move":
        resp = http_json("POST", f"{args.arena}/match/{args.match_id}/move", {"uci": args.uci}, token=args.token)
        print(json.dumps(resp, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

