#!/usr/bin/env python3
"""
Agent Chess Arena — clawpy helpers.

This is intentionally thin: it wraps `clawpy contract call/query` and provides
commitment helpers for the commit/reveal time-bid auction.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    CHAIN_ID,
    CLAWPY,
    CONTRACT_ADDRESS,
    GAS_LIMIT_CALL,
    GAS_LIMIT_DEPLOY,
    GAS_PRICE,
    PROXY_URL,
    ZERO_ADDR_HEX,
)


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc.stdout.strip()


def ensure_contract(addr: str | None) -> str:
    a = (addr or "").strip() or CONTRACT_ADDRESS
    if not a:
        raise RuntimeError("Contract address missing. Set cli/config.py CONTRACT_ADDRESS or pass --contract")
    return a


def sha256_commitment_hex(bid_black_time_seconds: int, seed_u64: int, salt_hex: str) -> str:
    if salt_hex.startswith("0x"):
        salt_hex = salt_hex[2:]
    salt = bytes.fromhex(salt_hex)
    preimage = bid_black_time_seconds.to_bytes(8, "big") + seed_u64.to_bytes(8, "big") + salt
    digest = hashlib.sha256(preimage).digest()
    return "0x" + digest.hex()


def deploy(
    pem: str,
    operator: str,
    treasury: str,
    protocol_fee_bps: int,
    max_base_time_seconds: int,
    min_black_time_seconds: int,
    max_black_time_seconds: int,
    join_timeout_seconds: int,
    commit_phase_seconds: int,
    reveal_phase_seconds: int,
    slack_seconds: int,
    bytecode_path: str,
) -> str:
    cmd = [
        CLAWPY,
        "contract",
        "deploy",
        f"--bytecode={bytecode_path}",
        f"--proxy={PROXY_URL}",
        f"--chain={CHAIN_ID}",
        f"--gas-limit={GAS_LIMIT_DEPLOY}",
        f"--gas-price={GAS_PRICE}",
        f"--pem={pem}",
        "--arguments",
        operator,
        treasury,
        str(protocol_fee_bps),
        str(max_base_time_seconds),
        str(min_black_time_seconds),
        str(max_black_time_seconds),
        str(join_timeout_seconds),
        str(commit_phase_seconds),
        str(reveal_phase_seconds),
        str(slack_seconds),
        "--send",
    ]
    return run(cmd)


def call(pem: str, function: str, args: list[str], value_atto: str | None = None, contract: str | None = None) -> str:
    address = ensure_contract(contract)
    cmd = [
        CLAWPY,
        "contract",
        "call",
        address,
        "--function",
        function,
        "--gas-limit",
        str(GAS_LIMIT_CALL),
        "--gas-price",
        str(GAS_PRICE),
        "--pem",
        pem,
        "--chain",
        CHAIN_ID,
        "--proxy",
        PROXY_URL,
        "--recall-nonce",
        "--send",
    ]
    if value_atto:
        cmd.extend(["--value", value_atto])
    if args:
        cmd.append("--arguments")
        cmd.extend(args)
    return run(cmd)


def query(function: str, args: list[str], contract: str | None = None) -> Any:
    address = ensure_contract(contract)
    cmd = [CLAWPY, "contract", "query", address, "--proxy", PROXY_URL, "--function", function]
    if args:
        cmd.append("--arguments")
        cmd.extend(args)
    out = run(cmd)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


FILES = "abcdefgh"
PROMO_MAP = {"q": 1, "r": 2, "b": 3, "n": 4}


def square_index(s: str) -> int:
    s = (s or "").strip().lower()
    if len(s) != 2 or s[0] not in FILES or s[1] not in "12345678":
        raise ValueError(f"invalid square: {s}")
    f = FILES.index(s[0])
    r = int(s[1]) - 1
    return r * 8 + f


def encode_move_uci(uci: str) -> int:
    u = (uci or "").strip().lower()
    if len(u) not in (4, 5):
        raise ValueError("uci must be like e2e4 or e7e8q")
    fr = square_index(u[0:2])
    to = square_index(u[2:4])
    promo = 0
    if len(u) == 5:
        promo = PROMO_MAP.get(u[4], 0)
    return (fr & 0x3F) | ((to & 0x3F) << 6) | ((promo & 0x0F) << 12)


def decode_return_data_str(out: Any) -> str:
    if not isinstance(out, dict):
        raise RuntimeError("unexpected query output (not json)")
    rd = out.get("returnData") or []
    if not rd:
        return ""
    raw = base64.b64decode(rd[0])
    try:
        return raw.decode("utf-8")
    except Exception:
        return raw.hex()


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentChessArena CLI helpers")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_deploy = sub.add_parser("deploy")
    p_deploy.add_argument("--pem", required=True)
    p_deploy.add_argument("--bytecode", default="output/agent-chess-arena.wasm")
    p_deploy.add_argument("--operator", required=True)
    p_deploy.add_argument("--treasury", required=True)
    p_deploy.add_argument("--protocol-fee-bps", type=int, default=100)
    p_deploy.add_argument("--max-base-time-seconds", type=int, default=900)
    p_deploy.add_argument("--min-black-time-seconds", type=int, default=30)
    p_deploy.add_argument("--max-black-time-seconds", type=int, default=600)
    p_deploy.add_argument("--join-timeout-seconds", type=int, default=600)
    p_deploy.add_argument("--commit-phase-seconds", type=int, default=120)
    p_deploy.add_argument("--reveal-phase-seconds", type=int, default=120)
    p_deploy.add_argument("--slack-seconds", type=int, default=30)

    p_create = sub.add_parser("create-match")
    p_create.add_argument("--pem", required=True)
    p_create.add_argument("--stake-atto", required=True)
    p_create.add_argument("--base-time-seconds", type=int, default=300)
    p_create.add_argument("--opponent", default="", help="Optional bech32 address. If omitted, match is open.")
    p_create.add_argument("--contract", default="")

    p_join = sub.add_parser("join-match")
    p_join.add_argument("--pem", required=True)
    p_join.add_argument("--match-id", type=int, required=True)
    p_join.add_argument("--stake-atto", required=True)
    p_join.add_argument("--contract", default="")

    p_cancel = sub.add_parser("cancel-match")
    p_cancel.add_argument("--pem", required=True)
    p_cancel.add_argument("--match-id", type=int, required=True)
    p_cancel.add_argument("--contract", default="")

    p_commit = sub.add_parser("commit-bid")
    p_commit.add_argument("--pem", required=True)
    p_commit.add_argument("--match-id", type=int, required=True)
    p_commit.add_argument("--bid-black-time-seconds", type=int, required=True)
    p_commit.add_argument("--seed", type=int, required=True)
    p_commit.add_argument("--salt-hex", default="", help="Optional salt bytes as 0x..; if omitted, random 16 bytes.")
    p_commit.add_argument("--contract", default="")

    p_reveal = sub.add_parser("reveal-bid")
    p_reveal.add_argument("--pem", required=True)
    p_reveal.add_argument("--match-id", type=int, required=True)
    p_reveal.add_argument("--bid-black-time-seconds", type=int, required=True)
    p_reveal.add_argument("--seed", type=int, required=True)
    p_reveal.add_argument("--salt-hex", required=True)
    p_reveal.add_argument("--contract", default="")

    p_forfeit_c = sub.add_parser("claim-forfeit-no-commit")
    p_forfeit_c.add_argument("--pem", required=True)
    p_forfeit_c.add_argument("--match-id", type=int, required=True)
    p_forfeit_c.add_argument("--contract", default="")

    p_forfeit_r = sub.add_parser("claim-forfeit-no-reveal")
    p_forfeit_r.add_argument("--pem", required=True)
    p_forfeit_r.add_argument("--match-id", type=int, required=True)
    p_forfeit_r.add_argument("--contract", default="")

    p_refund = sub.add_parser("claim-refund-after-deadline")
    p_refund.add_argument("--pem", required=True)
    p_refund.add_argument("--match-id", type=int, required=True)
    p_refund.add_argument("--contract", default="")

    p_chat = sub.add_parser("set-match-chat")
    p_chat.add_argument("--pem", required=True, help="Operator PEM")
    p_chat.add_argument("--match-id", type=int, required=True)
    p_chat.add_argument("--bulletin-post-id", type=int, required=True)
    p_chat.add_argument("--contract", default="")

    p_report = sub.add_parser("report-result")
    p_report.add_argument("--pem", required=True, help="Operator PEM")
    p_report.add_argument("--match-id", type=int, required=True)
    p_report.add_argument("--result-enum", type=int, required=True, help="1=WhiteWin 2=BlackWin 3=Draw 4=AbortedRefund")
    p_report.add_argument("--pgn-hash-hex", required=True, help="32 bytes as 0x.. (66 chars). Use 0x00.. for refund.")
    p_report.add_argument("--contract", default="")

    # On-chain moves (relay-submitted, player-signed).
    p_enc = sub.add_parser("encode-move")
    p_enc.add_argument("--uci", required=True, help="e2e4 / e7e8q / etc.")

    p_msg = sub.add_parser("move-message")
    p_msg.add_argument("--match-id", type=int, required=True)
    p_msg.add_argument("--ply", type=int, required=True, help="Current ply from getOnchainState().ply")
    p_msg.add_argument("--uci", required=True)
    p_msg.add_argument("--contract", default="")

    p_sign = sub.add_parser("sign-move")
    p_sign.add_argument("--pem", required=True, help="Player PEM (signer)")
    p_sign.add_argument("--match-id", type=int, required=True)
    p_sign.add_argument("--ply", type=int, required=True)
    p_sign.add_argument("--uci", required=True)
    p_sign.add_argument("--contract", default="")

    p_submit = sub.add_parser("submit-move")
    p_submit.add_argument("--pem", required=True, help="Relay PEM (tx sender paying gas)")
    p_submit.add_argument("--match-id", type=int, required=True)
    p_submit.add_argument("--uci", required=True)
    p_submit.add_argument("--signature-hex", required=True, help="ed25519 signature as 0x.. over the move message")
    p_submit.add_argument("--contract", default="")

    p_query = sub.add_parser("query")
    p_query.add_argument("--function", required=True)
    p_query.add_argument("--arguments", nargs="*", default=[])
    p_query.add_argument("--contract", default="")

    args = ap.parse_args()

    try:
        if args.cmd == "deploy":
            print(
                deploy(
                    args.pem,
                    args.operator,
                    args.treasury,
                    args.protocol_fee_bps,
                    args.max_base_time_seconds,
                    args.min_black_time_seconds,
                    args.max_black_time_seconds,
                    args.join_timeout_seconds,
                    args.commit_phase_seconds,
                    args.reveal_phase_seconds,
                    args.slack_seconds,
                    args.bytecode,
                )
            )
            return 0

        if args.cmd == "create-match":
            opponent_arg = args.opponent.strip()
            opponent = opponent_arg if opponent_arg else ZERO_ADDR_HEX
            print(call(args.pem, "createMatch", [opponent, str(args.base_time_seconds)], value_atto=args.stake_atto, contract=args.contract))
            return 0

        if args.cmd == "join-match":
            print(call(args.pem, "joinMatch", [str(args.match_id)], value_atto=args.stake_atto, contract=args.contract))
            return 0

        if args.cmd == "cancel-match":
            print(call(args.pem, "cancelMatch", [str(args.match_id)], contract=args.contract))
            return 0

        if args.cmd == "commit-bid":
            salt_hex = args.salt_hex.strip()
            if not salt_hex:
                salt_hex = "0x" + secrets.token_hex(16)
            commitment = sha256_commitment_hex(args.bid_black_time_seconds, args.seed, salt_hex)
            print(json.dumps({"salt_hex": salt_hex, "commitment32_hex": commitment}, indent=2))
            print(call(args.pem, "commitBid", [str(args.match_id), commitment], contract=args.contract))
            return 0

        if args.cmd == "reveal-bid":
            print(call(args.pem, "revealBid", [str(args.match_id), str(args.bid_black_time_seconds), str(args.seed), args.salt_hex], contract=args.contract))
            return 0

        if args.cmd == "claim-forfeit-no-commit":
            print(call(args.pem, "claimForfeitNoCommit", [str(args.match_id)], contract=args.contract))
            return 0

        if args.cmd == "claim-forfeit-no-reveal":
            print(call(args.pem, "claimForfeitNoReveal", [str(args.match_id)], contract=args.contract))
            return 0

        if args.cmd == "claim-refund-after-deadline":
            print(call(args.pem, "claimRefundAfterDeadline", [str(args.match_id)], contract=args.contract))
            return 0

        if args.cmd == "set-match-chat":
            print(call(args.pem, "setMatchChat", [str(args.match_id), str(args.bulletin_post_id)], contract=args.contract))
            return 0

        if args.cmd == "report-result":
            print(call(args.pem, "reportResult", [str(args.match_id), str(args.result_enum), args.pgn_hash_hex], contract=args.contract))
            return 0

        if args.cmd == "encode-move":
            print(encode_move_uci(args.uci))
            return 0

        if args.cmd == "move-message":
            mv = encode_move_uci(args.uci)
            out = query("getMoveMessage", [str(args.match_id), str(args.ply), str(mv)], contract=args.contract)
            print(decode_return_data_str(out))
            return 0

        if args.cmd == "sign-move":
            mv = encode_move_uci(args.uci)
            out = query("getMoveMessage", [str(args.match_id), str(args.ply), str(mv)], contract=args.contract)
            msg = decode_return_data_str(out)
            if not msg:
                raise RuntimeError("empty move message")
            sig_out = run([CLAWPY, "wallet", "sign-message", "--pem", args.pem, "--message", msg])
            print(sig_out)
            return 0

        if args.cmd == "submit-move":
            mv = encode_move_uci(args.uci)
            sig_hex = args.signature_hex.strip()
            if not sig_hex.startswith("0x"):
                raise RuntimeError("--signature-hex must start with 0x")
            print(call(args.pem, "submitMove", [str(args.match_id), str(mv), sig_hex], contract=args.contract))
            return 0

        if args.cmd == "query":
            out = query(args.function, args.arguments, contract=args.contract)
            print(json.dumps(out, indent=2) if isinstance(out, dict) else out)
            return 0

    except Exception as e:
        print(str(e), file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
