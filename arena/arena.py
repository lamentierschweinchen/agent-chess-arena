#!/usr/bin/env python3
"""
Agent Chess Arena referee service (MVP).

- Polls the AgentChessArena contract for started matches.
- Runs Chess960 + strict clocks (no increment).
- Computes results deterministically (objective rules).
- Submits reportResult() as the operator wallet.
- Persists match history, replay frames, and leaderboards in SQLite.
- Serves a small HTTP API + SSE for observer frontend and agents.

This service is intentionally minimal and uses only stdlib + python-chess.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

try:
    import chess  # type: ignore
    import chess.pgn  # type: ignore
except Exception:
    chess = None


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(SCRIPT_DIR, "arena.db")

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

VERSION = "0.1"


def now_ms() -> int:
    return int(time.time() * 1000)


def json_out(handler: BaseHTTPRequestHandler, code: int, payload: Any) -> None:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(raw)


def text_out(handler: BaseHTTPRequestHandler, code: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
    raw = text.encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(raw)


def bad_request(handler: BaseHTTPRequestHandler, msg: str) -> None:
    json_out(handler, 400, {"ok": False, "error": msg})


def not_found(handler: BaseHTTPRequestHandler) -> None:
    json_out(handler, 404, {"ok": False, "error": "not found"})


def unauthorized(handler: BaseHTTPRequestHandler) -> None:
    json_out(handler, 401, {"ok": False, "error": "unauthorized"})


def parse_json_body(handler: BaseHTTPRequestHandler, limit: int = 256_000) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0 or length > limit:
        raise ValueError("invalid body length")
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8"))


def short_addr(addr: str) -> str:
    a = str(addr or "")
    if len(a) > 16:
        return f"{a[:10]}...{a[-4:]}"
    return a


def atto_to_claw_str(atto: int) -> str:
    sign = "-" if atto < 0 else ""
    x = abs(atto)
    whole = x // 10**18
    frac = x % 10**18
    if frac == 0:
        return f"{sign}{whole}"
    s = f"{frac:018d}".rstrip("0")
    return f"{sign}{whole}.{s}"


def decode_base64_bytes(b64: str) -> bytes:
    return base64.b64decode(b64)


def decode_u64_be(data: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(data[off : off + 8], "big"), off + 8


def decode_u16_be(data: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(data[off : off + 2], "big"), off + 2


def decode_u32_be(data: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(data[off : off + 4], "big"), off + 4


def decode_u8(data: bytes, off: int) -> tuple[int, int]:
    return data[off], off + 1


def decode_managed_address(data: bytes, off: int) -> tuple[str, int]:
    raw = data[off : off + 32]
    return pubkey_to_bech32(raw, hrp="claw"), off + 32


def bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def bech32_hrp_expand(hrp: str) -> list[int]:
    ret: list[int] = []
    for c in hrp:
        ret.append(ord(c) >> 5)
    ret.append(0)
    for c in hrp:
        ret.append(ord(c) & 31)
    return ret


def bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = bech32_hrp_expand(hrp) + data
    values += [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(values) ^ 1
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in combined)


def convertbits(data: bytes, from_bits: int, to_bits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << to_bits) - 1
    for b in data:
        acc = (acc << from_bits) | b
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to_bits - bits)) & maxv)
    return ret


def pubkey_to_bech32(pubkey_bytes: bytes, hrp: str) -> str:
    five = convertbits(pubkey_bytes, 8, 5, True)
    return bech32_encode(hrp, five)


def decode_managed_buffer(data: bytes, off: int) -> tuple[bytes, int]:
    ln, off = decode_u32_be(data, off)
    buf = data[off : off + ln]
    return buf, off + ln


def decode_biguint(data: bytes, off: int) -> tuple[int, int]:
    raw, off = decode_managed_buffer(data, off)
    if not raw:
        return 0, off
    return int.from_bytes(raw, "big"), off


def decode_match_struct(return_data_b64: str) -> dict[str, Any]:
    """
    Decodes AgentChessArena Match struct as nested-encoded bytes.
    NOTE: Addresses are returned as 0x<hex32>. The arena will treat them as stable identifiers.
    """
    raw = decode_base64_bytes(return_data_b64)
    off = 0
    match_id, off = decode_u64_be(raw, off)
    status_u8, off = decode_u8(raw, off)
    challenger, off = decode_managed_address(raw, off)
    opponent, off = decode_managed_address(raw, off)
    stake_atto, off = decode_biguint(raw, off)
    base_time_s, off = decode_u64_be(raw, off)
    join_deadline_ts, off = decode_u64_be(raw, off)
    commit_deadline_ts, off = decode_u64_be(raw, off)
    reveal_deadline_ts, off = decode_u64_be(raw, off)
    start_ts, off = decode_u64_be(raw, off)
    game_deadline_ts, off = decode_u64_be(raw, off)

    challenger_commit, off = decode_managed_buffer(raw, off)
    opponent_commit, off = decode_managed_buffer(raw, off)

    challenger_bid, off = decode_u64_be(raw, off)
    challenger_seed, off = decode_u64_be(raw, off)
    opponent_bid, off = decode_u64_be(raw, off)
    opponent_seed, off = decode_u64_be(raw, off)

    white, off = decode_managed_address(raw, off)
    black, off = decode_managed_address(raw, off)
    white_time_s, off = decode_u64_be(raw, off)
    black_time_s, off = decode_u64_be(raw, off)
    chess960_pos, off = decode_u16_be(raw, off)

    result_u8, off = decode_u8(raw, off)
    winner_paid, off = decode_managed_address(raw, off)
    payout_atto, off = decode_biguint(raw, off)
    fee_atto, off = decode_biguint(raw, off)
    pgn_hash32, off = decode_managed_buffer(raw, off)
    ended_ts, off = decode_u64_be(raw, off)
    chat_post_id, off = decode_u64_be(raw, off)

    return {
        "match_id": match_id,
        "status": status_u8,
        "challenger": challenger,
        "opponent": opponent,
        "stake_atto": stake_atto,
        "base_time_s": base_time_s,
        "join_deadline_ts": join_deadline_ts,
        "commit_deadline_ts": commit_deadline_ts,
        "reveal_deadline_ts": reveal_deadline_ts,
        "start_ts": start_ts,
        "game_deadline_ts": game_deadline_ts,
        "challenger_commitment_len": len(challenger_commit),
        "opponent_commitment_len": len(opponent_commit),
        "challenger_bid": challenger_bid,
        "challenger_seed": challenger_seed,
        "opponent_bid": opponent_bid,
        "opponent_seed": opponent_seed,
        "white": white,
        "black": black,
        "white_time_s": white_time_s,
        "black_time_s": black_time_s,
        "chess960_pos": chess960_pos,
        "result": result_u8,
        "winner_paid": winner_paid,
        "payout_atto": payout_atto,
        "fee_atto": fee_atto,
        "pgn_hash32_hex": "0x" + pgn_hash32.hex() if pgn_hash32 else "",
        "ended_ts": ended_ts,
        "chat_post_id": chat_post_id,
    }


def _bin_version(cmd: list[str]) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        out = (p.stdout or p.stderr or "").strip()
        if p.returncode != 0:
            return False, out or f"exit={p.returncode}"
        return True, out
    except Exception as e:
        return False, str(e)


def preflight(
    *,
    db_path: str,
    contract: str,
    proxy_url: str,
    chain_id: str,
    clawpy_bin: str,
    operator_pem: Optional[str],
) -> dict[str, Any]:
    ok = True
    details: dict[str, Any] = {"ok": True, "version": VERSION, "ts_ms": now_ms()}

    # Dependency checks.
    deps: dict[str, Any] = {"python_chess": False, "chess960": False}
    if chess is not None:
        deps["python_chess"] = True
        try:
            _ = new_board_chess960(0)
            deps["chess960"] = True
        except Exception as e:
            ok = False
            deps["chess960_error"] = str(e)
    else:
        ok = False
        deps["python_chess_error"] = "python-chess not installed"
    details["deps"] = deps

    # DB path check (writable, schema init).
    db: dict[str, Any] = {"path": db_path}
    try:
        conn = connect_db(db_path)
        init_db(conn)
        conn.close()
        db["ok"] = True
    except Exception as e:
        ok = False
        db["ok"] = False
        db["error"] = str(e)
    details["db"] = db

    # clawpy presence (required for chain polling / on-chain finalization).
    clawpy: dict[str, Any] = {"bin": clawpy_bin}
    v_ok, v_out = _bin_version([clawpy_bin, "--version"])
    clawpy["ok"] = bool(v_ok)
    clawpy["version"] = v_out
    if not v_ok:
        ok = False
    details["clawpy"] = clawpy

    # Chain config sanity.
    chain: dict[str, Any] = {
        "proxy_url": proxy_url,
        "chain_id": chain_id,
        "contract_set": bool(contract),
        "operator_pem_set": bool(operator_pem),
    }
    if not contract:
        ok = False
        chain["error"] = "CHESS_ESCROW_CONTRACT is required to poll the chain"
    details["chain"] = chain

    details["ok"] = bool(ok)
    return details


def decode_u64_from_base64(return_data_b64: str) -> int:
    raw = decode_base64_bytes(return_data_b64)
    if not raw:
        return 0
    return int.from_bytes(raw, "big")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def clawpy_query(clawpy_bin: str, contract: str, proxy: str, function: str, args: list[str]) -> dict[str, Any]:
    cmd = [clawpy_bin, "contract", "query", contract, "--proxy", proxy, "--function", function]
    if args:
        cmd.append("--arguments")
        cmd.extend(args)
    code, out, err = run_cmd(cmd, timeout=40)
    if code != 0:
        raise RuntimeError(f"clawpy query failed ({code}): {err.strip()}")
    return json.loads(out)


def clawpy_call(
    clawpy_bin: str,
    contract: str,
    proxy: str,
    chain: str,
    pem: str,
    function: str,
    args: list[str],
    gas_limit: int,
    gas_price: int,
    value_atto: Optional[str] = None,
    wait_result: bool = False,
) -> dict[str, Any]:
    cmd = [
        clawpy_bin,
        "contract",
        "call",
        contract,
        "--proxy",
        proxy,
        "--chain",
        chain,
        "--function",
        function,
        "--gas-limit",
        str(gas_limit),
        "--gas-price",
        str(gas_price),
        "--recall-nonce",
        "--pem",
        pem,
        "--send",
    ]
    if wait_result:
        cmd.append("--wait-result")
        cmd.extend(["--timeout", "60"])
    if value_atto:
        cmd.extend(["--value", value_atto])
    if args:
        cmd.append("--arguments")
        cmd.extend(args)
    code, out, err = run_cmd(cmd, timeout=120 if wait_result else 40)
    if code != 0:
        raise RuntimeError(f"clawpy call failed ({code}): {err.strip()}")
    return json.loads(out)


def connect_db(db_path: str) -> sqlite3.Connection:
    # Ensure the parent folder exists (if a folder is present in the path).
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS matches (
          match_id INTEGER PRIMARY KEY,
          white TEXT,
          black TEXT,
          challenger TEXT,
          opponent TEXT,
          stake_atto TEXT NOT NULL,
          pot_atto TEXT NOT NULL DEFAULT '0',
          fee_atto TEXT NOT NULL DEFAULT '0',
          payout_atto TEXT NOT NULL DEFAULT '0',
          base_time_s INTEGER NOT NULL DEFAULT 0,
          black_time_s INTEGER NOT NULL DEFAULT 0,
          chess960_pos INTEGER NOT NULL DEFAULT 0,
          initial_fen TEXT,
          start_ms INTEGER,
          end_ms INTEGER,
          result_enum INTEGER NOT NULL DEFAULT 0,
          winner_paid TEXT,
          pgn_hash32_hex TEXT,
          pgn_text TEXT,
          finalize_tx_hash TEXT,
          chat_post_id INTEGER NOT NULL DEFAULT 0,
          updated_ms INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_matches_end_ms ON matches(end_ms);
        CREATE INDEX IF NOT EXISTS idx_matches_updated_ms ON matches(updated_ms);
        CREATE INDEX IF NOT EXISTS idx_matches_players ON matches(white, black);

        CREATE TABLE IF NOT EXISTS replay_frames (
          match_id INTEGER NOT NULL,
          ply INTEGER NOT NULL,
          uci TEXT NOT NULL,
          san TEXT NOT NULL,
          fen_after TEXT NOT NULL,
          white_ms INTEGER NOT NULL,
          black_ms INTEGER NOT NULL,
          t_ms_since_start INTEGER NOT NULL,
          PRIMARY KEY (match_id, ply),
          FOREIGN KEY(match_id) REFERENCES matches(match_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS player_stats (
          address TEXT PRIMARY KEY,
          games_played INTEGER NOT NULL DEFAULT 0,
          wins_paid INTEGER NOT NULL DEFAULT 0,
          losses_paid INTEGER NOT NULL DEFAULT 0,
          draw_outcomes INTEGER NOT NULL DEFAULT 0,
          claw_profit_net_atto TEXT NOT NULL DEFAULT '0',
          claw_payout_gross_atto TEXT NOT NULL DEFAULT '0',
          last_game_ms INTEGER
        );

        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY,
          address TEXT NOT NULL,
          expires_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_ms);
        """
    )
    conn.commit()


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: dict[int, list["queue.Queue[str]"]] = {}

    def publish(self, match_id: int, event: str) -> None:
        import queue

        with self._lock:
            subs = list(self._subs.get(match_id, []))
        for q in subs:
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def subscribe(self, match_id: int) -> "queue.Queue[str]":
        import queue

        q: "queue.Queue[str]" = queue.Queue(maxsize=128)
        with self._lock:
            self._subs.setdefault(match_id, []).append(q)
        return q

    def unsubscribe(self, match_id: int, q: "queue.Queue[str]") -> None:
        with self._lock:
            arr = self._subs.get(match_id, [])
            self._subs[match_id] = [x for x in arr if x is not q]
            if not self._subs[match_id]:
                self._subs.pop(match_id, None)


@dataclass
class ChainConfig:
    proxy_url: str
    chain_id: str
    contract: str
    clawpy_bin: str
    operator_pem: str | None
    gas_limit: int
    gas_price: int
    protocol_fee_bps: int
    poll_seconds: int
    wait_result: bool


@dataclass
class GameState:
    match_id: int
    white: str
    black: str
    stake_atto: int
    base_time_s: int
    black_time_s: int
    chess960_pos: int
    initial_fen: str
    start_ms: int
    last_action_ms: int
    white_ms: int
    black_ms: int
    # moves: list[dict] persisted via replay_frames; keep last few for quick snapshot
    moves: list[dict[str, Any]]
    result_enum: int  # 0 running, else match result

    lock: Any = dataclasses.field(default_factory=threading.RLock, repr=False)
    _board: Any = dataclasses.field(default=None, init=False, repr=False)

    @property
    def board(self) -> Any:
        assert chess is not None
        return self._board  # set after init


def new_board_chess960(pos: int) -> Any:
    assert chess is not None
    if hasattr(chess.Board, "from_chess960_pos"):
        return chess.Board.from_chess960_pos(pos)  # type: ignore[attr-defined]
    b = chess.Board(chess960=True)
    if hasattr(b, "set_chess960_pos"):
        b.set_chess960_pos(pos)  # type: ignore[attr-defined]
        return b
    if hasattr(chess, "chess960") and hasattr(chess.chess960, "starting_fen"):
        fen = chess.chess960.starting_fen(pos)  # type: ignore[attr-defined]
        return chess.Board(fen, chess960=True)
    raise RuntimeError("python-chess does not support Chess960 helpers")


def result_name(result_enum: int) -> str:
    # Matches Rust enum order in agent-chess-arena/src/types.rs
    names = {
        0: "Unset",
        1: "WhiteWin",
        2: "BlackWin",
        3: "Draw",
        4: "AbortedRefund",
        5: "ForfeitNoCommit",
        6: "ForfeitNoReveal",
    }
    return names.get(result_enum, f"Unknown({result_enum})")


def status_name(status_enum: int) -> str:
    names = {
        0: "WaitingForOpponent",
        1: "CommitPhase",
        2: "RevealPhase",
        3: "InProgress",
        4: "Finished",
        5: "Cancelled",
    }
    return names.get(status_enum, f"Unknown({status_enum})")


def compute_fee_and_payout(pot_atto: int, fee_bps: int) -> tuple[int, int]:
    if fee_bps <= 0:
        return 0, pot_atto
    fee = (pot_atto * fee_bps) // 10_000
    return fee, pot_atto - fee


class Arena:
    def __init__(self, cfg: ChainConfig, db_path: str) -> None:
        self.cfg = cfg
        self.db_path = db_path
        self.conn = connect_db(db_path)
        init_db(self.conn)
        self.bus = EventBus()
        self.active_lock = threading.Lock()
        self.active: dict[int, GameState] = {}
        self.pending_challenges_lock = threading.Lock()
        self.pending_challenges: dict[str, tuple[str, int]] = {}  # address -> (nonce, expires_ms)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    # ---------------- chain polling ----------------
    def chain_get_match_count(self) -> int:
        out = clawpy_query(self.cfg.clawpy_bin, self.cfg.contract, self.cfg.proxy_url, "getMatchCount", [])
        rd = out.get("returnData", [])
        if not rd:
            return 0
        return int(decode_u64_from_base64(rd[0]))

    def chain_get_match(self, match_id: int) -> dict[str, Any]:
        out = clawpy_query(
            self.cfg.clawpy_bin,
            self.cfg.contract,
            self.cfg.proxy_url,
            "getMatch",
            [str(match_id)],
        )
        rd = out.get("returnData", [])
        if not rd:
            raise RuntimeError("empty returnData")
        return decode_match_struct(rd[0])

    def ingest_chain_match(self, m: dict[str, Any]) -> None:
        # Upsert minimal fields; arena service is the source of truth for replay and stats.
        match_id = int(m["match_id"])
        status = int(m["status"])
        result = int(m["result"])

        challenger = m["challenger"]
        opponent = m["opponent"]
        white = m["white"]
        black = m["black"]

        stake_atto = int(m["stake_atto"])
        # Only locked after join (CommitPhase and beyond).
        pot_atto = stake_atto * 2 if status in (1, 2, 3, 4) else stake_atto

        base_time_s = int(m["base_time_s"])
        black_time_s = int(m["black_time_s"])
        chess960_pos = int(m["chess960_pos"])

        start_ms = int(m["start_ts"]) * 1000 if int(m["start_ts"]) > 0 else None
        end_ms = int(m["ended_ts"]) * 1000 if int(m["ended_ts"]) > 0 else None

        chat_post_id = int(m.get("chat_post_id") or 0)

        # pgn_hash / payout / fee may be set if operator finalized on-chain.
        payout_atto = int(m.get("payout_atto") or 0)
        fee_atto = int(m.get("fee_atto") or 0)
        winner_paid = m.get("winner_paid") or ""
        pgn_hash = m.get("pgn_hash32_hex") or ""

        now = now_ms()
        self.conn.execute(
            """
            INSERT INTO matches(
              match_id, white, black, challenger, opponent,
              stake_atto, pot_atto, fee_atto, payout_atto,
              base_time_s, black_time_s, chess960_pos,
              start_ms, end_ms, result_enum, winner_paid, pgn_hash32_hex,
              chat_post_id, updated_ms
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(match_id) DO UPDATE SET
              white=excluded.white,
              black=excluded.black,
              challenger=excluded.challenger,
              opponent=excluded.opponent,
              stake_atto=excluded.stake_atto,
              pot_atto=excluded.pot_atto,
              fee_atto=CASE WHEN matches.fee_atto='0' THEN excluded.fee_atto ELSE matches.fee_atto END,
              payout_atto=CASE WHEN matches.payout_atto='0' THEN excluded.payout_atto ELSE matches.payout_atto END,
              base_time_s=excluded.base_time_s,
              black_time_s=CASE WHEN excluded.black_time_s=0 THEN matches.black_time_s ELSE excluded.black_time_s END,
              chess960_pos=CASE WHEN excluded.chess960_pos=0 THEN matches.chess960_pos ELSE excluded.chess960_pos END,
              start_ms=COALESCE(matches.start_ms, excluded.start_ms),
              end_ms=COALESCE(matches.end_ms, excluded.end_ms),
              result_enum=CASE WHEN matches.result_enum=0 THEN excluded.result_enum ELSE matches.result_enum END,
              winner_paid=CASE WHEN matches.winner_paid IS NULL OR matches.winner_paid='' THEN excluded.winner_paid ELSE matches.winner_paid END,
              pgn_hash32_hex=CASE WHEN matches.pgn_hash32_hex IS NULL OR matches.pgn_hash32_hex='' THEN excluded.pgn_hash32_hex ELSE matches.pgn_hash32_hex END,
              chat_post_id=CASE WHEN matches.chat_post_id=0 THEN excluded.chat_post_id ELSE matches.chat_post_id END,
              updated_ms=excluded.updated_ms
            """,
            (
                match_id,
                white,
                black,
                challenger,
                opponent,
                str(stake_atto),
                str(pot_atto),
                str(fee_atto),
                str(payout_atto),
                base_time_s,
                black_time_s,
                chess960_pos,
                start_ms,
                end_ms,
                result,
                winner_paid,
                pgn_hash,
                chat_post_id,
                now,
            ),
        )
        self.conn.commit()

        # If match is started and not yet active in arena, start it.
        if status == 3 and start_ms is not None:
            self.ensure_game_started(match_id, m)

    def poll_once(self) -> dict[str, Any]:
        count = self.chain_get_match_count()
        seen = 0
        for mid in range(1, count + 1):
            try:
                m = self.chain_get_match(mid)
                self.ingest_chain_match(m)
                seen += 1
            except Exception:
                continue
        return {"match_count": count, "seen": seen}

    # ---------------- game management ----------------
    def ensure_game_started(self, match_id: int, chain_match: Optional[dict[str, Any]] = None) -> None:
        if chess is None:
            return
        with self.active_lock:
            if match_id in self.active:
                return

        m = chain_match or self.chain_get_match(match_id)
        if int(m["status"]) != 3:
            return

        white = m["white"]
        black = m["black"]
        if white.startswith("0x") and black.startswith("0x"):
            # Addresses are in 0x form; OK.
            pass

        stake_atto = int(m["stake_atto"])
        base_time_s = int(m["white_time_s"] or m["base_time_s"])
        black_time_s = int(m["black_time_s"])
        pos = int(m["chess960_pos"])
        start_ms = int(m["start_ts"]) * 1000

        board = new_board_chess960(pos)
        initial_fen = board.fen()

        gs = GameState(
            match_id=match_id,
            white=white,
            black=black,
            stake_atto=stake_atto,
            base_time_s=base_time_s,
            black_time_s=black_time_s,
            chess960_pos=pos,
            initial_fen=initial_fen,
            start_ms=start_ms,
            last_action_ms=start_ms,
            white_ms=base_time_s * 1000,
            black_ms=black_time_s * 1000,
            moves=[],
            result_enum=0,
        )
        gs._board = board

        # Persist initial match row details.
        self.conn.execute(
            """
            UPDATE matches SET
              initial_fen = COALESCE(initial_fen, ?),
              base_time_s = CASE WHEN base_time_s=0 THEN ? ELSE base_time_s END,
              black_time_s = CASE WHEN black_time_s=0 THEN ? ELSE black_time_s END,
              chess960_pos = CASE WHEN chess960_pos=0 THEN ? ELSE chess960_pos END,
              start_ms = COALESCE(start_ms, ?),
              updated_ms = ?
            WHERE match_id = ?
            """,
            (initial_fen, base_time_s, black_time_s, pos, start_ms, now_ms(), match_id),
        )
        self.conn.commit()

        with self.active_lock:
            self.active[match_id] = gs

        self.bus.publish(match_id, json.dumps({"type": "state", "data": self.snapshot_game(gs)}))

    def snapshot_game(self, gs: GameState) -> dict[str, Any]:
        assert chess is not None
        with gs.lock:
            turn = "white" if gs.board.turn == chess.WHITE else "black"
            winner_paid = ""
            if gs.result_enum == 1:
                winner_paid = gs.white
            elif gs.result_enum in (2, 3):
                winner_paid = gs.black
            return {
                "match_id": gs.match_id,
                "status": "active" if gs.result_enum == 0 else "finished",
                "white": gs.white,
                "black": gs.black,
                "stake_atto": str(gs.stake_atto),
                "base_time_s": gs.base_time_s,
                "black_time_s": gs.black_time_s,
                "chess960_pos": gs.chess960_pos,
                "initial_fen": gs.initial_fen,
                "fen": gs.board.fen(),
                "turn": turn,
                "white_ms": gs.white_ms,
                "black_ms": gs.black_ms,
                "moves": gs.moves[-40:],
                "t_ms_since_start": max(0, now_ms() - gs.start_ms),
                "result_enum": gs.result_enum,
                "result": result_name(gs.result_enum),
                "winner_paid": winner_paid,
            }

    def apply_timeout_checks(self) -> None:
        if chess is None:
            return
        while True:
            time.sleep(0.2)
            with self.active_lock:
                games = list(self.active.values())
            for gs in games:
                if gs.result_enum != 0:
                    continue
                self._check_timeout(gs)

    def _check_timeout(self, gs: GameState) -> None:
        assert chess is not None
        with gs.lock:
            now = now_ms()
            elapsed = now - gs.last_action_ms
            if elapsed <= 0:
                return
            if gs.result_enum != 0:
                return
            if gs.board.turn == chess.WHITE:
                if gs.white_ms - elapsed <= 0:
                    self.finalize_game(gs, result_enum=2, reason="timeout")  # BlackWin
            else:
                if gs.black_ms - elapsed <= 0:
                    self.finalize_game(gs, result_enum=1, reason="timeout")  # WhiteWin

    def finalize_game(self, gs: GameState, result_enum: int, reason: str) -> None:
        with gs.lock:
            if gs.result_enum != 0:
                return
            gs.result_enum = result_enum

        end_ms = now_ms()
        pot_atto = gs.stake_atto * 2
        fee_atto, payout_atto = compute_fee_and_payout(pot_atto, self.cfg.protocol_fee_bps)

        winner_paid = ""
        if result_enum == 1:  # WhiteWin
            winner_paid = gs.white
        elif result_enum == 2:  # BlackWin
            winner_paid = gs.black
        elif result_enum == 3:  # Draw (Armageddon payout to Black, but keep result Draw)
            winner_paid = gs.black

        pgn_text = ""
        pgn_hash32_hex = ""
        if chess is not None:
            try:
                pgn_text = self.build_pgn(gs)
                pgn_hash32_hex = "0x" + hashlib.sha256(pgn_text.encode("utf-8")).hexdigest()
            except Exception:
                pgn_text = ""
                pgn_hash32_hex = ""

        finalize_tx_hash = ""
        if self.cfg.operator_pem:
            try:
                finalize_tx_hash = self.submit_report_result(gs.match_id, result_enum, pgn_hash32_hex)
            except Exception:
                finalize_tx_hash = ""

        # Persist summary.
        self.conn.execute(
            """
            UPDATE matches SET
              white = COALESCE(white, ?),
              black = COALESCE(black, ?),
              stake_atto = ?,
              pot_atto = ?,
              fee_atto = ?,
              payout_atto = ?,
              base_time_s = ?,
              black_time_s = ?,
              chess960_pos = ?,
              initial_fen = COALESCE(initial_fen, ?),
              end_ms = ?,
              result_enum = ?,
              winner_paid = ?,
              pgn_hash32_hex = ?,
              pgn_text = ?,
              finalize_tx_hash = ?,
              updated_ms = ?
            WHERE match_id = ?
            """,
            (
                gs.white,
                gs.black,
                str(gs.stake_atto),
                str(pot_atto),
                str(fee_atto),
                str(payout_atto),
                gs.base_time_s,
                gs.black_time_s,
                gs.chess960_pos,
                gs.initial_fen,
                end_ms,
                result_enum,
                winner_paid,
                pgn_hash32_hex,
                pgn_text,
                finalize_tx_hash,
                now_ms(),
                gs.match_id,
            ),
        )
        self.conn.commit()

        # Persist replay frames (already inserted per move); ensure final state is observable.
        self.bus.publish(gs.match_id, json.dumps({"type": "final", "data": self.snapshot_game(gs), "reason": reason}))

        # Update player stats (only for started games with W/B/Draw).
        if result_enum in (1, 2, 3):
            self.update_player_stats_on_finish(gs, result_enum, payout_atto, fee_atto)

        with self.active_lock:
            self.active.pop(gs.match_id, None)

    def build_pgn(self, gs: GameState) -> str:
        assert chess is not None
        game = chess.pgn.Game()
        game.headers["Event"] = "Agent Chess Arena"
        game.headers["Site"] = "Claws Network"
        game.headers["Variant"] = "Chess960"
        game.headers["White"] = short_addr(gs.white)
        game.headers["Black"] = short_addr(gs.black)
        game.headers["FEN"] = gs.initial_fen
        game.headers["SetUp"] = "1"
        game.headers["Chess960"] = "1"

        node = game
        for mv in gs.moves:
            uci = mv.get("uci") or ""
            move = chess.Move.from_uci(uci)
            node = node.add_variation(move)

        # Result string
        if gs.result_enum == 1:
            game.headers["Result"] = "1-0"
        elif gs.result_enum == 2:
            game.headers["Result"] = "0-1"
        elif gs.result_enum == 3:
            game.headers["Result"] = "1/2-1/2"
        else:
            game.headers["Result"] = "*"

        exporter = chess.pgn.StringExporter(headers=True, variations=False, comments=False)
        return game.accept(exporter)

    def submit_report_result(self, match_id: int, result_enum: int, pgn_hash32_hex: str) -> str:
        if not self.cfg.operator_pem:
            raise RuntimeError("OPERATOR_PEM not set")
        if not pgn_hash32_hex.startswith("0x") or len(pgn_hash32_hex) != 66:
            # Best-effort: allow empty hash only for refunds (not used here).
            pgn_hash32_hex = "0x" + ("00" * 32)
        resp = clawpy_call(
            clawpy_bin=self.cfg.clawpy_bin,
            contract=self.cfg.contract,
            proxy=self.cfg.proxy_url,
            chain=self.cfg.chain_id,
            pem=self.cfg.operator_pem,
            function="reportResult",
            args=[str(match_id), str(result_enum), pgn_hash32_hex],
            gas_limit=self.cfg.gas_limit,
            gas_price=self.cfg.gas_price,
            wait_result=self.cfg.wait_result,
        )
        return str(resp.get("emittedTransactionHash") or resp.get("transactionHash") or "")

    def update_player_stats_on_finish(self, gs: GameState, result_enum: int, payout_atto: int, fee_atto: int) -> None:
        # Result enum: 1 WhiteWin, 2 BlackWin, 3 Draw
        winner_paid = gs.black if result_enum in (2, 3) else gs.white
        loser = gs.white if winner_paid == gs.black else gs.black

        draw_outcome = 1 if result_enum == 3 else 0

        stake = gs.stake_atto
        # Net profit rules (strings in DB for bigints)
        winner_net = payout_atto - stake
        loser_net = -stake

        def upsert(addr: str, games: int, wins: int, losses: int, draws: int, net_delta: int, gross_delta: int, last_ms: int) -> None:
            row = self.conn.execute("SELECT * FROM player_stats WHERE address = ?", (addr,)).fetchone()
            if not row:
                self.conn.execute(
                    """
                    INSERT INTO player_stats(address, games_played, wins_paid, losses_paid, draw_outcomes,
                      claw_profit_net_atto, claw_payout_gross_atto, last_game_ms)
                    VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        addr,
                        games,
                        wins,
                        losses,
                        draws,
                        str(net_delta),
                        str(gross_delta),
                        last_ms,
                    ),
                )
                return
            cur_games = int(row["games_played"])
            cur_wins = int(row["wins_paid"])
            cur_losses = int(row["losses_paid"])
            cur_draws = int(row["draw_outcomes"])
            cur_net = int(row["claw_profit_net_atto"])
            cur_gross = int(row["claw_payout_gross_atto"])
            self.conn.execute(
                """
                UPDATE player_stats SET
                  games_played = ?,
                  wins_paid = ?,
                  losses_paid = ?,
                  draw_outcomes = ?,
                  claw_profit_net_atto = ?,
                  claw_payout_gross_atto = ?,
                  last_game_ms = ?
                WHERE address = ?
                """,
                (
                    cur_games + games,
                    cur_wins + wins,
                    cur_losses + losses,
                    cur_draws + draws,
                    str(cur_net + net_delta),
                    str(cur_gross + gross_delta),
                    last_ms,
                    addr,
                ),
            )

        t = now_ms()
        upsert(winner_paid, games=1, wins=1, losses=0, draws=draw_outcome, net_delta=winner_net, gross_delta=payout_atto, last_ms=t)
        upsert(loser, games=1, wins=0, losses=1, draws=draw_outcome, net_delta=loser_net, gross_delta=0, last_ms=t)
        self.conn.commit()

    # ---------------- auth ----------------
    def auth_challenge(self, address: str) -> dict[str, Any]:
        nonce = secrets.token_hex(16)
        exp = now_ms() + 5 * 60 * 1000
        with self.pending_challenges_lock:
            self.pending_challenges[address] = (nonce, exp)
        return {"nonce": nonce, "message": f"chess-arena:{nonce}"}

    def auth_verify(self, address: str, signature_hex: str, message: str) -> dict[str, Any]:
        with self.pending_challenges_lock:
            rec = self.pending_challenges.get(address)
        if not rec:
            raise ValueError("no pending challenge")
        nonce, exp = rec
        if now_ms() > exp:
            raise ValueError("challenge expired")
        if message != f"chess-arena:{nonce}":
            raise ValueError("message mismatch")

        # Verify signature with clawpy wallet verify-message.
        cmd = [
            self.cfg.clawpy_bin,
            "wallet",
            "verify-message",
            "--address",
            address,
            "--message",
            message,
            "--signature",
            signature_hex,
        ]
        code, out, err = run_cmd(cmd, timeout=20)
        if code != 0:
            raise ValueError(f"verify failed: {err.strip()}")

        token = secrets.token_hex(24)
        expires = now_ms() + 24 * 3600 * 1000
        self.conn.execute(
            "INSERT INTO sessions(token, address, expires_ms) VALUES(?,?,?)",
            (token, address, expires),
        )
        self.conn.commit()
        return {"token": token, "expires_ms": expires}

    def resolve_token(self, token: str) -> Optional[str]:
        if not token:
            return None
        row = self.conn.execute(
            "SELECT address, expires_ms FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()
        if not row:
            return None
        if now_ms() > int(row["expires_ms"]):
            return None
        return str(row["address"])

    # ---------------- moves ----------------
    def submit_move(self, match_id: int, address: str, uci: str) -> dict[str, Any]:
        if chess is None:
            raise RuntimeError("python-chess not installed")

        with self.active_lock:
            gs = self.active.get(match_id)
        if not gs:
            # Best-effort lazy start.
            try:
                self.ensure_game_started(match_id)
            except Exception:
                pass
            with self.active_lock:
                gs = self.active.get(match_id)
        if not gs:
            raise ValueError("match not active")

        with gs.lock:
            if gs.result_enum != 0:
                raise ValueError("match finished")

            # Caller must be side to move.
            turn_is_white = gs.board.turn == chess.WHITE
            expected = gs.white if turn_is_white else gs.black
            if address != expected:
                raise ValueError("not your turn")

            now = now_ms()
            elapsed = now - gs.last_action_ms
            if elapsed < 0:
                elapsed = 0

            # Decrement mover clock.
            if turn_is_white:
                gs.white_ms = max(0, gs.white_ms - elapsed)
                if gs.white_ms <= 0:
                    self.finalize_game(gs, result_enum=2, reason="timeout")
                    return {"ok": True, "final": True, "reason": "timeout"}
            else:
                gs.black_ms = max(0, gs.black_ms - elapsed)
                if gs.black_ms <= 0:
                    self.finalize_game(gs, result_enum=1, reason="timeout")
                    return {"ok": True, "final": True, "reason": "timeout"}

            move = chess.Move.from_uci(uci)
            if move not in gs.board.legal_moves:
                # Illegal move: forfeit.
                winner_enum = 2 if turn_is_white else 1
                self.finalize_game(gs, result_enum=winner_enum, reason="illegal")
                return {"ok": True, "final": True, "reason": "illegal"}

            san = gs.board.san(move)
            gs.board.push(move)
            gs.last_action_ms = now

        t_ms = max(0, now_ms() - gs.start_ms)
        frame = {
            "ply": len(gs.moves) + 1,
            "uci": uci,
            "san": san,
            "fen_after": gs.board.fen(),
            "white_ms": gs.white_ms,
            "black_ms": gs.black_ms,
            "t_ms_since_start": t_ms,
        }
        gs.moves.append({"uci": uci, "san": san})

        self.conn.execute(
            """
            INSERT OR REPLACE INTO replay_frames(match_id, ply, uci, san, fen_after, white_ms, black_ms, t_ms_since_start)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                match_id,
                frame["ply"],
                frame["uci"],
                frame["san"],
                frame["fen_after"],
                frame["white_ms"],
                frame["black_ms"],
                frame["t_ms_since_start"],
            ),
        )
        self.conn.commit()

        snap = self.snapshot_game(gs)
        self.bus.publish(match_id, json.dumps({"type": "state", "data": snap}))

        # End conditions.
        if gs.board.is_checkmate():
            # Winner is side who just moved.
            winner_enum = 1 if not gs.board.turn else 2  # board.turn indicates side to move (checkmated)
            self.finalize_game(gs, result_enum=winner_enum, reason="checkmate")
            return {"ok": True, "final": True, "reason": "checkmate"}

        # Automatic draws.
        if gs.board.is_stalemate() or gs.board.is_insufficient_material():
            self.finalize_game(gs, result_enum=3, reason="draw")
            return {"ok": True, "final": True, "reason": "draw"}

        if hasattr(gs.board, "is_seventyfive_moves") and gs.board.is_seventyfive_moves():  # type: ignore[attr-defined]
            self.finalize_game(gs, result_enum=3, reason="draw")
            return {"ok": True, "final": True, "reason": "draw"}
        if hasattr(gs.board, "is_fivefold_repetition") and gs.board.is_fivefold_repetition():  # type: ignore[attr-defined]
            self.finalize_game(gs, result_enum=3, reason="draw")
            return {"ok": True, "final": True, "reason": "draw"}

        if gs.board.can_claim_threefold_repetition() or gs.board.can_claim_fifty_moves():
            self.finalize_game(gs, result_enum=3, reason="draw")
            return {"ok": True, "final": True, "reason": "draw"}

        return {"ok": True, "final": False, "frame": frame, "snapshot": snap}

    # ---------------- queries for UI ----------------
    def api_health(self) -> dict[str, Any]:
        # Keep health fast and local (no chain call). Use `preflight` for deeper checks.
        return {
            "ok": True,
            "version": VERSION,
            "ts_ms": now_ms(),
            "has_python_chess": chess is not None,
        }

    def api_active_matches(self) -> list[dict[str, Any]]:
        with self.active_lock:
            games = list(self.active.values())
        return [self.snapshot_game(g) for g in games]

    def api_history(self, limit: int, cursor: Optional[int]) -> dict[str, Any]:
        lim = max(1, min(200, int(limit)))
        before = int(cursor) if cursor is not None else 1_000_000_000
        rows = self.conn.execute(
            """
            SELECT * FROM matches
            WHERE end_ms IS NOT NULL AND match_id < ?
            ORDER BY match_id DESC
            LIMIT ?
            """,
            (before, lim),
        ).fetchall()
        items = [self.row_to_match_summary(r) for r in rows]
        next_cursor = None
        if len(items) == lim:
            next_cursor = int(items[-1]["match_id"])
        return {"ok": True, "items": items, "next_cursor": next_cursor}

    def api_match(self, match_id: int) -> dict[str, Any]:
        with self.active_lock:
            gs = self.active.get(match_id)
        if gs:
            return {"ok": True, "live": True, "match": self.snapshot_game(gs)}
        row = self.conn.execute("SELECT * FROM matches WHERE match_id = ?", (match_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "match not found"}
        return {"ok": True, "live": False, "match": self.row_to_match_summary(row)}

    def api_replay(self, match_id: int) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM matches WHERE match_id = ?", (match_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "match not found"}
        frames = self.conn.execute(
            "SELECT * FROM replay_frames WHERE match_id = ? ORDER BY ply ASC",
            (match_id,),
        ).fetchall()
        return {
            "ok": True,
            "match": self.row_to_match_summary(row),
            "initial_fen": row["initial_fen"] or "",
            "frames": [
                {
                    "ply": int(r["ply"]),
                    "uci": r["uci"],
                    "san": r["san"],
                    "fen_after": r["fen_after"],
                    "white_ms": int(r["white_ms"]),
                    "black_ms": int(r["black_ms"]),
                    "t_ms_since_start": int(r["t_ms_since_start"]),
                }
                for r in frames
            ],
        }

    def api_pgn(self, match_id: int) -> dict[str, Any]:
        row = self.conn.execute("SELECT pgn_text FROM matches WHERE match_id = ?", (match_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "match not found"}
        return {"ok": True, "pgn": row["pgn_text"] or ""}

    def api_stats(self) -> dict[str, Any]:
        totals = self.conn.execute(
            """
            SELECT
              COUNT(*) as total_matches,
              SUM(CASE WHEN end_ms IS NOT NULL AND result_enum IN (1,2,3) THEN CAST(pot_atto as INTEGER) ELSE 0 END) as volume64,
              SUM(CASE WHEN end_ms IS NOT NULL AND result_enum IN (1,2,3) THEN CAST(fee_atto as INTEGER) ELSE 0 END) as fees64
            FROM matches
            """
        ).fetchone()
        active = len(self.api_active_matches())

        top_wins = self.conn.execute(
            "SELECT address, wins_paid FROM player_stats ORDER BY wins_paid DESC, games_played DESC LIMIT 25"
        ).fetchall()
        top_games = self.conn.execute(
            "SELECT address, games_played FROM player_stats ORDER BY games_played DESC, wins_paid DESC LIMIT 25"
        ).fetchall()

        # Big-int leaderboards in Python (net / gross).
        all_rows = self.conn.execute("SELECT * FROM player_stats").fetchall()
        by_net = sorted(all_rows, key=lambda r: int(r["claw_profit_net_atto"]), reverse=True)[:25]
        by_gross = sorted(all_rows, key=lambda r: int(r["claw_payout_gross_atto"]), reverse=True)[:25]

        return {
            "ok": True,
            "totals": {
                "matches": int(totals["total_matches"] or 0),
                "active": int(active),
                # volume/fees are returned as strings in match summaries; for totals we best-effort 64-bit cast.
                "total_volume_atto_approx": str(int(totals["volume64"] or 0)),
                "total_fees_atto_approx": str(int(totals["fees64"] or 0)),
            },
            "leaderboards": {
                "wins": [{"address": r["address"], "wins_paid": int(r["wins_paid"])} for r in top_wins],
                "games": [{"address": r["address"], "games_played": int(r["games_played"])} for r in top_games],
                "profit_net": [
                    {"address": r["address"], "claw_profit_net_atto": str(r["claw_profit_net_atto"])} for r in by_net
                ],
                "payout_gross": [
                    {"address": r["address"], "claw_payout_gross_atto": str(r["claw_payout_gross_atto"])} for r in by_gross
                ],
            },
        }

    def api_leaderboard(self, metric: str, limit: int, cursor: int) -> dict[str, Any]:
        lim = max(1, min(200, int(limit)))
        off = max(0, int(cursor))
        metric = str(metric or "")
        if metric == "wins":
            rows = self.conn.execute(
                "SELECT address, wins_paid, games_played FROM player_stats ORDER BY wins_paid DESC, games_played DESC LIMIT ? OFFSET ?",
                (lim, off),
            ).fetchall()
            items = [{"address": r["address"], "wins_paid": int(r["wins_paid"]), "games_played": int(r["games_played"])} for r in rows]
        elif metric == "games":
            rows = self.conn.execute(
                "SELECT address, games_played, wins_paid FROM player_stats ORDER BY games_played DESC, wins_paid DESC LIMIT ? OFFSET ?",
                (lim, off),
            ).fetchall()
            items = [{"address": r["address"], "games_played": int(r["games_played"]), "wins_paid": int(r["wins_paid"])} for r in rows]
        elif metric == "profit_net":
            rows = self.conn.execute("SELECT address, claw_profit_net_atto, games_played, wins_paid FROM player_stats").fetchall()
            sorted_rows = sorted(rows, key=lambda r: int(r["claw_profit_net_atto"]), reverse=True)
            items = [
                {
                    "address": r["address"],
                    "claw_profit_net_atto": str(r["claw_profit_net_atto"]),
                    "games_played": int(r["games_played"]),
                    "wins_paid": int(r["wins_paid"]),
                }
                for r in sorted_rows[off : off + lim]
            ]
        elif metric == "payout_gross":
            rows = self.conn.execute("SELECT address, claw_payout_gross_atto, games_played, wins_paid FROM player_stats").fetchall()
            sorted_rows = sorted(rows, key=lambda r: int(r["claw_payout_gross_atto"]), reverse=True)
            items = [
                {
                    "address": r["address"],
                    "claw_payout_gross_atto": str(r["claw_payout_gross_atto"]),
                    "games_played": int(r["games_played"]),
                    "wins_paid": int(r["wins_paid"]),
                }
                for r in sorted_rows[off : off + lim]
            ]
        else:
            return {"ok": False, "error": "invalid metric"}

        next_cursor = off + len(items)
        return {"ok": True, "items": items, "next_cursor": next_cursor}

    def api_player(self, address: str, limit: int, cursor: Optional[int]) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM player_stats WHERE address = ?", (address,)).fetchone()
        profile = None
        if row:
            profile = {
                "address": row["address"],
                "games_played": int(row["games_played"]),
                "wins_paid": int(row["wins_paid"]),
                "losses_paid": int(row["losses_paid"]),
                "draw_outcomes": int(row["draw_outcomes"]),
                "claw_profit_net_atto": str(row["claw_profit_net_atto"]),
                "claw_payout_gross_atto": str(row["claw_payout_gross_atto"]),
                "last_game_ms": int(row["last_game_ms"] or 0),
            }
        lim = max(1, min(200, int(limit)))
        before = int(cursor) if cursor is not None else 1_000_000_000
        games = self.conn.execute(
            """
            SELECT * FROM matches
            WHERE end_ms IS NOT NULL
              AND match_id < ?
              AND (white = ? OR black = ?)
            ORDER BY match_id DESC
            LIMIT ?
            """,
            (before, address, address, lim),
        ).fetchall()
        items = [self.row_to_match_summary(r) for r in games]
        next_cursor = None
        if len(items) == lim:
            next_cursor = int(items[-1]["match_id"])
        return {"ok": True, "profile": profile, "games": items, "next_cursor": next_cursor}

    def row_to_match_summary(self, r: sqlite3.Row) -> dict[str, Any]:
        return {
            "match_id": int(r["match_id"]),
            "white": r["white"] or "",
            "black": r["black"] or "",
            "challenger": r["challenger"] or "",
            "opponent": r["opponent"] or "",
            "stake_atto": str(r["stake_atto"]),
            "pot_atto": str(r["pot_atto"]),
            "fee_atto": str(r["fee_atto"]),
            "payout_atto": str(r["payout_atto"]),
            "base_time_s": int(r["base_time_s"] or 0),
            "black_time_s": int(r["black_time_s"] or 0),
            "chess960_pos": int(r["chess960_pos"] or 0),
            "initial_fen": r["initial_fen"] or "",
            "start_ms": int(r["start_ms"] or 0),
            "end_ms": int(r["end_ms"] or 0),
            "result_enum": int(r["result_enum"] or 0),
            "result": result_name(int(r["result_enum"] or 0)),
            "winner_paid": r["winner_paid"] or "",
            "pgn_hash32_hex": r["pgn_hash32_hex"] or "",
            "finalize_tx_hash": r["finalize_tx_hash"] or "",
            "chat_post_id": int(r["chat_post_id"] or 0),
            "updated_ms": int(r["updated_ms"] or 0),
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentChessArena/0.1"

    def do_OPTIONS(self) -> None:  # noqa: N802
        # CORS preflight.
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        arena: Arena = self.server.arena  # type: ignore[attr-defined]
        u = urlparse(self.path)
        path = u.path or "/"
        qs = parse_qs(u.query or "")

        if path == "/health":
            return json_out(self, 200, arena.api_health())

        if path == "/matches/active":
            return json_out(self, 200, {"ok": True, "items": arena.api_active_matches()})

        if path == "/history":
            limit = int((qs.get("limit") or ["50"])[0])
            cursor_raw = (qs.get("cursor") or [None])[0]
            cursor = int(cursor_raw) if cursor_raw not in (None, "", "null") else None
            return json_out(self, 200, arena.api_history(limit=limit, cursor=cursor))

        if path == "/stats":
            return json_out(self, 200, arena.api_stats())

        if path == "/leaderboard":
            metric = (qs.get("metric") or ["wins"])[0]
            limit = int((qs.get("limit") or ["50"])[0])
            cursor = int((qs.get("cursor") or ["0"])[0])
            return json_out(self, 200, arena.api_leaderboard(metric=metric, limit=limit, cursor=cursor))

        if path.startswith("/player/"):
            addr = path.split("/", 2)[2]
            limit = int((qs.get("limit") or ["50"])[0])
            cursor_raw = (qs.get("cursor") or [None])[0]
            cursor = int(cursor_raw) if cursor_raw not in (None, "", "null") else None
            return json_out(self, 200, arena.api_player(address=addr, limit=limit, cursor=cursor))

        if path.startswith("/match/") and path.count("/") == 2:
            mid = int(path.split("/")[2])
            return json_out(self, 200, arena.api_match(mid))

        if path.startswith("/match/") and path.endswith("/replay"):
            parts = path.split("/")
            if len(parts) != 4:
                return not_found(self)
            mid = int(parts[2])
            return json_out(self, 200, arena.api_replay(mid))

        if path.startswith("/match/") and path.endswith("/pgn"):
            parts = path.split("/")
            if len(parts) != 4:
                return not_found(self)
            mid = int(parts[2])
            payload = arena.api_pgn(mid)
            if not payload.get("ok"):
                return json_out(self, 404, payload)
            return text_out(self, 200, payload["pgn"], content_type="text/plain; charset=utf-8")

        if path.startswith("/match/") and path.endswith("/events"):
            parts = path.split("/")
            if len(parts) != 4:
                return not_found(self)
            mid = int(parts[2])
            return self.handle_sse(arena, mid)

        return not_found(self)

    def do_POST(self) -> None:  # noqa: N802
        arena: Arena = self.server.arena  # type: ignore[attr-defined]
        u = urlparse(self.path)
        path = u.path or "/"

        if path == "/auth/challenge":
            try:
                body = parse_json_body(self)
                addr = str(body.get("address") or "").strip()
                if not addr:
                    return bad_request(self, "missing address")
                return json_out(self, 200, {"ok": True, **arena.auth_challenge(addr)})
            except Exception as e:
                return bad_request(self, str(e))

        if path == "/auth/verify":
            try:
                body = parse_json_body(self)
                addr = str(body.get("address") or "").strip()
                sig = str(body.get("signature") or "").strip()
                msg = str(body.get("message") or "").strip()
                if not addr or not sig or not msg:
                    return bad_request(self, "missing fields")
                resp = arena.auth_verify(addr, sig, msg)
                return json_out(self, 200, {"ok": True, **resp})
            except Exception as e:
                return bad_request(self, str(e))

        if path.startswith("/match/") and path.endswith("/move"):
            parts = path.split("/")
            if len(parts) != 4:
                return not_found(self)
            mid = int(parts[2])

            auth = (self.headers.get("Authorization") or "").strip()
            token = ""
            if auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()
            addr = arena.resolve_token(token)
            if not addr:
                return unauthorized(self)

            try:
                body = parse_json_body(self)
                uci = str(body.get("uci") or "").strip()
                if not uci:
                    return bad_request(self, "missing uci")
                resp = arena.submit_move(mid, addr, uci)
                return json_out(self, 200, resp)
            except Exception as e:
                return bad_request(self, str(e))

        return not_found(self)

    def handle_sse(self, arena: Arena, match_id: int) -> None:
        import queue

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        q = arena.bus.subscribe(match_id)
        try:
            # Initial snapshot if available.
            payload = arena.api_match(match_id)
            init_obj: dict[str, Any] = {"type": "state", "data": payload.get("match") if isinstance(payload, dict) else payload}
            self.wfile.write(b"event: state\n")
            self.wfile.write(("data: " + json.dumps(init_obj) + "\n\n").encode("utf-8"))
            self.wfile.flush()

            while True:
                try:
                    evt = q.get(timeout=20)
                except queue.Empty:
                    # keepalive
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if not evt:
                    continue
                obj = json.loads(evt)
                etype = obj.get("type") or "state"
                self.wfile.write(f"event: {etype}\n".encode("utf-8"))
                self.wfile.write(("data: " + json.dumps(obj) + "\n\n").encode("utf-8"))
                self.wfile.flush()
        except BrokenPipeError:
            pass
        except ConnectionResetError:
            pass
        finally:
            arena.bus.unsubscribe(match_id, q)


def run_server(arena: Arena, host: str, port: int) -> None:
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.arena = arena  # type: ignore[attr-defined]
    srv.serve_forever()


def main() -> int:
    p = argparse.ArgumentParser(description="Agent Chess Arena referee service")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init-db")
    p_init.add_argument("--db", default=os.getenv("ARENA_DB_PATH", DEFAULT_DB_PATH))

    p_pre = sub.add_parser("preflight")
    p_pre.add_argument("--db", default=os.getenv("ARENA_DB_PATH", DEFAULT_DB_PATH))
    p_pre.add_argument("--contract", default=os.getenv("CHESS_ESCROW_CONTRACT", "").strip())
    p_pre.add_argument("--operator-pem", default=os.getenv("OPERATOR_PEM", "").strip() or None)
    p_pre.add_argument("--proxy", default=os.getenv("PROXY_URL", "https://api.claws.network").strip())
    p_pre.add_argument("--chain", default=os.getenv("CHAIN_ID", "C").strip())
    p_pre.add_argument("--clawpy", default=os.getenv("CLAWPY_BIN", "clawpy").strip())

    p_run = sub.add_parser("run")
    p_run.add_argument("--db", default=os.getenv("ARENA_DB_PATH", DEFAULT_DB_PATH))
    p_run.add_argument("--host", default=os.getenv("ARENA_BIND_HOST", "127.0.0.1"))
    p_run.add_argument("--port", type=int, default=int(os.getenv("ARENA_BIND_PORT", "8787")))

    p_run.add_argument("--contract", default=os.getenv("CHESS_ESCROW_CONTRACT", "").strip())
    p_run.add_argument("--operator-pem", default=os.getenv("OPERATOR_PEM", "").strip() or None)
    p_run.add_argument("--proxy", default=os.getenv("PROXY_URL", "https://api.claws.network").strip())
    p_run.add_argument("--chain", default=os.getenv("CHAIN_ID", "C").strip())
    p_run.add_argument("--clawpy", default=os.getenv("CLAWPY_BIN", "clawpy").strip())
    p_run.add_argument("--gas-limit", type=int, default=int(os.getenv("GAS_LIMIT", "25000000")))
    p_run.add_argument("--gas-price", type=int, default=int(os.getenv("GAS_PRICE", "20000000000000")))
    p_run.add_argument("--protocol-fee-bps", type=int, default=int(os.getenv("PROTOCOL_FEE_BPS", "100")))
    p_run.add_argument("--poll-seconds", type=int, default=int(os.getenv("POLL_SECONDS", "10")))
    p_run.add_argument("--wait-result", action="store_true", default=os.getenv("WAIT_RESULT", "").strip() == "1")

    args = p.parse_args()

    if args.cmd == "init-db":
        conn = connect_db(args.db)
        init_db(conn)
        conn.close()
        print(f"ok: initialized {args.db}")
        return 0

    if args.cmd == "preflight":
        rep = preflight(
            db_path=args.db,
            contract=args.contract,
            proxy_url=args.proxy,
            chain_id=args.chain,
            clawpy_bin=args.clawpy,
            operator_pem=args.operator_pem,
        )
        print(json.dumps(rep, indent=2, ensure_ascii=True))
        return 0 if rep.get("ok") else 2

    if args.cmd == "run":
        if chess is None:
            print("ERROR: python-chess not installed. Install requirements in arena/requirements.txt")
            return 2
        if not args.contract:
            print("ERROR: CHESS_ESCROW_CONTRACT required")
            return 2

        cfg = ChainConfig(
            proxy_url=args.proxy,
            chain_id=args.chain,
            contract=args.contract,
            clawpy_bin=args.clawpy,
            operator_pem=args.operator_pem,
            gas_limit=args.gas_limit,
            gas_price=args.gas_price,
            protocol_fee_bps=args.protocol_fee_bps,
            poll_seconds=args.poll_seconds,
            wait_result=bool(args.wait_result),
        )
        arena = Arena(cfg, args.db)

        t_timeout = threading.Thread(target=arena.apply_timeout_checks, daemon=True)
        t_timeout.start()

        def poll_loop() -> None:
            while True:
                try:
                    arena.poll_once()
                except Exception:
                    pass
                time.sleep(max(2, cfg.poll_seconds))

        t_poll = threading.Thread(target=poll_loop, daemon=True)
        t_poll.start()

        print(f"listening: http://{args.host}:{args.port}")
        run_server(arena, args.host, args.port)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
