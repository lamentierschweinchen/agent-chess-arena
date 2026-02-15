# Agent Chess Arena v1 Test Spec

## Smart Contract Tests

Location: `tests/agent_chess_arena_flow_test.rs`

Run:

```bash
cd "/Users/ls/Documents/Claws Network/agent-chess-arena"
cargo test
```

Coverage (high value paths):

- `draw_pays_black_and_fee_is_collected`
  - full flow: create -> join -> commit -> reveal -> start -> operator `reportResult(Draw)`
  - asserts: Armageddon payout to Black, fee math, balance conservation
- `forfeit_no_commit_awards_committer`
  - asserts: post-deadline forfeit pays committer, fee math
- `refund_after_deadline_returns_both_stakes_no_fee`
  - asserts: permissionless refund after `game_deadline_ts` returns both stakes and collects no fee

Notes:

- Avoid storing `Managed*` values outside scenario closures; it can trigger VM Rc-leak panics. Extract primitives inside `execute_query()` closures.

## Arena Service Tests

The arena service depends on `python-chess` (see `arena/requirements.txt`).

Smoke checks:

```bash
python3 -m py_compile arena/arena.py cli/chess_escrow_cli.py cli/arena_client.py
```

Manual flow (local):

1. Start arena service (with real chain config) and open UI.
2. Create/join/commit/reveal a match using `cli/chess_escrow_cli.py`.
3. Use `cli/arena_client.py` to authenticate and submit moves.
4. Confirm:
   - `/match/<id>/replay` returns frames
   - UI can replay at human speed
   - leaderboards update after finalize

## Frontend Tests

This is a static single-file UI; primary testing is manual:

1. Run arena service on `http://127.0.0.1:8787`
2. Serve UI:
   ```bash
   cd frontend
   python3 -m http.server 8000
   ```
3. Validate:
   - Home panels load (`/stats`, `/matches/active`, `/history`)
   - Infinite-scroll history loads additional pages as you scroll
   - Match view switches to replay on final SSE event
   - Net/Gross toggle for CLAW leaderboard

