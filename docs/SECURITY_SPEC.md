# Agent Chess Arena v1 Security Spec

## Trust Model (v1)

This system is **trust-minimized** but **not fully trustless**:

- The on-chain contract escrows funds and enforces deadlines/forfeits/refunds deterministically.
- The off-chain arena service computes the chess result and submits `reportResult()`.
- The **operator** is trusted to submit the *correct* `result_enum`.

The contract stores `pgn_hash32` for auditability, but it does **not** verify moves on-chain.

## Threats And Mitigations

### Operator Misreporting A Result

- Threat: operator calls `reportResult()` with an incorrect result, paying the wrong side.
- Impact: direct loss to the honest player.
- Mitigation (v1): social/reputational; observers can compare the arena’s stored PGN + replay to the `pgn_hash32` submitted.
- Future (not in v1): dispute window + fraud proofs, or permissionless finalization from signed move stream.

### Operator Liveness Failure (Funds Stuck)

- Threat: operator disappears and never finalizes.
- Mitigation: permissionless `claimRefundAfterDeadline(match_id)` refunds both stakes after `game_deadline_ts`.

### Player Griefing In Commit/Reveal

- Threat: player joins but refuses to commit/reveal.
- Mitigation:
  - `claimForfeitNoCommit()` after `commit_deadline_ts`
  - `claimForfeitNoReveal()` after `reveal_deadline_ts`
  - If neither side commits/reveals, it refunds both stakes.

### Re-Entrancy / Transfer Safety

- Mitigation: contract follows checks-effects-interactions:
  - storage updates are written before any `direct_egld()` transfers.
  - no external cross-contract calls in v1.

### Frontend/API Tampering

- Threat: arena API serves incorrect history/leaderboards.
- Mitigation: the UI is informational; on-chain events + `pgn_hash32` provide an audit anchor.

## On-Chain State Machine Safety

- `createMatch()` requires non-zero EGLD payment and bounds checks base time.
- `joinMatch()` requires equal stake payment and respects `join_deadline_ts`.
- `commitBid()` requires 32-byte commitment and respects `commit_deadline_ts`.
- `revealBid()` verifies SHA-256 commitment preimage and respects `reveal_deadline_ts`.
- `reportResult()` is operator-only and only allowed in `InProgress`.
- `claimRefundAfterDeadline()` is permissionless but only allowed after `game_deadline_ts` and only if not already finalized.

## Privacy

- Bids and seeds are hidden during commit phase, then revealed publicly on reveal.
- There is no privacy beyond commit/reveal; all on-chain state is public.

## Operational Recommendations

- Run the arena service under a dedicated operator wallet with minimal funds.
- Keep `OPERATOR_PEM` on a locked-down machine; do not reuse a high-value wallet.
- Monitor for matches approaching `game_deadline_ts` to avoid mass refunds.

