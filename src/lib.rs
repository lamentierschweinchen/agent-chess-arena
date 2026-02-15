#![no_std]

multiversx_sc::imports!();
multiversx_sc::derive_imports!();

pub mod chess;
pub mod types;

use types::{
    Config, Match, MatchCancelledData, MatchCreatedData, MatchFinalizedData, MatchForfeitData,
    MatchJoinedData, MatchRefundedData, MatchResult, MatchStartedData, MatchStatus, MatchSummary,
    MoveSubmittedData, OnchainGameState,
};

const BPS_DENOMINATOR: u64 = 10_000;
const MAX_LATEST_MATCHES: u64 = 50;
const MAX_ONCHAIN_PLIES: usize = 1024;

const ERR_PAUSED: &str = "ERR_PAUSED";
const ERR_UNAUTHORIZED: &str = "ERR_UNAUTHORIZED";
const ERR_INVALID_STATE: &str = "ERR_INVALID_STATE";
const ERR_INVALID_AMOUNT: &str = "ERR_INVALID_AMOUNT";
const ERR_INVALID_ARG: &str = "ERR_INVALID_ARG";
const ERR_DEADLINE: &str = "ERR_DEADLINE";
const ERR_ALREADY_SET: &str = "ERR_ALREADY_SET";
const ERR_INVALID_COMMIT: &str = "ERR_INVALID_COMMIT";
const ERR_COMMIT_MISMATCH: &str = "ERR_COMMIT_MISMATCH";
const ERR_NOT_STARTED: &str = "ERR_NOT_STARTED";
const ERR_INVALID_MOVE: &str = "ERR_INVALID_MOVE";
const ERR_GAME_OVER: &str = "ERR_GAME_OVER";
const ERR_MISSING_SIG: &str = "ERR_MISSING_SIG";
const ERR_DEPRECATED: &str = "ERR_DEPRECATED";

#[multiversx_sc::contract]
pub trait AgentChessArena {
    #[init]
    fn init(
        &self,
        operator: ManagedAddress,
        treasury: ManagedAddress,
        protocol_fee_bps: u64,
        max_base_time_seconds: u64,
        min_black_time_seconds: u64,
        max_black_time_seconds: u64,
        join_timeout_seconds: u64,
        commit_phase_seconds: u64,
        reveal_phase_seconds: u64,
        slack_seconds: u64,
    ) {
        require!(!operator.is_zero(), ERR_INVALID_ARG);
        require!(!treasury.is_zero(), ERR_INVALID_ARG);
        require!(protocol_fee_bps <= BPS_DENOMINATOR, ERR_INVALID_ARG);
        require!(max_base_time_seconds > 0, ERR_INVALID_ARG);
        require!(min_black_time_seconds > 0, ERR_INVALID_ARG);
        require!(
            max_black_time_seconds >= min_black_time_seconds,
            ERR_INVALID_ARG
        );
        require!(join_timeout_seconds > 0, ERR_INVALID_ARG);
        require!(commit_phase_seconds > 0, ERR_INVALID_ARG);
        require!(reveal_phase_seconds > 0, ERR_INVALID_ARG);

        let caller = self.blockchain().get_caller();
        self.owner().set(&caller);
        self.operator().set(&operator);
        self.treasury().set(&treasury);
        self.protocol_fee_bps().set(protocol_fee_bps);
        self.paused().set(false);

        self.max_base_time_seconds().set(max_base_time_seconds);
        self.min_black_time_seconds().set(min_black_time_seconds);
        self.max_black_time_seconds().set(max_black_time_seconds);
        self.join_timeout_seconds().set(join_timeout_seconds);
        self.commit_phase_seconds().set(commit_phase_seconds);
        self.reveal_phase_seconds().set(reveal_phase_seconds);
        self.slack_seconds().set(slack_seconds);

        self.match_count().set(0u64);
    }

    #[upgrade]
    fn upgrade(&self) {}

    // ============================================================
    // Owner controls
    // ============================================================

    #[endpoint(setOperator)]
    fn set_operator(&self, new_operator: ManagedAddress) {
        self.require_owner();
        require!(!new_operator.is_zero(), ERR_INVALID_ARG);
        self.operator().set(&new_operator);
    }

    #[endpoint(setTreasury)]
    fn set_treasury(&self, new_treasury: ManagedAddress) {
        self.require_owner();
        require!(!new_treasury.is_zero(), ERR_INVALID_ARG);
        self.treasury().set(&new_treasury);
    }

    #[endpoint(setProtocolFeeBps)]
    fn set_protocol_fee_bps(&self, new_bps: u64) {
        self.require_owner();
        require!(new_bps <= BPS_DENOMINATOR, ERR_INVALID_ARG);
        self.protocol_fee_bps().set(new_bps);
    }

    #[endpoint(pause)]
    fn pause(&self) {
        self.require_owner();
        self.paused().set(true);
    }

    #[endpoint(resume)]
    fn resume(&self) {
        self.require_owner();
        self.paused().set(false);
    }

    // ============================================================
    // Match lifecycle
    // ============================================================

    #[endpoint(createMatch)]
    #[payable("EGLD")]
    fn create_match(&self, opponent: ManagedAddress, base_time_seconds: u64) -> u64 {
        self.require_not_paused();

        require!(base_time_seconds > 0, ERR_INVALID_ARG);
        require!(
            base_time_seconds <= self.max_base_time_seconds().get(),
            ERR_INVALID_ARG
        );

        let stake = self.call_value().egld_value().clone_value();
        require!(stake > 0u64, ERR_INVALID_AMOUNT);

        let challenger = self.blockchain().get_caller();
        require!(
            opponent.is_zero() || opponent != challenger,
            ERR_INVALID_ARG
        );

        let now = self.blockchain().get_block_timestamp();
        let match_id = self.match_count().get() + 1u64;
        self.match_count().set(match_id);

        let join_deadline_ts = now + self.join_timeout_seconds().get();

        let m = Match {
            id: match_id,
            status: MatchStatus::WaitingForOpponent,
            challenger: challenger.clone(),
            opponent: opponent.clone(),
            stake_atto: stake.clone(),
            base_time_seconds,
            join_deadline_ts,
            commit_deadline_ts: 0,
            reveal_deadline_ts: 0,
            start_ts: 0,
            game_deadline_ts: 0,
            challenger_commitment: ManagedBuffer::new(),
            opponent_commitment: ManagedBuffer::new(),
            challenger_bid: 0,
            challenger_seed: 0,
            opponent_bid: 0,
            opponent_seed: 0,
            white: ManagedAddress::zero(),
            black: ManagedAddress::zero(),
            white_time_seconds: 0,
            black_time_seconds: 0,
            chess960_pos: 0,
            result: MatchResult::Unset,
            winner_paid: ManagedAddress::zero(),
            payout_atto: BigUint::zero(),
            fee_atto: BigUint::zero(),
            pgn_hash32: ManagedBuffer::new(),
            ended_ts: 0,
            chat_post_id: 0,
        };

        self.matches(match_id).set(&m);
        self.match_created_event(
            match_id,
            &challenger,
            &opponent,
            MatchCreatedData {
                stake_atto: stake,
                join_deadline_ts,
                base_time_seconds,
            },
        );

        match_id
    }

    #[endpoint(joinMatch)]
    #[payable("EGLD")]
    fn join_match(&self, match_id: u64) {
        self.require_not_paused();

        let mut m = self.require_match(match_id);
        require!(
            m.status == MatchStatus::WaitingForOpponent,
            ERR_INVALID_STATE
        );

        let now = self.blockchain().get_block_timestamp();
        require!(now <= m.join_deadline_ts, ERR_DEADLINE);

        let caller = self.blockchain().get_caller();
        require!(caller != m.challenger, ERR_INVALID_ARG);
        if !m.opponent.is_zero() {
            require!(caller == m.opponent, ERR_UNAUTHORIZED);
        } else {
            m.opponent = caller.clone();
        }

        let payment = self.call_value().egld_value().clone_value();
        require!(payment == m.stake_atto, ERR_INVALID_AMOUNT);

        m.status = MatchStatus::CommitPhase;
        m.commit_deadline_ts = now + self.commit_phase_seconds().get();
        m.reveal_deadline_ts = 0;

        self.matches(match_id).set(&m);
        self.match_joined_event(
            match_id,
            &caller,
            MatchJoinedData {
                commit_deadline_ts: m.commit_deadline_ts,
            },
        );
    }

    #[endpoint(cancelMatch)]
    fn cancel_match(&self, match_id: u64) {
        // Allowed even when paused.
        let mut m = self.require_match(match_id);
        require!(
            m.status == MatchStatus::WaitingForOpponent,
            ERR_INVALID_STATE
        );

        let caller = self.blockchain().get_caller();
        require!(caller == m.challenger, ERR_UNAUTHORIZED);

        let now = self.blockchain().get_block_timestamp();
        m.status = MatchStatus::Cancelled;
        m.ended_ts = now;
        m.result = MatchResult::AbortedRefund;
        self.matches(match_id).set(&m);

        self.match_cancelled_event(
            match_id,
            MatchCancelledData {
                refunded_stake_atto: m.stake_atto.clone(),
                ended_ts: now,
            },
        );
        self.send().direct_egld(&caller, &m.stake_atto);
    }

    #[endpoint(commitBid)]
    fn commit_bid(&self, match_id: u64, commitment32: ManagedBuffer) {
        self.require_not_paused();

        let mut m = self.require_match(match_id);
        require!(m.status == MatchStatus::CommitPhase, ERR_INVALID_STATE);

        let now = self.blockchain().get_block_timestamp();
        require!(now <= m.commit_deadline_ts, ERR_DEADLINE);
        require!(commitment32.len() == 32, ERR_INVALID_COMMIT);

        let caller = self.blockchain().get_caller();
        require!(self.is_player(&m, &caller), ERR_UNAUTHORIZED);

        if caller == m.challenger {
            require!(m.challenger_commitment.is_empty(), ERR_ALREADY_SET);
            m.challenger_commitment = commitment32;
        } else {
            require!(m.opponent_commitment.is_empty(), ERR_ALREADY_SET);
            m.opponent_commitment = commitment32;
        }

        let both = !m.challenger_commitment.is_empty() && !m.opponent_commitment.is_empty();
        if both {
            m.status = MatchStatus::RevealPhase;
            m.reveal_deadline_ts = now + self.reveal_phase_seconds().get();
        }

        self.matches(match_id).set(&m);
        self.bid_committed_event(match_id, &caller);
    }

    #[endpoint(revealBid)]
    fn reveal_bid(
        &self,
        match_id: u64,
        bid_black_time_seconds: u64,
        seed_u64: u64,
        salt: ManagedBuffer,
    ) {
        self.require_not_paused();

        let mut m = self.require_match(match_id);
        require!(m.status == MatchStatus::RevealPhase, ERR_INVALID_STATE);

        let now = self.blockchain().get_block_timestamp();
        require!(now <= m.reveal_deadline_ts, ERR_DEADLINE);

        let min_black = self.min_black_time_seconds().get();
        let max_black = self.max_black_time_seconds().get();
        require!(
            bid_black_time_seconds >= min_black && bid_black_time_seconds <= max_black,
            ERR_INVALID_ARG
        );

        let caller = self.blockchain().get_caller();
        require!(self.is_player(&m, &caller), ERR_UNAUTHORIZED);

        // Enforce commitment exists and reveal is single-use.
        let commitment = if caller == m.challenger {
            require!(!m.challenger_commitment.is_empty(), ERR_INVALID_STATE);
            require!(m.challenger_bid == 0, ERR_ALREADY_SET);
            m.challenger_commitment.clone()
        } else {
            require!(!m.opponent_commitment.is_empty(), ERR_INVALID_STATE);
            require!(m.opponent_bid == 0, ERR_ALREADY_SET);
            m.opponent_commitment.clone()
        };

        // preimage = u64_be(bid) || u64_be(seed) || salt_bytes
        let mut preimage = ManagedBuffer::new();
        let bid_bytes = bid_black_time_seconds.to_be_bytes();
        let seed_bytes = seed_u64.to_be_bytes();
        preimage.append_bytes(&bid_bytes);
        preimage.append_bytes(&seed_bytes);
        preimage.append(&salt);

        let digest = self.crypto().sha256(&preimage);
        require!(
            digest.as_managed_buffer() == &commitment,
            ERR_COMMIT_MISMATCH
        );

        if caller == m.challenger {
            m.challenger_bid = bid_black_time_seconds;
            m.challenger_seed = seed_u64;
        } else {
            m.opponent_bid = bid_black_time_seconds;
            m.opponent_seed = seed_u64;
        }

        let both_revealed = m.challenger_bid != 0 && m.opponent_bid != 0;
        if both_revealed {
            // Assign colors by lowest bid; ties broken by address bytes.
            let (white, black, black_time_seconds) =
                self.assign_colors(&m.challenger, m.challenger_bid, &m.opponent, m.opponent_bid);

            let pos = ((m.challenger_seed ^ m.opponent_seed) % 960u64) as u16;
            let slack = self.slack_seconds().get();

            m.white = white.clone();
            m.black = black.clone();
            m.white_time_seconds = m.base_time_seconds;
            m.black_time_seconds = black_time_seconds;
            m.chess960_pos = pos;

            m.start_ts = now;
            m.game_deadline_ts = now + m.white_time_seconds + m.black_time_seconds + slack;
            m.status = MatchStatus::InProgress;

            // Initialize on-chain chess engine state and first position hash.
            let (board, ci) = chess::Board::new_chess960(m.chess960_pos);
            let gs = OnchainGameState {
                bitboards: board.bitboards,
                side_to_move: board.side_to_move,
                castling: board.castling,
                ep_square: board.ep_square,
                halfmove_clock: board.halfmove_clock,
                fullmove_number: board.fullmove_number,
                w_king_start: ci.w_king_start,
                w_rook_ks_start: ci.w_rook_ks_start,
                w_rook_qs_start: ci.w_rook_qs_start,
                b_king_start: ci.b_king_start,
                b_rook_ks_start: ci.b_rook_ks_start,
                b_rook_qs_start: ci.b_rook_qs_start,
                white_time_left_s: m.white_time_seconds,
                black_time_left_s: m.black_time_seconds,
                last_move_ts: now,
                ply: 0,
            };
            self.onchain_state(match_id).set(&gs);
            let mut hashes = self.pos_hashes(match_id);
            hashes.clear();
            let h0 =
                chess::position_hash(&gs.bitboards, gs.side_to_move, gs.castling, gs.ep_square);
            hashes.push(&h0);

            self.match_started_event(
                match_id,
                &m.white,
                &m.black,
                MatchStartedData {
                    white_time_seconds: m.white_time_seconds,
                    black_time_seconds: m.black_time_seconds,
                    chess960_pos: m.chess960_pos,
                    game_deadline_ts: m.game_deadline_ts,
                },
            );
        }

        self.matches(match_id).set(&m);
        self.bid_revealed_event(match_id, &caller, bid_black_time_seconds);
    }

    #[endpoint(claimForfeitNoCommit)]
    fn claim_forfeit_no_commit(&self, match_id: u64) {
        // Allowed even when paused (unwind).
        let mut m = self.require_match(match_id);
        require!(m.status == MatchStatus::CommitPhase, ERR_INVALID_STATE);

        let now = self.blockchain().get_block_timestamp();
        require!(now > m.commit_deadline_ts, ERR_DEADLINE);

        let challenger_committed = !m.challenger_commitment.is_empty();
        let opponent_committed = !m.opponent_commitment.is_empty();
        require!(
            !(challenger_committed && opponent_committed),
            ERR_INVALID_STATE
        );

        if challenger_committed ^ opponent_committed {
            let winner = if challenger_committed {
                m.challenger.clone()
            } else {
                m.opponent.clone()
            };
            self.finish_winner_takes_all(
                &mut m,
                match_id,
                MatchResult::ForfeitNoCommit,
                &winner,
                ManagedBuffer::new(),
                now,
            );
            self.match_forfeit_event(
                match_id,
                &winner,
                MatchForfeitData {
                    reason_code: 1u8,
                    ended_ts: now,
                },
            );
        } else {
            // Neither committed: refund both.
            self.finish_refund_both(&mut m, match_id, now, MatchResult::AbortedRefund);
            self.match_refunded_event(
                match_id,
                MatchRefundedData {
                    stake_atto: m.stake_atto.clone(),
                    ended_ts: now,
                },
            );
        }
    }

    #[endpoint(claimForfeitNoReveal)]
    fn claim_forfeit_no_reveal(&self, match_id: u64) {
        // Allowed even when paused (unwind).
        let mut m = self.require_match(match_id);
        require!(m.status == MatchStatus::RevealPhase, ERR_INVALID_STATE);

        let now = self.blockchain().get_block_timestamp();
        require!(now > m.reveal_deadline_ts, ERR_DEADLINE);

        let challenger_revealed = m.challenger_bid != 0;
        let opponent_revealed = m.opponent_bid != 0;
        require!(
            !(challenger_revealed && opponent_revealed),
            ERR_INVALID_STATE
        );

        if challenger_revealed ^ opponent_revealed {
            let winner = if challenger_revealed {
                m.challenger.clone()
            } else {
                m.opponent.clone()
            };
            self.finish_winner_takes_all(
                &mut m,
                match_id,
                MatchResult::ForfeitNoReveal,
                &winner,
                ManagedBuffer::new(),
                now,
            );
            self.match_forfeit_event(
                match_id,
                &winner,
                MatchForfeitData {
                    reason_code: 2u8,
                    ended_ts: now,
                },
            );
        } else {
            self.finish_refund_both(&mut m, match_id, now, MatchResult::AbortedRefund);
            self.match_refunded_event(
                match_id,
                MatchRefundedData {
                    stake_atto: m.stake_atto.clone(),
                    ended_ts: now,
                },
            );
        }
    }

    // ============================================================
    // Operator endpoints (arena finalization)
    // ============================================================

    #[endpoint(setMatchChat)]
    fn set_match_chat(&self, match_id: u64, bulletin_post_id: u64) {
        self.require_operator();
        require!(bulletin_post_id > 0, ERR_INVALID_ARG);

        let mut m = self.require_match(match_id);
        require!(m.chat_post_id == 0, ERR_ALREADY_SET);
        m.chat_post_id = bulletin_post_id;
        self.matches(match_id).set(&m);
    }

    #[endpoint(reportResult)]
    fn report_result(&self, match_id: u64, result: MatchResult, pgn_hash32: ManagedBuffer) {
        let _ = (match_id, result, pgn_hash32);
        sc_panic!(ERR_DEPRECATED);
    }

    // ============================================================
    // On-chain moves (relay-submitted, player-signed)
    // ============================================================

    #[endpoint(submitMove)]
    fn submit_move(&self, match_id: u64, mv_u16: u16, signature: ManagedBuffer) {
        self.require_not_paused();

        let mut m = self.require_match(match_id);
        require!(m.status == MatchStatus::InProgress, ERR_INVALID_STATE);
        require!(m.result == MatchResult::Unset, ERR_GAME_OVER);

        require!(!self.onchain_state(match_id).is_empty(), ERR_INVALID_STATE);
        let mut gs = self.onchain_state(match_id).get();
        let now = self.blockchain().get_block_timestamp();

        let side = gs.side_to_move;
        let expected = if side == chess::WHITE {
            m.white.clone()
        } else {
            m.black.clone()
        };

        let caller = self.blockchain().get_caller();
        if caller != expected {
            require!(!signature.is_empty(), ERR_MISSING_SIG);
            self.verify_move_sig(&expected, match_id, gs.ply, mv_u16, &signature);
        } else if !signature.is_empty() {
            self.verify_move_sig(&expected, match_id, gs.ply, mv_u16, &signature);
        }

        // Deduct time for side-to-move; if it flags, finalize immediately.
        let elapsed = now.saturating_sub(gs.last_move_ts);
        if side == chess::WHITE {
            if elapsed >= gs.white_time_left_s {
                let winner = m.black.clone();
                self.finish_winner_takes_all(
                    &mut m,
                    match_id,
                    MatchResult::BlackWin,
                    &winner,
                    ManagedBuffer::new(),
                    now,
                );
                return;
            }
            gs.white_time_left_s -= elapsed;
        } else {
            if elapsed >= gs.black_time_left_s {
                let winner = m.white.clone();
                self.finish_winner_takes_all(
                    &mut m,
                    match_id,
                    MatchResult::WhiteWin,
                    &winner,
                    ManagedBuffer::new(),
                    now,
                );
                return;
            }
            gs.black_time_left_s -= elapsed;
        }

        let mut board = gs.as_board();
        let ci = gs.as_castle_info();
        let apply_res = chess::apply_move(&mut board, ci, mv_u16);
        require!(
            matches!(apply_res, chess::ApplyResult::Ok { .. }),
            ERR_INVALID_MOVE
        );

        gs.update_from_board(&board);
        gs.last_move_ts = now;
        gs.ply = gs.ply.saturating_add(1);
        self.onchain_state(match_id).set(&gs);

        self.move_submitted_event(
            match_id,
            &expected,
            MoveSubmittedData {
                ply: gs.ply,
                mv_u16,
                ts: now,
            },
        );

        // Draw rules.
        if chess::insufficient_material(&gs.bitboards) || gs.halfmove_clock >= 100 {
            let winner = m.black.clone();
            self.finish_winner_takes_all(
                &mut m,
                match_id,
                MatchResult::Draw,
                &winner,
                ManagedBuffer::new(),
                now,
            );
            return;
        }

        let h = chess::position_hash(&gs.bitboards, gs.side_to_move, gs.castling, gs.ep_square);
        let mut hashes = self.pos_hashes(match_id);
        hashes.push(&h);
        if hashes.len() > MAX_ONCHAIN_PLIES {
            // Hard cap to prevent unbounded storage growth. Treat as a draw.
            let winner = m.black.clone();
            self.finish_winner_takes_all(
                &mut m,
                match_id,
                MatchResult::Draw,
                &winner,
                ManagedBuffer::new(),
                now,
            );
            return;
        }
        let mut count = 0u32;
        for x in hashes.iter() {
            if x == h {
                count += 1;
            }
        }
        if count >= 3 {
            let winner = m.black.clone();
            self.finish_winner_takes_all(
                &mut m,
                match_id,
                MatchResult::Draw,
                &winner,
                ManagedBuffer::new(),
                now,
            );
            return;
        }

        // Checkmate / stalemate.
        if !chess::has_any_legal_move(&board, ci) {
            let stm = board.side_to_move;
            if chess::in_check(&board.bitboards, stm) {
                let winner = if stm == chess::WHITE {
                    m.black.clone()
                } else {
                    m.white.clone()
                };
                let res = if winner == m.white {
                    MatchResult::WhiteWin
                } else {
                    MatchResult::BlackWin
                };
                self.finish_winner_takes_all(
                    &mut m,
                    match_id,
                    res,
                    &winner,
                    ManagedBuffer::new(),
                    now,
                );
            } else {
                let winner = m.black.clone();
                self.finish_winner_takes_all(
                    &mut m,
                    match_id,
                    MatchResult::Draw,
                    &winner,
                    ManagedBuffer::new(),
                    now,
                );
            }
        }
    }

    // ============================================================
    // Liveness
    // ============================================================

    #[endpoint(claimRefundAfterDeadline)]
    fn claim_refund_after_deadline(&self, match_id: u64) {
        // Allowed even when paused.
        let mut m = self.require_match(match_id);
        require!(m.status == MatchStatus::InProgress, ERR_INVALID_STATE);
        require!(m.result == MatchResult::Unset, ERR_INVALID_STATE);
        require!(m.start_ts > 0, ERR_NOT_STARTED);

        let now = self.blockchain().get_block_timestamp();
        require!(now > m.game_deadline_ts, ERR_DEADLINE);

        self.finish_refund_both(&mut m, match_id, now, MatchResult::AbortedRefund);
        self.match_refunded_event(
            match_id,
            MatchRefundedData {
                stake_atto: m.stake_atto.clone(),
                ended_ts: now,
            },
        );
    }

    #[endpoint(claimTimeout)]
    fn claim_timeout(&self, match_id: u64) {
        // Permissionless. Allowed even when paused.
        let mut m = self.require_match(match_id);
        require!(m.status == MatchStatus::InProgress, ERR_INVALID_STATE);
        require!(m.result == MatchResult::Unset, ERR_GAME_OVER);

        require!(!self.onchain_state(match_id).is_empty(), ERR_INVALID_STATE);
        let gs = self.onchain_state(match_id).get();
        let now = self.blockchain().get_block_timestamp();
        let elapsed = now.saturating_sub(gs.last_move_ts);

        if gs.side_to_move == chess::WHITE {
            require!(elapsed >= gs.white_time_left_s, ERR_DEADLINE);
            let winner = m.black.clone();
            self.finish_winner_takes_all(
                &mut m,
                match_id,
                MatchResult::BlackWin,
                &winner,
                ManagedBuffer::new(),
                now,
            );
        } else {
            require!(elapsed >= gs.black_time_left_s, ERR_DEADLINE);
            let winner = m.white.clone();
            self.finish_winner_takes_all(
                &mut m,
                match_id,
                MatchResult::WhiteWin,
                &winner,
                ManagedBuffer::new(),
                now,
            );
        }
    }

    // ============================================================
    // Views
    // ============================================================

    #[view(getConfig)]
    fn get_config(&self) -> Config<Self::Api> {
        Config {
            owner: self.owner().get(),
            operator: self.operator().get(),
            treasury: self.treasury().get(),
            protocol_fee_bps: self.protocol_fee_bps().get(),
            paused: self.paused().get(),
            max_base_time_seconds: self.max_base_time_seconds().get(),
            min_black_time_seconds: self.min_black_time_seconds().get(),
            max_black_time_seconds: self.max_black_time_seconds().get(),
            join_timeout_seconds: self.join_timeout_seconds().get(),
            commit_phase_seconds: self.commit_phase_seconds().get(),
            reveal_phase_seconds: self.reveal_phase_seconds().get(),
            slack_seconds: self.slack_seconds().get(),
        }
    }

    #[view(getMatch)]
    fn get_match(&self, match_id: u64) -> Match<Self::Api> {
        require!(!self.matches(match_id).is_empty(), ERR_INVALID_ARG);
        self.matches(match_id).get()
    }

    #[view(getOnchainState)]
    fn get_onchain_state(&self, match_id: u64) -> OnchainGameState {
        require!(!self.onchain_state(match_id).is_empty(), ERR_INVALID_ARG);
        self.onchain_state(match_id).get()
    }

    #[view(getMoveMessage)]
    fn get_move_message(&self, match_id: u64, ply: u16, mv_u16: u16) -> ManagedBuffer {
        require!(!self.onchain_state(match_id).is_empty(), ERR_INVALID_ARG);
        self.build_move_message(match_id, ply, mv_u16)
    }

    #[view(getMatchSummary)]
    fn get_match_summary(&self, match_id: u64) -> MatchSummary<Self::Api> {
        require!(!self.matches(match_id).is_empty(), ERR_INVALID_ARG);
        let m = self.matches(match_id).get();
        self.to_summary(&m)
    }

    #[view(getMatchCount)]
    fn get_match_count(&self) -> u64 {
        self.match_count().get()
    }

    #[view(getLatestMatches)]
    fn get_latest_matches(&self, count: u64) -> MultiValueEncoded<MatchSummary<Self::Api>> {
        let capped = core::cmp::min(count, MAX_LATEST_MATCHES);
        let total = self.match_count().get();
        let mut result = MultiValueEncoded::new();

        let mut pushed = 0u64;
        let mut id = total;
        while id > 0 && pushed < capped {
            if !self.matches(id).is_empty() {
                let m = self.matches(id).get();
                result.push(self.to_summary(&m));
                pushed += 1;
            }
            id -= 1;
        }

        result
    }

    // ============================================================
    // Internal helpers
    // ============================================================

    fn require_not_paused(&self) {
        require!(!self.paused().get(), ERR_PAUSED);
    }

    fn require_owner(&self) {
        let caller = self.blockchain().get_caller();
        require!(caller == self.owner().get(), ERR_UNAUTHORIZED);
    }

    fn require_operator(&self) {
        let caller = self.blockchain().get_caller();
        require!(caller == self.operator().get(), ERR_UNAUTHORIZED);
    }

    fn require_match(&self, match_id: u64) -> Match<Self::Api> {
        require!(!self.matches(match_id).is_empty(), ERR_INVALID_ARG);
        self.matches(match_id).get()
    }

    fn is_player(&self, m: &Match<Self::Api>, addr: &ManagedAddress) -> bool {
        *addr == m.challenger || *addr == m.opponent
    }

    fn to_summary(&self, m: &Match<Self::Api>) -> MatchSummary<Self::Api> {
        MatchSummary {
            id: m.id,
            status: m.status,
            challenger: m.challenger.clone(),
            opponent: m.opponent.clone(),
            stake_atto: m.stake_atto.clone(),
            base_time_seconds: m.base_time_seconds,
            start_ts: m.start_ts,
            ended_ts: m.ended_ts,
            result: m.result,
            winner_paid: m.winner_paid.clone(),
            chess960_pos: m.chess960_pos,
            chat_post_id: m.chat_post_id,
        }
    }

    fn assign_colors(
        &self,
        a: &ManagedAddress,
        bid_a: u64,
        b: &ManagedAddress,
        bid_b: u64,
    ) -> (ManagedAddress, ManagedAddress, u64) {
        if bid_a < bid_b {
            // a wins Black.
            (b.clone(), a.clone(), bid_a)
        } else if bid_b < bid_a {
            // b wins Black.
            (a.clone(), b.clone(), bid_b)
        } else {
            // Tie: black is lexicographically smaller address bytes.
            let a_bytes = a.to_byte_array();
            let b_bytes = b.to_byte_array();
            if a_bytes < b_bytes {
                (b.clone(), a.clone(), bid_a)
            } else {
                (a.clone(), b.clone(), bid_b)
            }
        }
    }

    fn calc_fee_and_payout(&self, pot_atto: &BigUint, fee_bps: u64) -> (BigUint, BigUint) {
        if fee_bps == 0 {
            return (BigUint::zero(), pot_atto.clone());
        }
        let mut fee = pot_atto.clone();
        fee *= fee_bps;
        fee /= BPS_DENOMINATOR;
        let payout = pot_atto - &fee;
        (fee, payout)
    }

    fn finish_winner_takes_all(
        &self,
        m: &mut Match<Self::Api>,
        match_id: u64,
        result: MatchResult,
        winner: &ManagedAddress,
        pgn_hash32: ManagedBuffer,
        ended_ts: u64,
    ) {
        require!(!winner.is_zero(), ERR_INVALID_ARG);
        require!(m.status != MatchStatus::Finished, ERR_INVALID_STATE);

        let pot = &m.stake_atto * 2u64;
        let fee_bps = self.protocol_fee_bps().get();
        let (fee, payout) = self.calc_fee_and_payout(&pot, fee_bps);

        m.status = MatchStatus::Finished;
        m.result = result;
        m.winner_paid = winner.clone();
        m.ended_ts = ended_ts;
        m.fee_atto = fee.clone();
        m.payout_atto = payout.clone();
        m.pgn_hash32 = pgn_hash32.clone();

        self.matches(match_id).set(&*m);

        if fee > 0u64 {
            let treasury = self.treasury().get();
            self.send().direct_egld(&treasury, &fee);
        }
        self.send().direct_egld(winner, &payout);

        self.match_finalized_event(
            match_id,
            MatchFinalizedData {
                white: m.white.clone(),
                black: m.black.clone(),
                result_enum: m.result,
                winner_paid: m.winner_paid.clone(),
                payout_atto: m.payout_atto.clone(),
                fee_atto: m.fee_atto.clone(),
                pgn_hash32,
                ended_ts,
            },
        );
    }

    fn finish_refund_both(
        &self,
        m: &mut Match<Self::Api>,
        match_id: u64,
        ended_ts: u64,
        result: MatchResult,
    ) {
        require!(m.status != MatchStatus::Finished, ERR_INVALID_STATE);
        require!(!m.opponent.is_zero(), ERR_INVALID_STATE);

        m.status = MatchStatus::Finished;
        m.result = result;
        m.winner_paid = ManagedAddress::zero();
        m.ended_ts = ended_ts;
        m.fee_atto = BigUint::zero();
        m.payout_atto = BigUint::zero();
        m.pgn_hash32 = ManagedBuffer::new();

        let stake = m.stake_atto.clone();
        let challenger = m.challenger.clone();
        let opponent = m.opponent.clone();

        self.matches(match_id).set(&*m);

        self.send().direct_egld(&challenger, &stake);
        self.send().direct_egld(&opponent, &stake);
    }

    // ============================================================
    // Signature helpers (relay-submitted moves)
    // ============================================================

    fn verify_move_sig(
        &self,
        signer: &ManagedAddress,
        match_id: u64,
        ply: u16,
        mv_u16: u16,
        signature: &ManagedBuffer,
    ) {
        let pubkey = signer.to_byte_array();
        let key = ManagedBuffer::new_from_bytes(&pubkey);
        let msg = self.build_move_message(match_id, ply, mv_u16);
        self.crypto().verify_ed25519(&key, &msg, signature);
    }

    fn build_move_message(&self, match_id: u64, ply: u16, mv_u16: u16) -> ManagedBuffer {
        // Message format (ASCII):
        // ACAMOVE1|<sc_hex>|<match_id>|<ply>|<mv_u16>
        let mut buf = ManagedBuffer::new();
        buf.append_bytes(b"ACAMOVE1|");
        let sc = self.blockchain().get_sc_address();
        let sc_bytes = sc.to_byte_array();
        self.append_hex32(&mut buf, &sc_bytes);
        buf.append_bytes(b"|");
        self.append_u64_ascii(&mut buf, match_id);
        buf.append_bytes(b"|");
        self.append_u64_ascii(&mut buf, ply as u64);
        buf.append_bytes(b"|");
        self.append_u64_ascii(&mut buf, mv_u16 as u64);
        buf
    }

    fn append_hex32(&self, buf: &mut ManagedBuffer, bytes32: &[u8; 32]) {
        for b in bytes32.iter() {
            let hi = b >> 4;
            let lo = b & 0x0f;
            let out = [self.hex_digit(hi), self.hex_digit(lo)];
            buf.append_bytes(&out);
        }
    }

    fn hex_digit(&self, n: u8) -> u8 {
        if n < 10 {
            b'0' + n
        } else {
            b'a' + (n - 10)
        }
    }

    fn append_u64_ascii(&self, buf: &mut ManagedBuffer, mut x: u64) {
        // Write decimal digits without heap allocation.
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        if x == 0 {
            buf.append_bytes(b"0");
            return;
        }
        while x > 0 {
            let d = (x % 10) as u8;
            x /= 10;
            i -= 1;
            tmp[i] = b'0' + d;
        }
        buf.append_bytes(&tmp[i..]);
    }

    // ============================================================
    // Events
    // ============================================================

    #[event("matchCreated")]
    fn match_created_event(
        &self,
        #[indexed] match_id: u64,
        #[indexed] challenger: &ManagedAddress,
        #[indexed] opponent: &ManagedAddress,
        data: MatchCreatedData<Self::Api>,
    );

    #[event("matchJoined")]
    fn match_joined_event(
        &self,
        #[indexed] match_id: u64,
        #[indexed] opponent: &ManagedAddress,
        data: MatchJoinedData,
    );

    #[event("bidCommitted")]
    fn bid_committed_event(&self, #[indexed] match_id: u64, #[indexed] player: &ManagedAddress);

    #[event("bidRevealed")]
    fn bid_revealed_event(
        &self,
        #[indexed] match_id: u64,
        #[indexed] player: &ManagedAddress,
        bid_black_time_seconds: u64,
    );

    #[event("matchStarted")]
    fn match_started_event(
        &self,
        #[indexed] match_id: u64,
        #[indexed] white: &ManagedAddress,
        #[indexed] black: &ManagedAddress,
        data: MatchStartedData,
    );

    #[event("matchFinalized")]
    fn match_finalized_event(&self, #[indexed] match_id: u64, data: MatchFinalizedData<Self::Api>);

    #[event("matchCancelled")]
    fn match_cancelled_event(&self, #[indexed] match_id: u64, data: MatchCancelledData<Self::Api>);

    #[event("matchRefunded")]
    fn match_refunded_event(&self, #[indexed] match_id: u64, data: MatchRefundedData<Self::Api>);

    #[event("matchForfeit")]
    fn match_forfeit_event(
        &self,
        #[indexed] match_id: u64,
        #[indexed] winner: &ManagedAddress,
        data: MatchForfeitData,
    );

    #[event("moveSubmitted")]
    fn move_submitted_event(
        &self,
        #[indexed] match_id: u64,
        #[indexed] player: &ManagedAddress,
        data: MoveSubmittedData,
    );

    // ============================================================
    // Storage
    // ============================================================

    #[storage_mapper("owner")]
    fn owner(&self) -> SingleValueMapper<ManagedAddress>;

    #[storage_mapper("operator")]
    fn operator(&self) -> SingleValueMapper<ManagedAddress>;

    #[storage_mapper("treasury")]
    fn treasury(&self) -> SingleValueMapper<ManagedAddress>;

    #[storage_mapper("protocolFeeBps")]
    fn protocol_fee_bps(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("paused")]
    fn paused(&self) -> SingleValueMapper<bool>;

    #[storage_mapper("maxBaseTimeSeconds")]
    fn max_base_time_seconds(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("minBlackTimeSeconds")]
    fn min_black_time_seconds(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("maxBlackTimeSeconds")]
    fn max_black_time_seconds(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("joinTimeoutSeconds")]
    fn join_timeout_seconds(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("commitPhaseSeconds")]
    fn commit_phase_seconds(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("revealPhaseSeconds")]
    fn reveal_phase_seconds(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("slackSeconds")]
    fn slack_seconds(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("matchCount")]
    fn match_count(&self) -> SingleValueMapper<u64>;

    #[storage_mapper("matches")]
    fn matches(&self, match_id: u64) -> SingleValueMapper<Match<Self::Api>>;

    #[storage_mapper("onchainState")]
    fn onchain_state(&self, match_id: u64) -> SingleValueMapper<OnchainGameState>;

    #[storage_mapper("posHashes")]
    fn pos_hashes(&self, match_id: u64) -> VecMapper<u64>;
}
