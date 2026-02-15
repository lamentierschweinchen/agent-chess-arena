multiversx_sc::imports!();
multiversx_sc::derive_imports!();

use crate::chess;

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone, Copy, PartialEq, Eq)]
pub enum MatchStatus {
    WaitingForOpponent,
    CommitPhase,
    RevealPhase,
    InProgress,
    Finished,
    Cancelled,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    Unset,
    WhiteWin,
    BlackWin,
    Draw,
    AbortedRefund,
    ForfeitNoCommit,
    ForfeitNoReveal,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct Config<M: ManagedTypeApi> {
    pub owner: ManagedAddress<M>,
    pub operator: ManagedAddress<M>,
    pub treasury: ManagedAddress<M>,
    pub protocol_fee_bps: u64,
    pub paused: bool,

    pub max_base_time_seconds: u64,
    pub min_black_time_seconds: u64,
    pub max_black_time_seconds: u64,
    pub join_timeout_seconds: u64,
    pub commit_phase_seconds: u64,
    pub reveal_phase_seconds: u64,
    pub slack_seconds: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct Match<M: ManagedTypeApi> {
    pub id: u64,
    pub status: MatchStatus,

    pub challenger: ManagedAddress<M>,
    pub opponent: ManagedAddress<M>, // zero until joined unless invite-only

    pub stake_atto: BigUint<M>, // per-player stake
    pub base_time_seconds: u64,

    pub join_deadline_ts: u64,
    pub commit_deadline_ts: u64,
    pub reveal_deadline_ts: u64,

    pub start_ts: u64,
    pub game_deadline_ts: u64,

    pub challenger_commitment: ManagedBuffer<M>, // 32 bytes when set
    pub opponent_commitment: ManagedBuffer<M>,   // 32 bytes when set

    pub challenger_bid: u64,  // 0 if not revealed
    pub challenger_seed: u64, // any u64
    pub opponent_bid: u64,    // 0 if not revealed
    pub opponent_seed: u64,   // any u64

    pub white: ManagedAddress<M>,
    pub black: ManagedAddress<M>,
    pub white_time_seconds: u64,
    pub black_time_seconds: u64,
    pub chess960_pos: u16,

    pub result: MatchResult,
    pub winner_paid: ManagedAddress<M>,
    pub payout_atto: BigUint<M>,
    pub fee_atto: BigUint<M>,
    pub pgn_hash32: ManagedBuffer<M>, // 32 bytes when set (winner-takes-all)
    pub ended_ts: u64,

    pub chat_post_id: u64, // bulletin-board post id (0 if unset)
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchSummary<M: ManagedTypeApi> {
    pub id: u64,
    pub status: MatchStatus,
    pub challenger: ManagedAddress<M>,
    pub opponent: ManagedAddress<M>,
    pub stake_atto: BigUint<M>,
    pub base_time_seconds: u64,
    pub start_ts: u64,
    pub ended_ts: u64,
    pub result: MatchResult,
    pub winner_paid: ManagedAddress<M>,
    pub chess960_pos: u16,
    pub chat_post_id: u64,
}

// ============================================================
// Event payloads (MultiversX events allow only one non-indexed arg)
// ============================================================

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchCreatedData<M: ManagedTypeApi> {
    pub stake_atto: BigUint<M>,
    pub join_deadline_ts: u64,
    pub base_time_seconds: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchJoinedData {
    pub commit_deadline_ts: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchStartedData {
    pub white_time_seconds: u64,
    pub black_time_seconds: u64,
    pub chess960_pos: u16,
    pub game_deadline_ts: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchFinalizedData<M: ManagedTypeApi> {
    pub white: ManagedAddress<M>,
    pub black: ManagedAddress<M>,
    pub result_enum: MatchResult,
    pub winner_paid: ManagedAddress<M>,
    pub payout_atto: BigUint<M>,
    pub fee_atto: BigUint<M>,
    pub pgn_hash32: ManagedBuffer<M>,
    pub ended_ts: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchCancelledData<M: ManagedTypeApi> {
    pub refunded_stake_atto: BigUint<M>,
    pub ended_ts: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchRefundedData<M: ManagedTypeApi> {
    pub stake_atto: BigUint<M>,
    pub ended_ts: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MatchForfeitData {
    pub reason_code: u8,
    pub ended_ts: u64,
}

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct MoveSubmittedData {
    pub ply: u16,
    pub mv_u16: u16,
    pub ts: u64,
}

// ============================================================
// On-chain gameplay state (stored separately from Match for gas/ABI stability)
// ============================================================

#[type_abi]
#[derive(TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct OnchainGameState {
    pub bitboards: [u64; 12],
    pub side_to_move: u8, // 0=White 1=Black
    pub castling: u8,     // chess::CASTLE_* bits
    pub ep_square: u8,    // 0..63 or chess::EP_NONE
    pub halfmove_clock: u16,
    pub fullmove_number: u16,

    pub w_king_start: u8,
    pub w_rook_ks_start: u8,
    pub w_rook_qs_start: u8,
    pub b_king_start: u8,
    pub b_rook_ks_start: u8,
    pub b_rook_qs_start: u8,

    pub white_time_left_s: u64,
    pub black_time_left_s: u64,
    pub last_move_ts: u64,
    pub ply: u16,
}

impl OnchainGameState {
    pub fn as_board(&self) -> chess::Board {
        chess::Board {
            bitboards: self.bitboards,
            side_to_move: self.side_to_move,
            castling: self.castling,
            ep_square: self.ep_square,
            halfmove_clock: self.halfmove_clock,
            fullmove_number: self.fullmove_number,
        }
    }

    pub fn as_castle_info(&self) -> chess::CastleInfo {
        chess::CastleInfo {
            w_king_start: self.w_king_start,
            w_rook_ks_start: self.w_rook_ks_start,
            w_rook_qs_start: self.w_rook_qs_start,
            b_king_start: self.b_king_start,
            b_rook_ks_start: self.b_rook_ks_start,
            b_rook_qs_start: self.b_rook_qs_start,
        }
    }

    pub fn update_from_board(&mut self, b: &chess::Board) {
        self.bitboards = b.bitboards;
        self.side_to_move = b.side_to_move;
        self.castling = b.castling;
        self.ep_square = b.ep_square;
        self.halfmove_clock = b.halfmove_clock;
        self.fullmove_number = b.fullmove_number;
    }
}
