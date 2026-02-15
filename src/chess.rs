//! On-chain chess engine (Chess960 + standard draw rules).
//!
//! This is intentionally compact and self-contained: no alloc-heavy move lists
//! and no external dependencies (smart contract is `no_std`).

#![allow(clippy::many_single_char_names)]

use core::cmp::{max, min};

pub const WHITE: u8 = 0;
pub const BLACK: u8 = 1;

pub const PIECE_PAWN: u8 = 0;
pub const PIECE_KNIGHT: u8 = 1;
pub const PIECE_BISHOP: u8 = 2;
pub const PIECE_ROOK: u8 = 3;
pub const PIECE_QUEEN: u8 = 4;
pub const PIECE_KING: u8 = 5;

// bitboard index: (color * 6 + piece_kind)
pub const fn bb_idx(color: u8, piece: u8) -> usize {
    (color as usize) * 6 + (piece as usize)
}

pub const CASTLE_WK: u8 = 1 << 0;
pub const CASTLE_WQ: u8 = 1 << 1;
pub const CASTLE_BK: u8 = 1 << 2;
pub const CASTLE_BQ: u8 = 1 << 3;

pub const EP_NONE: u8 = 64;

// Promotion codes in the 4 high bits of the encoded move.
pub const PROMO_NONE: u8 = 0;
pub const PROMO_Q: u8 = 1;
pub const PROMO_R: u8 = 2;
pub const PROMO_B: u8 = 3;
pub const PROMO_N: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApplyResult {
    Ok { capture: bool, pawn_move: bool },
    Illegal,
}

#[derive(Clone, Copy)]
pub struct DecodedMove {
    pub from: u8,
    pub to: u8,
    pub promo: u8,
}

#[inline]
pub fn decode_move(mv: u16) -> DecodedMove {
    DecodedMove {
        from: (mv & 0x3f) as u8,
        to: ((mv >> 6) & 0x3f) as u8,
        promo: ((mv >> 12) & 0x0f) as u8,
    }
}

#[inline]
pub fn encode_move(from: u8, to: u8, promo: u8) -> u16 {
    (from as u16) | ((to as u16) << 6) | ((promo as u16) << 12)
}

#[inline]
fn sq_mask(sq: u8) -> u64 {
    1u64 << (sq as u64)
}

#[inline]
pub fn file_of(sq: u8) -> u8 {
    sq & 7
}

#[inline]
pub fn rank_of(sq: u8) -> u8 {
    sq >> 3
}

#[inline]
fn pop_lsb(bb: &mut u64) -> u8 {
    let lsb = bb.trailing_zeros() as u8;
    *bb &= *bb - 1;
    lsb
}

#[inline]
fn occ_color(bitboards: &[u64; 12], color: u8) -> u64 {
    bitboards[bb_idx(color, PIECE_PAWN)]
        | bitboards[bb_idx(color, PIECE_KNIGHT)]
        | bitboards[bb_idx(color, PIECE_BISHOP)]
        | bitboards[bb_idx(color, PIECE_ROOK)]
        | bitboards[bb_idx(color, PIECE_QUEEN)]
        | bitboards[bb_idx(color, PIECE_KING)]
}

#[inline]
fn occ_all(bitboards: &[u64; 12]) -> u64 {
    occ_color(bitboards, WHITE) | occ_color(bitboards, BLACK)
}

#[inline]
fn piece_at(bitboards: &[u64; 12], sq: u8) -> Option<(u8, u8)> {
    let m = sq_mask(sq);
    for color in [WHITE, BLACK] {
        for piece in [
            PIECE_PAWN,
            PIECE_KNIGHT,
            PIECE_BISHOP,
            PIECE_ROOK,
            PIECE_QUEEN,
            PIECE_KING,
        ] {
            if (bitboards[bb_idx(color, piece)] & m) != 0 {
                return Some((color, piece));
            }
        }
    }
    None
}

#[inline]
fn king_sq(bitboards: &[u64; 12], color: u8) -> u8 {
    let mut bb = bitboards[bb_idx(color, PIECE_KING)];
    // There is always exactly 1 king.
    pop_lsb(&mut bb)
}

#[inline]
fn step_ok(file: i8, rank: i8) -> bool {
    (0..8).contains(&file) && (0..8).contains(&rank)
}

#[inline]
fn sq_from_fr(file: i8, rank: i8) -> u8 {
    ((rank as u8) << 3) | (file as u8)
}

fn knight_attacks(sq: u8) -> u64 {
    let f = file_of(sq) as i8;
    let r = rank_of(sq) as i8;
    let deltas = [
        (1, 2),
        (2, 1),
        (2, -1),
        (1, -2),
        (-1, -2),
        (-2, -1),
        (-2, 1),
        (-1, 2),
    ];
    let mut a = 0u64;
    for (df, dr) in deltas {
        let nf = f + df;
        let nr = r + dr;
        if step_ok(nf, nr) {
            a |= sq_mask(sq_from_fr(nf, nr));
        }
    }
    a
}

fn king_attacks(sq: u8) -> u64 {
    let f = file_of(sq) as i8;
    let r = rank_of(sq) as i8;
    let mut a = 0u64;
    for dr in -1..=1 {
        for df in -1..=1 {
            if df == 0 && dr == 0 {
                continue;
            }
            let nf = f + df;
            let nr = r + dr;
            if step_ok(nf, nr) {
                a |= sq_mask(sq_from_fr(nf, nr));
            }
        }
    }
    a
}

fn ray_attacks(sq: u8, df: i8, dr: i8, occ: u64) -> u64 {
    let mut a = 0u64;
    let mut f = file_of(sq) as i8;
    let mut r = rank_of(sq) as i8;
    loop {
        f += df;
        r += dr;
        if !step_ok(f, r) {
            break;
        }
        let nsq = sq_from_fr(f, r);
        let m = sq_mask(nsq);
        a |= m;
        if (occ & m) != 0 {
            break;
        }
    }
    a
}

fn bishop_attacks(sq: u8, occ: u64) -> u64 {
    ray_attacks(sq, 1, 1, occ)
        | ray_attacks(sq, 1, -1, occ)
        | ray_attacks(sq, -1, 1, occ)
        | ray_attacks(sq, -1, -1, occ)
}

fn rook_attacks(sq: u8, occ: u64) -> u64 {
    ray_attacks(sq, 1, 0, occ)
        | ray_attacks(sq, -1, 0, occ)
        | ray_attacks(sq, 0, 1, occ)
        | ray_attacks(sq, 0, -1, occ)
}

fn queen_attacks(sq: u8, occ: u64) -> u64 {
    bishop_attacks(sq, occ) | rook_attacks(sq, occ)
}

fn pawn_attacks(sq: u8, color: u8) -> u64 {
    let f = file_of(sq) as i8;
    let r = rank_of(sq) as i8;
    let dr = if color == WHITE { 1 } else { -1 };
    let mut a = 0u64;
    for df in [-1, 1] {
        let nf = f + df;
        let nr = r + dr;
        if step_ok(nf, nr) {
            a |= sq_mask(sq_from_fr(nf, nr));
        }
    }
    a
}

pub fn is_square_attacked(bitboards: &[u64; 12], sq: u8, by_color: u8) -> bool {
    let occ = occ_all(bitboards);

    // Pawns
    {
        let mut pawns = bitboards[bb_idx(by_color, PIECE_PAWN)];
        while pawns != 0 {
            let psq = pop_lsb(&mut pawns);
            if (pawn_attacks(psq, by_color) & sq_mask(sq)) != 0 {
                return true;
            }
        }
    }

    // Knights
    if (knight_attacks(sq) & bitboards[bb_idx(by_color, PIECE_KNIGHT)]) != 0 {
        return true;
    }

    // Bishops / queens (diagonals)
    if (bishop_attacks(sq, occ)
        & (bitboards[bb_idx(by_color, PIECE_BISHOP)] | bitboards[bb_idx(by_color, PIECE_QUEEN)]))
        != 0
    {
        return true;
    }

    // Rooks / queens (files/ranks)
    if (rook_attacks(sq, occ)
        & (bitboards[bb_idx(by_color, PIECE_ROOK)] | bitboards[bb_idx(by_color, PIECE_QUEEN)]))
        != 0
    {
        return true;
    }

    // King
    if (king_attacks(sq) & bitboards[bb_idx(by_color, PIECE_KING)]) != 0 {
        return true;
    }

    false
}

pub fn in_check(bitboards: &[u64; 12], color: u8) -> bool {
    let ksq = king_sq(bitboards, color);
    let opp = if color == WHITE { BLACK } else { WHITE };
    is_square_attacked(bitboards, ksq, opp)
}

#[derive(Clone, Copy)]
pub struct CastleInfo {
    pub w_king_start: u8,
    pub w_rook_ks_start: u8,
    pub w_rook_qs_start: u8,
    pub b_king_start: u8,
    pub b_rook_ks_start: u8,
    pub b_rook_qs_start: u8,
}

#[derive(Clone, Copy)]
pub struct Board {
    pub bitboards: [u64; 12],
    pub side_to_move: u8,
    pub castling: u8,
    pub ep_square: u8, // 0..63 or EP_NONE
    pub halfmove_clock: u16,
    pub fullmove_number: u16,
}

impl Board {
    pub fn new_chess960(pos: u16) -> (Self, CastleInfo) {
        let back = chess960_backrank(pos);

        let mut bitboards = [0u64; 12];

        // White back rank (rank 1 == 0), pawns at rank 2 (1)
        for file in 0..8u8 {
            let sq = file; // rank 0
            place_piece(&mut bitboards, WHITE, back[file as usize], sq);
            place_piece(&mut bitboards, WHITE, PIECE_PAWN, 8 + file);
        }
        // Black back rank (rank 8 == 7), pawns at rank 7 (6)
        for file in 0..8u8 {
            let sq = 56 + file; // rank 7
            place_piece(&mut bitboards, BLACK, back[file as usize], sq);
            place_piece(&mut bitboards, BLACK, PIECE_PAWN, 48 + file);
        }

        // Identify castling rook start squares (Chess960-specific).
        let (w_king_start, w_rook_qs_start, w_rook_ks_start) = find_king_rooks_rank(&back, 0);
        let (b_king_start, b_rook_qs_start, b_rook_ks_start) = find_king_rooks_rank(&back, 7);

        let board = Board {
            bitboards,
            side_to_move: WHITE,
            castling: CASTLE_WK | CASTLE_WQ | CASTLE_BK | CASTLE_BQ,
            ep_square: EP_NONE,
            halfmove_clock: 0,
            fullmove_number: 1,
        };

        (
            board,
            CastleInfo {
                w_king_start,
                w_rook_ks_start,
                w_rook_qs_start,
                b_king_start,
                b_rook_ks_start,
                b_rook_qs_start,
            },
        )
    }
}

fn place_piece(bitboards: &mut [u64; 12], color: u8, piece: u8, sq: u8) {
    bitboards[bb_idx(color, piece)] |= sq_mask(sq);
}

fn remove_piece(bitboards: &mut [u64; 12], color: u8, piece: u8, sq: u8) {
    bitboards[bb_idx(color, piece)] &= !sq_mask(sq);
}

fn chess960_backrank(pos: u16) -> [u8; 8] {
    // Numbering scheme:
    // - 4 options for light-square bishop (b,d,f,h)  => pos % 4
    // - 4 options for dark-square bishop (a,c,e,g)   => (pos/4) % 4
    // - 6 options for queen among remaining squares  => (pos/16) % 6
    // - 10 options for 2 knights among 5 squares     => pos/96 (0..9), combinations (i<j)
    // Remaining 3 squares are always R, K, R (king between rooks).
    let pos = pos as u32;
    let b_light = (pos % 4) as u8;
    let b_dark = ((pos / 4) % 4) as u8;
    let q = ((pos / 16) % 6) as u8;
    let k = (pos / 96) as u8; // 0..9

    let mut slots = [0xFFu8; 8];
    // light squares on rank 1 are odd files; dark squares are even files.
    slots[(b_light * 2 + 1) as usize] = PIECE_BISHOP;
    slots[(b_dark * 2) as usize] = PIECE_BISHOP;

    // remaining squares list (sorted by file).
    let mut rem = [0u8; 8];
    let mut rem_len = 0usize;
    for i in 0..8u8 {
        if slots[i as usize] == 0xFF {
            rem[rem_len] = i;
            rem_len += 1;
        }
    }

    // place queen in q-th remaining
    let q_file = rem[q as usize];
    slots[q_file as usize] = PIECE_QUEEN;

    // rebuild remaining (now 5 squares)
    rem_len = 0;
    for i in 0..8u8 {
        if slots[i as usize] == 0xFF {
            rem[rem_len] = i;
            rem_len += 1;
        }
    }

    // select 2-square combination for knights (lexicographic combinations of indices).
    let mut idx = 0u8;
    let mut n1_file = 0u8;
    let mut n2_file = 0u8;
    for i in 0..rem_len {
        for j in (i + 1)..rem_len {
            if idx == k {
                n1_file = rem[i];
                n2_file = rem[j];
            }
            idx += 1;
        }
    }
    slots[n1_file as usize] = PIECE_KNIGHT;
    slots[n2_file as usize] = PIECE_KNIGHT;

    // remaining three are rook, king, rook with king in the middle by file order.
    let mut rem3 = [0u8; 3];
    let mut rr = 0usize;
    for i in 0..8u8 {
        if slots[i as usize] == 0xFF {
            rem3[rr] = i;
            rr += 1;
        }
    }
    rem3.sort();
    slots[rem3[0] as usize] = PIECE_ROOK;
    slots[rem3[1] as usize] = PIECE_KING;
    slots[rem3[2] as usize] = PIECE_ROOK;

    let mut out = [0u8; 8];
    out.copy_from_slice(&slots);
    out
}

fn find_king_rooks_rank(back: &[u8; 8], rank: u8) -> (u8, u8, u8) {
    let mut kf: i8 = -1;
    let mut rooks = [0u8; 2];
    let mut rlen = 0usize;
    for file in 0..8u8 {
        match back[file as usize] {
            PIECE_KING => kf = file as i8,
            PIECE_ROOK => {
                rooks[rlen] = file;
                rlen += 1;
            }
            _ => {}
        }
    }
    // rook QS is left of king; KS right.
    let mut qs_file = 0u8;
    let mut ks_file = 0u8;
    for rf in rooks {
        if (rf as i8) < kf {
            qs_file = rf;
        } else {
            ks_file = rf;
        }
    }
    let king_sq = (rank * 8) + (kf as u8);
    let qs_sq = rank * 8 + qs_file;
    let ks_sq = rank * 8 + ks_file;
    (king_sq, qs_sq, ks_sq)
}

fn promo_piece(promo: u8) -> Option<u8> {
    match promo {
        PROMO_Q => Some(PIECE_QUEEN),
        PROMO_R => Some(PIECE_ROOK),
        PROMO_B => Some(PIECE_BISHOP),
        PROMO_N => Some(PIECE_KNIGHT),
        _ => None,
    }
}

fn between_squares(a: u8, b: u8) -> u64 {
    // squares strictly between a and b on same rank or file
    if a == b {
        return 0;
    }
    let af = file_of(a);
    let ar = rank_of(a);
    let bf = file_of(b);
    let br = rank_of(b);
    let mut mask = 0u64;
    if ar == br {
        let f1 = min(af, bf) + 1;
        let f2 = max(af, bf);
        for f in f1..f2 {
            mask |= sq_mask(ar * 8 + f);
        }
    } else if af == bf {
        let r1 = min(ar, br) + 1;
        let r2 = max(ar, br);
        for r in r1..r2 {
            mask |= sq_mask(r * 8 + af);
        }
    }
    mask
}

fn king_path_squares(from: u8, to: u8) -> u64 {
    // inclusive of destination, exclusive of from, along rank.
    let ar = rank_of(from);
    let af = file_of(from);
    let bf = file_of(to);
    let mut mask = 0u64;
    if ar != rank_of(to) {
        return 0;
    }
    if af < bf {
        for f in (af + 1)..=bf {
            mask |= sq_mask(ar * 8 + f);
        }
    } else {
        for f in (bf..af).rev() {
            mask |= sq_mask(ar * 8 + f);
        }
        mask |= sq_mask(ar * 8 + bf);
    }
    mask
}

pub fn apply_move(b: &mut Board, ci: CastleInfo, mv_u16: u16) -> ApplyResult {
    let mv = decode_move(mv_u16);
    if mv.from >= 64 || mv.to >= 64 {
        return ApplyResult::Illegal;
    }
    let side = b.side_to_move;
    let opp = if side == WHITE { BLACK } else { WHITE };

    let (pc_color, pc_kind) = match piece_at(&b.bitboards, mv.from) {
        Some(x) => x,
        None => return ApplyResult::Illegal,
    };
    if pc_color != side {
        return ApplyResult::Illegal;
    }

    // Only allow from==to as a Chess960 castling representation (king already on c/g file).
    if mv.from == mv.to {
        let r = rank_of(mv.from);
        let is_castle_dst = mv.to == (r * 8 + 2) || mv.to == (r * 8 + 6);
        if !(pc_kind == PIECE_KING && is_castle_dst) {
            return ApplyResult::Illegal;
        }
    }

    // Cannot capture own piece.
    if (occ_color(&b.bitboards, side) & sq_mask(mv.to)) != 0 {
        return ApplyResult::Illegal;
    }

    let mut capture = false;
    let mut pawn_move = false;

    // Copy bitboards for legality checking (king safety).
    let before = b.bitboards;

    // Remove moving piece from from-square now.
    remove_piece(&mut b.bitboards, side, pc_kind, mv.from);

    // Clear en passant by default; may be set by a double pawn push.
    let prev_ep = b.ep_square;
    b.ep_square = EP_NONE;

    // If destination occupied by opponent, capture it.
    if let Some((oc, ok)) = piece_at(&b.bitboards, mv.to) {
        if oc == opp {
            remove_piece(&mut b.bitboards, oc, ok, mv.to);
            capture = true;
            // Capturing a rook from its start square removes castling rights.
            b.castling = clear_castle_if_rook_captured(b.castling, ci, mv.to, oc);
        }
    }

    match pc_kind {
        PIECE_PAWN => {
            pawn_move = true;
            let dir: i8 = if side == WHITE { 1 } else { -1 };
            let from_f = file_of(mv.from) as i8;
            let from_r = rank_of(mv.from) as i8;
            let to_f = file_of(mv.to) as i8;
            let to_r = rank_of(mv.to) as i8;

            let dr = to_r - from_r;
            let df = to_f - from_f;

            let occ = occ_all(&b.bitboards);

            // En-passant capture.
            if (df.abs() == 1) && (dr == dir) && (mv.to == prev_ep) {
                // captured pawn is behind ep square.
                let cap_r = to_r - dir;
                if !step_ok(to_f, cap_r) {
                    return ApplyResult::Illegal;
                }
                let cap_sq = sq_from_fr(to_f, cap_r);
                // must be opponent pawn
                if (b.bitboards[bb_idx(opp, PIECE_PAWN)] & sq_mask(cap_sq)) == 0 {
                    return ApplyResult::Illegal;
                }
                remove_piece(&mut b.bitboards, opp, PIECE_PAWN, cap_sq);
                capture = true;
            } else if df == 0 && dr == dir {
                // single push must be empty
                if (occ & sq_mask(mv.to)) != 0 {
                    return ApplyResult::Illegal;
                }
            } else if df == 0 && dr == 2 * dir {
                // double push from start rank
                let start_rank = if side == WHITE { 1 } else { 6 };
                if from_r != start_rank {
                    return ApplyResult::Illegal;
                }
                // both squares must be empty
                let mid_r = from_r + dir;
                let mid_sq = sq_from_fr(from_f, mid_r);
                if (occ & (sq_mask(mid_sq) | sq_mask(mv.to))) != 0 {
                    return ApplyResult::Illegal;
                }
                // set ep square
                b.ep_square = mid_sq;
            } else if df.abs() == 1 && dr == dir {
                // normal capture requires opponent on destination.
                if !capture {
                    return ApplyResult::Illegal;
                }
            } else {
                return ApplyResult::Illegal;
            }

            // Promotion if reaching last rank.
            let last_rank = if side == WHITE { 7 } else { 0 };
            if to_r == last_rank {
                let promo = promo_piece(mv.promo).unwrap_or(PIECE_QUEEN);
                place_piece(&mut b.bitboards, side, promo, mv.to);
            } else {
                place_piece(&mut b.bitboards, side, PIECE_PAWN, mv.to);
            }
        }
        PIECE_KNIGHT => {
            if (knight_attacks(mv.from) & sq_mask(mv.to)) == 0 {
                return ApplyResult::Illegal;
            }
            place_piece(&mut b.bitboards, side, PIECE_KNIGHT, mv.to);
        }
        PIECE_BISHOP => {
            let occ = occ_all(&b.bitboards);
            if (bishop_attacks(mv.from, occ) & sq_mask(mv.to)) == 0 {
                return ApplyResult::Illegal;
            }
            place_piece(&mut b.bitboards, side, PIECE_BISHOP, mv.to);
        }
        PIECE_ROOK => {
            let occ = occ_all(&b.bitboards);
            if (rook_attacks(mv.from, occ) & sq_mask(mv.to)) == 0 {
                return ApplyResult::Illegal;
            }
            // Moving rook from its start square clears that castling right.
            b.castling = clear_castle_if_rook_moved(b.castling, ci, mv.from, side);
            place_piece(&mut b.bitboards, side, PIECE_ROOK, mv.to);
        }
        PIECE_QUEEN => {
            let occ = occ_all(&b.bitboards);
            if (queen_attacks(mv.from, occ) & sq_mask(mv.to)) == 0 {
                return ApplyResult::Illegal;
            }
            place_piece(&mut b.bitboards, side, PIECE_QUEEN, mv.to);
        }
        PIECE_KING => {
            // Castling is expressed as a king move to c-file or g-file on the same rank.
            let from_r = rank_of(mv.from);
            let to_r = rank_of(mv.to);
            if from_r == to_r && (mv.to == (from_r * 8 + 2) || mv.to == (from_r * 8 + 6)) {
                // attempt castle
                if !apply_castle(b, ci, side, mv.from, mv.to) {
                    return ApplyResult::Illegal;
                }
            } else {
                if (king_attacks(mv.from) & sq_mask(mv.to)) == 0 {
                    return ApplyResult::Illegal;
                }
                // Any king move clears both castling rights for that side.
                b.castling = clear_castle_if_king_moved(b.castling, side);
                place_piece(&mut b.bitboards, side, PIECE_KING, mv.to);
            }
        }
        _ => return ApplyResult::Illegal,
    }

    // Illegal if moving side leaves itself in check.
    if in_check(&b.bitboards, side) {
        b.bitboards = before;
        return ApplyResult::Illegal;
    }

    // Update halfmove clock (50-move rule).
    if pawn_move || capture {
        b.halfmove_clock = 0;
    } else {
        b.halfmove_clock = b.halfmove_clock.saturating_add(1);
    }

    // Side to move changes; fullmove increments after Black moves.
    if side == BLACK {
        b.fullmove_number = b.fullmove_number.saturating_add(1);
    }
    b.side_to_move = opp;

    ApplyResult::Ok { capture, pawn_move }
}

fn clear_castle_if_king_moved(castling: u8, color: u8) -> u8 {
    match color {
        WHITE => castling & !(CASTLE_WK | CASTLE_WQ),
        BLACK => castling & !(CASTLE_BK | CASTLE_BQ),
        _ => castling,
    }
}

fn clear_castle_if_rook_moved(castling: u8, ci: CastleInfo, from_sq: u8, color: u8) -> u8 {
    match color {
        WHITE => {
            let mut c = castling;
            if from_sq == ci.w_rook_ks_start {
                c &= !CASTLE_WK;
            }
            if from_sq == ci.w_rook_qs_start {
                c &= !CASTLE_WQ;
            }
            c
        }
        BLACK => {
            let mut c = castling;
            if from_sq == ci.b_rook_ks_start {
                c &= !CASTLE_BK;
            }
            if from_sq == ci.b_rook_qs_start {
                c &= !CASTLE_BQ;
            }
            c
        }
        _ => castling,
    }
}

fn clear_castle_if_rook_captured(
    castling: u8,
    ci: CastleInfo,
    to_sq: u8,
    captured_color: u8,
) -> u8 {
    // If a rook is captured on its original square, that castling right is lost.
    clear_castle_if_rook_moved(castling, ci, to_sq, captured_color)
}

fn apply_castle(b: &mut Board, ci: CastleInfo, color: u8, king_from: u8, king_to: u8) -> bool {
    // Determine side (K/Q) by destination file.
    let rank = rank_of(king_from);
    if rank != rank_of(king_to) {
        return false;
    }
    let is_kingside = file_of(king_to) == 6;

    // Determine rook start and rights.
    let (right_bit, rook_from_sq, rook_to_sq) = match (color, is_kingside) {
        (WHITE, true) => (CASTLE_WK, ci.w_rook_ks_start, rank * 8 + 5),
        (WHITE, false) => (CASTLE_WQ, ci.w_rook_qs_start, rank * 8 + 3),
        (BLACK, true) => (CASTLE_BK, ci.b_rook_ks_start, rank * 8 + 5),
        (BLACK, false) => (CASTLE_BQ, ci.b_rook_qs_start, rank * 8 + 3),
        _ => return false,
    };
    if (b.castling & right_bit) == 0 {
        return false;
    }

    // Must have rook on rook_from_sq.
    if (b.bitboards[bb_idx(color, PIECE_ROOK)] & sq_mask(rook_from_sq)) == 0 {
        return false;
    }
    // Must have king on king_from (already removed by caller, so check before removal isn't possible).
    // Instead, ensure caller passed the actual king_from by checking previous state via occupancy:
    // This function is called only from king move handling; that's sufficient.

    // Squares between king and rook must be empty (excluding endpoints).
    let between = between_squares(king_from, rook_from_sq);
    if (between & occ_all(&b.bitboards)) != 0 {
        return false;
    }

    // Destination squares must be empty unless occupied by the moving rook/king in Chess960 edge-cases.
    let occ_now = occ_all(&b.bitboards);
    let king_dest = king_to;
    if (occ_now & sq_mask(king_dest)) != 0 {
        return false;
    }
    if rook_to_sq != rook_from_sq && (occ_now & sq_mask(rook_to_sq)) != 0 {
        return false;
    }

    // King may not be in check, and may not pass through attacked squares.
    let opp = if color == WHITE { BLACK } else { WHITE };
    // Temporarily place king back on from square to check current check.
    place_piece(&mut b.bitboards, color, PIECE_KING, king_from);
    let in_chk_now = in_check(&b.bitboards, color);
    remove_piece(&mut b.bitboards, color, PIECE_KING, king_from);
    if in_chk_now {
        return false;
    }

    let path = king_path_squares(king_from, king_dest);
    // Check each square on path for attack by opponent (king treated as on that square).
    let mut mask = path;
    while mask != 0 {
        let sq = pop_lsb(&mut mask);
        // Place king on sq and check attack.
        place_piece(&mut b.bitboards, color, PIECE_KING, sq);
        let attacked = is_square_attacked(&b.bitboards, sq, opp);
        remove_piece(&mut b.bitboards, color, PIECE_KING, sq);
        if attacked {
            return false;
        }
    }

    // Perform castle: move king to destination, rook to destination.
    // Caller has already removed king from king_from.
    remove_piece(&mut b.bitboards, color, PIECE_ROOK, rook_from_sq);
    place_piece(&mut b.bitboards, color, PIECE_KING, king_dest);
    place_piece(&mut b.bitboards, color, PIECE_ROOK, rook_to_sq);

    // Clear castling rights for that side.
    b.castling = clear_castle_if_king_moved(b.castling, color);
    true
}

pub fn has_any_legal_move(b: &Board, ci: CastleInfo) -> bool {
    let side = b.side_to_move;
    let occ_side = occ_color(&b.bitboards, side);
    let occ = occ_all(&b.bitboards);

    // Iterate pieces and generate a limited set of pseudo-moves; apply and early-exit if legal.
    for piece in [
        PIECE_PAWN,
        PIECE_KNIGHT,
        PIECE_BISHOP,
        PIECE_ROOK,
        PIECE_QUEEN,
        PIECE_KING,
    ] {
        let mut bb = b.bitboards[bb_idx(side, piece)];
        while bb != 0 {
            let from = pop_lsb(&mut bb);
            let mut targets = 0u64;
            match piece {
                PIECE_PAWN => {
                    let dir: i8 = if side == WHITE { 1 } else { -1 };
                    let f = file_of(from) as i8;
                    let r = rank_of(from) as i8;
                    // captures
                    targets |= pawn_attacks(from, side)
                        & occ_color(&b.bitboards, if side == WHITE { BLACK } else { WHITE });
                    // en passant target square
                    if b.ep_square != EP_NONE
                        && (pawn_attacks(from, side) & sq_mask(b.ep_square)) != 0
                    {
                        targets |= sq_mask(b.ep_square);
                    }
                    // single push
                    let nr = r + dir;
                    if step_ok(f, nr) {
                        let to = sq_from_fr(f, nr);
                        if (occ & sq_mask(to)) == 0 {
                            targets |= sq_mask(to);
                            // double push
                            let start_rank = if side == WHITE { 1 } else { 6 };
                            if r == start_rank {
                                let nr2 = r + 2 * dir;
                                if step_ok(f, nr2) {
                                    let to2 = sq_from_fr(f, nr2);
                                    if (occ & sq_mask(to2)) == 0 {
                                        targets |= sq_mask(to2);
                                    }
                                }
                            }
                        }
                    }
                }
                PIECE_KNIGHT => targets = knight_attacks(from) & !occ_side,
                PIECE_BISHOP => targets = bishop_attacks(from, occ) & !occ_side,
                PIECE_ROOK => targets = rook_attacks(from, occ) & !occ_side,
                PIECE_QUEEN => targets = queen_attacks(from, occ) & !occ_side,
                PIECE_KING => {
                    targets = king_attacks(from) & !occ_side;
                    // also consider castling by attempting king-to g/c.
                    let rank = rank_of(from);
                    targets |= sq_mask(rank * 8 + 2);
                    targets |= sq_mask(rank * 8 + 6);
                }
                _ => {}
            }
            let mut t = targets;
            while t != 0 {
                let to = pop_lsb(&mut t);
                // promotions: try queen only (sufficient for existence of a legal move)
                let promo = if piece == PIECE_PAWN && (rank_of(to) == 0 || rank_of(to) == 7) {
                    PROMO_Q
                } else {
                    PROMO_NONE
                };
                let mv = encode_move(from, to, promo);
                let mut tmp = *b;
                let r = apply_move(&mut tmp, ci, mv);
                if matches!(r, ApplyResult::Ok { .. }) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn insufficient_material(bitboards: &[u64; 12]) -> bool {
    // Simplified sufficient conditions for dead positions:
    // - K vs K
    // - K+minor vs K
    // - K+B vs K+B with both bishops on same color
    let w_pawns = bitboards[bb_idx(WHITE, PIECE_PAWN)];
    let b_pawns = bitboards[bb_idx(BLACK, PIECE_PAWN)];
    let w_heavy = bitboards[bb_idx(WHITE, PIECE_ROOK)] | bitboards[bb_idx(WHITE, PIECE_QUEEN)];
    let b_heavy = bitboards[bb_idx(BLACK, PIECE_ROOK)] | bitboards[bb_idx(BLACK, PIECE_QUEEN)];
    if (w_pawns | b_pawns | w_heavy | b_heavy) != 0 {
        return false;
    }
    let w_minors = bitboards[bb_idx(WHITE, PIECE_BISHOP)] | bitboards[bb_idx(WHITE, PIECE_KNIGHT)];
    let b_minors = bitboards[bb_idx(BLACK, PIECE_BISHOP)] | bitboards[bb_idx(BLACK, PIECE_KNIGHT)];

    let w_minor_cnt = w_minors.count_ones();
    let b_minor_cnt = b_minors.count_ones();
    if w_minor_cnt == 0 && b_minor_cnt == 0 {
        return true;
    }
    if (w_minor_cnt == 1 && b_minor_cnt == 0) || (w_minor_cnt == 0 && b_minor_cnt == 1) {
        return true;
    }
    // Bishops same color only:
    if w_minor_cnt == 1
        && b_minor_cnt == 1
        && (bitboards[bb_idx(WHITE, PIECE_KNIGHT)] | bitboards[bb_idx(BLACK, PIECE_KNIGHT)]) == 0
    {
        // Compute bishop square parity by scanning bitboards directly:
        let w_b = bitboards[bb_idx(WHITE, PIECE_BISHOP)];
        let b_b = bitboards[bb_idx(BLACK, PIECE_BISHOP)];
        if w_b != 0 && b_b != 0 {
            let wsq = w_b.trailing_zeros() as u8;
            let bsq = b_b.trailing_zeros() as u8;
            let w_color = (file_of(wsq) + rank_of(wsq)) & 1;
            let b_color = (file_of(bsq) + rank_of(bsq)) & 1;
            return w_color == b_color;
        }
    }
    false
}

// ============================================================
// Position hashing (threefold repetition)
// ============================================================

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

pub fn position_hash(bitboards: &[u64; 12], side_to_move: u8, castling: u8, ep_square: u8) -> u64 {
    // Deterministic Zobrist-like hash derived from splitmix64(piece_id, square).
    // This is not cryptographic; collisions are extremely unlikely for practical play.
    let mut h = 0xcbf29ce484222325u64;
    for color in [WHITE, BLACK] {
        for piece in [
            PIECE_PAWN,
            PIECE_KNIGHT,
            PIECE_BISHOP,
            PIECE_ROOK,
            PIECE_QUEEN,
            PIECE_KING,
        ] {
            let mut bb = bitboards[bb_idx(color, piece)];
            let pid = (color as u64) * 6 + (piece as u64);
            while bb != 0 {
                let sq = pop_lsb(&mut bb) as u64;
                let x = (pid << 6) ^ sq;
                h ^= splitmix64(0xfeedfacedeadbeefu64 ^ x);
            }
        }
    }
    h ^= splitmix64(0xabad1deaa55aa55au64 ^ (side_to_move as u64));
    h ^= splitmix64(0x1234_5678_9abc_def0u64 ^ (castling as u64));
    if ep_square != EP_NONE {
        // Only file matters for repetition hashing, but including full square is fine.
        h ^= splitmix64(0x0ddc0ffeebadf00du64 ^ (ep_square as u64));
    }
    h
}
