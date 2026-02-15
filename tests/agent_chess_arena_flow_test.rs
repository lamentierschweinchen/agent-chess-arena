use multiversx_sc_scenario::{
    api::DebugApi, managed_address, managed_biguint, managed_buffer, rust_biguint,
    testing_framework::BlockchainStateWrapper,
};

use agent_chess_arena::AgentChessArena;
use sha2::{Digest, Sha256};

type ArenaContract = agent_chess_arena::ContractObj<DebugApi>;
type Address = multiversx_sc_scenario::multiversx_sc::types::heap::Address;
type ArenaScWrapper = multiversx_sc_scenario::testing_framework::ContractObjWrapper<
    ArenaContract,
    fn() -> ArenaContract,
>;
type Setup = (
    BlockchainStateWrapper,
    Address,
    Address,
    Address,
    ArenaScWrapper,
);

fn sha256_commitment(bid_black_time_seconds: u64, seed_u64: u64, salt: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(16 + salt.len());
    preimage.extend_from_slice(&bid_black_time_seconds.to_be_bytes());
    preimage.extend_from_slice(&seed_u64.to_be_bytes());
    preimage.extend_from_slice(salt);

    let digest = Sha256::digest(&preimage);
    digest.into()
}

fn setup() -> Setup {
    let mut b = BlockchainStateWrapper::new();

    // Keep balances within u64 for rust_biguint! convenience.
    let owner = b.create_user_account(&rust_biguint!(0));
    let operator = b.create_user_account(&rust_biguint!(0));
    let treasury = b.create_user_account(&rust_biguint!(0));

    let builder: fn() -> ArenaContract = agent_chess_arena::contract_obj::<DebugApi>;
    let sc = b.create_sc_account(
        &rust_biguint!(0),
        Some(&owner),
        builder,
        "output/agent-chess-arena.wasm",
    );

    b.set_block_timestamp(1_000);
    b.execute_tx(&owner, &sc, &rust_biguint!(0), |c| {
        c.init(
            managed_address!(&operator),
            managed_address!(&treasury),
            100, // 1%
            900,
            30,
            600,
            600,
            120,
            120,
            30,
        );
    })
    .assert_ok();

    (b, operator, treasury, owner, sc)
}

#[test]
fn draw_pays_black_and_fee_is_collected() {
    let (mut b, operator, treasury, _owner, sc) = setup();

    let alice = b.create_user_account(&rust_biguint!(10_000_000_000_000_000_000u64));
    let bob = b.create_user_account(&rust_biguint!(10_000_000_000_000_000_000u64));

    let stake = rust_biguint!(1_000_000_000_000_000_000u64);

    // Alice creates an open match.
    let mut match_id: u64 = 0;
    b.execute_tx(&alice, &sc, &stake, |c| {
        let zero = multiversx_sc::types::ManagedAddress::zero();
        match_id = c.create_match(zero, 300);
    })
    .assert_ok();
    assert_eq!(match_id, 1);

    // Bob joins.
    b.execute_tx(&bob, &sc, &stake, |c| {
        c.join_match(match_id);
    })
    .assert_ok();

    // Commit/reveal: Alice bids less, so she becomes Black (Armageddon draw odds).
    let bid_a = 60u64;
    let seed_a = 123u64;
    let salt_a = b"salt-a";
    let commit_a = sha256_commitment(bid_a, seed_a, salt_a);

    let bid_b = 90u64;
    let seed_b = 456u64;
    let salt_b = b"salt-b";
    let commit_b = sha256_commitment(bid_b, seed_b, salt_b);

    b.execute_tx(&alice, &sc, &rust_biguint!(0), |c| {
        c.commit_bid(match_id, managed_buffer!(commit_a.as_slice()));
    })
    .assert_ok();
    b.execute_tx(&bob, &sc, &rust_biguint!(0), |c| {
        c.commit_bid(match_id, managed_buffer!(commit_b.as_slice()));
    })
    .assert_ok();

    b.execute_tx(&alice, &sc, &rust_biguint!(0), |c| {
        c.reveal_bid(match_id, bid_a, seed_a, managed_buffer!(salt_a.as_slice()));
    })
    .assert_ok();
    b.execute_tx(&bob, &sc, &rust_biguint!(0), |c| {
        c.reveal_bid(match_id, bid_b, seed_b, managed_buffer!(salt_b.as_slice()));
    })
    .assert_ok();

    // Read match state (white/black assignments + start).
    b.execute_query(&sc, |c| {
        let m = c.get_match(match_id);
        assert!(m.status == agent_chess_arena::types::MatchStatus::InProgress);
        assert!(m.black == managed_address!(&alice));
        assert!(m.white == managed_address!(&bob));
        assert!(m.black_time_seconds == bid_a);
        assert!(m.white_time_seconds == 300);
        let expected_pos = ((seed_a ^ seed_b) % 960) as u16;
        assert!(m.chess960_pos == expected_pos);
    })
    .assert_ok();

    // Operator reports a draw; payout goes to Black.
    let pgn_hash = [7u8; 32];
    b.execute_tx(&operator, &sc, &rust_biguint!(0), |c| {
        c.report_result(
            match_id,
            agent_chess_arena::types::MatchResult::Draw,
            managed_buffer!(pgn_hash.as_slice()),
        );
    })
    .assert_ok();

    b.execute_query(&sc, |c| {
        let m2 = c.get_match(match_id);
        assert!(m2.status == agent_chess_arena::types::MatchStatus::Finished);
        assert!(m2.result == agent_chess_arena::types::MatchResult::Draw);
        assert!(m2.winner_paid == managed_address!(&alice));
        assert!(m2.fee_atto == managed_biguint!(20_000_000_000_000_000u64));
        assert!(m2.payout_atto == managed_biguint!(1_980_000_000_000_000_000u64));
    })
    .assert_ok();

    // Balance checks.
    let fee = rust_biguint!(20_000_000_000_000_000u64);

    // Alice ends at 10 + (payout - stake) = 10.98
    b.check_egld_balance(&alice, &rust_biguint!(10_980_000_000_000_000_000u64));
    // Bob loses stake.
    b.check_egld_balance(&bob, &rust_biguint!(9_000_000_000_000_000_000u64));
    b.check_egld_balance(&treasury, &fee);
    b.check_egld_balance(sc.address_ref(), &rust_biguint!(0));

    // Storage checks were asserted in the query above (avoid leaking managed values).
}

#[test]
fn forfeit_no_commit_awards_committer() {
    let (mut b, _operator, treasury, _owner, sc) = setup();

    let alice = b.create_user_account(&rust_biguint!(10_000_000_000_000_000_000u64));
    let bob = b.create_user_account(&rust_biguint!(10_000_000_000_000_000_000u64));
    let stake = rust_biguint!(1_000_000_000_000_000_000u64);

    let mut match_id: u64 = 0;
    b.execute_tx(&alice, &sc, &stake, |c| {
        let zero = multiversx_sc::types::ManagedAddress::zero();
        match_id = c.create_match(zero, 300);
    })
    .assert_ok();
    assert_eq!(match_id, 1);

    b.execute_tx(&bob, &sc, &stake, |c| {
        c.join_match(match_id);
    })
    .assert_ok();

    // Only Alice commits.
    let bid = 60u64;
    let seed = 1u64;
    let salt = b"only-alice";
    let commit = sha256_commitment(bid, seed, salt);
    b.execute_tx(&alice, &sc, &rust_biguint!(0), |c| {
        c.commit_bid(match_id, managed_buffer!(commit.as_slice()));
    })
    .assert_ok();

    // Advance time past commit deadline and claim forfeit.
    b.set_block_timestamp(1_000 + 120 + 1);
    b.execute_tx(&alice, &sc, &rust_biguint!(0), |c| {
        c.claim_forfeit_no_commit(match_id);
    })
    .assert_ok();

    // Alice receives payout (pot - fee).
    b.check_egld_balance(&alice, &rust_biguint!(10_980_000_000_000_000_000u64));
    b.check_egld_balance(&bob, &rust_biguint!(9_000_000_000_000_000_000u64));
    b.check_egld_balance(&treasury, &rust_biguint!(20_000_000_000_000_000u64));
    b.check_egld_balance(sc.address_ref(), &rust_biguint!(0));
}

#[test]
fn refund_after_deadline_returns_both_stakes_no_fee() {
    let (mut b, _operator, treasury, _owner, sc) = setup();

    let alice = b.create_user_account(&rust_biguint!(10_000_000_000_000_000_000u64));
    let bob = b.create_user_account(&rust_biguint!(10_000_000_000_000_000_000u64));
    let stake = rust_biguint!(1_000_000_000_000_000_000u64);

    let mut match_id: u64 = 0;
    b.execute_tx(&alice, &sc, &stake, |c| {
        let zero = multiversx_sc::types::ManagedAddress::zero();
        match_id = c.create_match(zero, 300);
    })
    .assert_ok();
    assert_eq!(match_id, 1);

    b.execute_tx(&bob, &sc, &stake, |c| {
        c.join_match(match_id);
    })
    .assert_ok();

    // Commit/reveal so the match starts.
    let bid_a = 60u64;
    let seed_a = 10u64;
    let salt_a = b"sa";
    let commit_a = sha256_commitment(bid_a, seed_a, salt_a);
    let bid_b = 90u64;
    let seed_b = 11u64;
    let salt_b = b"sb";
    let commit_b = sha256_commitment(bid_b, seed_b, salt_b);

    b.execute_tx(&alice, &sc, &rust_biguint!(0), |c| {
        c.commit_bid(match_id, managed_buffer!(commit_a.as_slice()));
    })
    .assert_ok();
    b.execute_tx(&bob, &sc, &rust_biguint!(0), |c| {
        c.commit_bid(match_id, managed_buffer!(commit_b.as_slice()));
    })
    .assert_ok();

    b.execute_tx(&alice, &sc, &rust_biguint!(0), |c| {
        c.reveal_bid(match_id, bid_a, seed_a, managed_buffer!(salt_a.as_slice()));
    })
    .assert_ok();
    b.execute_tx(&bob, &sc, &rust_biguint!(0), |c| {
        c.reveal_bid(match_id, bid_b, seed_b, managed_buffer!(salt_b.as_slice()));
    })
    .assert_ok();

    // Read deadline, then advance past it.
    let mut deadline: u64 = 0;
    b.execute_query(&sc, |c| {
        deadline = c.get_match(match_id).game_deadline_ts;
    })
    .assert_ok();
    b.set_block_timestamp(deadline + 1);

    // Anyone can call; use Bob.
    b.execute_tx(&bob, &sc, &rust_biguint!(0), |c| {
        c.claim_refund_after_deadline(match_id);
    })
    .assert_ok();

    // Both get stakes back, treasury gets nothing.
    b.check_egld_balance(&alice, &rust_biguint!(10_000_000_000_000_000_000u64));
    b.check_egld_balance(&bob, &rust_biguint!(10_000_000_000_000_000_000u64));
    b.check_egld_balance(&treasury, &rust_biguint!(0));
    b.check_egld_balance(sc.address_ref(), &rust_biguint!(0));
}
