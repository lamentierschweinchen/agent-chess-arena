fn main() {
    // multiversx-sc-meta-lib uses paths relative to the meta crate directory.
    // `cargo run --manifest-path meta/Cargo.toml` keeps the caller's cwd, so
    // normalize to the meta crate directory to make the README commands work.
    std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"))
        .expect("chdir to meta crate dir failed");
    multiversx_sc_meta_lib::cli_main::<agent_chess_arena::AbiProvider>();
}
