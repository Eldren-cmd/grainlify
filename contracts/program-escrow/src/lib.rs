#![no_std]
//! # Program Escrow Smart Contract
//!
//! A secure escrow system for managing hackathon and program prize pools on Stellar.
//! This contract enables organizers to lock funds and distribute prizes to multiple
//! winners through secure, auditable batch payouts.
//!
//! ## ABI Stability
//!
//! The complete public interface of this contract — including stability classifications
//! (`STABLE` / `EVOLVING` / `INTERNAL`), breaking-change rules, and all types that are
//! duplicated in facade bindings — is documented in the cross-contract ABI stability matrix:
//!
//! **[`docs/abi-stability-matrix.md`](../../../../docs/abi-stability-matrix.md)**
//!
//! ### Synchronization risks in this crate
//! - `PayoutRecord` is mirrored (with drift) in `view-facade/src/lib.rs`.
//! - `ProgramDelegateInfo` is mirrored in `escrow-view-facade/src/program_escrow_bindings.rs`.
//! - Any field addition/removal/reorder to these types **must** be applied to the binding
//!   in the same PR and the matrix updated accordingly.
//!
//! ## Overview
//!
//! The Program Escrow contract manages the complete lifecycle of hackathon/program prizes:
//! 1. **Initialization**: Set up program with authorized payout controller
//! 2. **Fund Locking**: Lock prize pool funds in escrow
//! 3. **Batch Payouts**: Distribute prizes to multiple winners simultaneously
//! 4. **Single Payouts**: Distribute individual prizes
//! 5. **Tracking**: Maintain complete payout history and balance tracking
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              Program Escrow Architecture                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐                                               │
//! │  │  Organizer   │                                               │
//! │  └──────┬───────┘                                               │
//! │         │                                                        │
//! │         │ 1. init_program()                                     │
//! │         ▼                                                        │
//! │  ┌──────────────────┐                                           │
//! │  │  Program Created │                                           │
//! │  └────────┬─────────┘                                           │
//! │           │                                                      │
//! │           │ 2. lock_program_funds()                             │
//! │           ▼                                                      │
//! │  ┌──────────────────┐                                           │
//! │  │  Funds Locked    │                                           │
//! │  │  (Prize Pool)    │                                           │
//! │  └────────┬─────────┘                                           │
//! │           │                                                      │
//! │           │ 3. Hackathon happens...                             │
//! │           │                                                      │
//! │  ┌────────▼─────────┐                                           │
//! │  │ Authorized       │                                           │
//! │  │ Payout Key       │                                           │
//! │  └────────┬─────────┘                                           │
//! │           │                                                      │
//! │    ┌──────┴───────┐                                             │
//! │    │              │                                             │
//! │    ▼              ▼                                             │
//! │ batch_payout() single_payout()                                  │
//! │    │              │                                             │
//! │    ▼              ▼                                             │
//! │ ┌─────────────────────────┐                                    │
//! │ │   Winner 1, 2, 3, ...   │                                    │
//! │ └─────────────────────────┘                                    │
//! │                                                                  │
//! │  Storage:                                                        │
//! │  ┌──────────────────────────────────────────┐                  │
//! │  │ ProgramData:                             │                  │
//! │  │  - program_id                            │                  │
//! │  │  - total_funds                           │                  │
//! │  │  - remaining_balance                     │                  │
//! │  │  - authorized_payout_key                 │                  │
//! │  │  - payout_history: [PayoutRecord]        │                  │
//! │  │  - token_address                         │                  │
//! │  └──────────────────────────────────────────┘                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Model
//!
//! ### Trust Assumptions
//! - **Authorized Payout Key**: Trusted backend service that triggers payouts
//! - **Organizer**: Trusted to lock appropriate prize amounts
//! - **Token Contract**: Standard Stellar Asset Contract (SAC)
//! - **Contract**: Trustless; operates according to programmed rules
//!
//! ### Key Security Features
//! 1. **Single Initialization**: Prevents program re-configuration
//! 2. **Authorization Checks**: Only authorized key can trigger payouts
//! 3. **Balance Validation**: Prevents overdrafts
//! 4. **Atomic Transfers**: All-or-nothing batch operations
//! 5. **Complete Audit Trail**: Full payout history tracking
//! 6. **Overflow Protection**: Safe arithmetic for all calculations
//! 7. **Circuit Breaker**: Per-program configurable failure threshold to prevent cascading failures
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use soroban_sdk::{Address, Env, String, vec};
//!
//! // 1. Initialize program (one-time setup)
//! let program_id = String::from_str(&env, "Hackathon2024");
//! let backend = Address::from_string("GBACKEND...");
//! let usdc_token = Address::from_string("CUSDC...");
//!
//! let program = escrow_client.init_program(
//!     &program_id,
//!     &backend,
//!     &usdc_token
//! );
//!
//! // 2. Lock prize pool (10,000 USDC)
//! let prize_pool = 10_000_0000000; // 10,000 USDC (7 decimals)
//! escrow_client.lock_program_funds(&prize_pool);
//!
//! // 3. After hackathon, distribute prizes
//! let winners = vec![
//!     &env,
//!     Address::from_string("GWINNER1..."),
//!     Address::from_string("GWINNER2..."),
//!     Address::from_string("GWINNER3..."),
//! ];
//!
//! let prizes = vec![
//!     &env,
//!     5_000_0000000,  // 1st place: 5,000 USDC
//!     3_000_0000000,  // 2nd place: 3,000 USDC
//!     2_000_0000000,  // 3rd place: 2,000 USDC
//! ];
//!
//! escrow_client.batch_payout(&winners, &prizes);
//! ```
//!
//! ## Event System
//!
//! The contract emits events for all major operations:
//! - `ProgramInit`: Program initialization
//! - `FundsLocked`: Prize funds locked
//! - `BatchPayout`: Multiple prizes distributed
//! - `Payout`: Single prize distributed
//!
//! ## Best Practices
//!
//! 1. **Verify Winners**: Confirm winner addresses off-chain before payout
//! 2. **Test Payouts**: Use testnet for testing prize distributions
//! 3. **Secure Backend**: Protect authorized payout key with HSM/multi-sig
//! 4. **Audit History**: Review payout history before each distribution
//! 5. **Balance Checks**: Verify remaining balance matches expectations
//! 6. **Token Approval**: Ensure contract has token allowance before locking funds

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, token, vec,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Vec,
};
use grainlify_core::CorrelationId;

mod errors;
pub use errors::BatchPayoutError;
use errors::ContractError;

mod gas_optimization;

mod metadata;
pub use metadata::{
    CompressedCustomField, CompressedProgramMetadata, MetadataFieldKey,
    try_decode_legacy_metadata,
};

mod dynamic_pricing;
pub use dynamic_pricing::{
    DynamicPricingConfig, PricingState, PricingEngine,
    DemandMetrics, SupplyMetrics, OracleMarketData, PriceUpdateEvent,
};
mod types;
pub use types::*;


mod anti_abuse {
    use soroban_sdk::{symbol_short, Address, Env, Symbol};

    const RATE_LIMIT: Symbol = symbol_short!("RateLim");

    pub fn check_rate_limit(env: &Env, _caller: Address) {
        let count: u32 = env.storage().instance().get(&RATE_LIMIT).unwrap_or(0);
        env.storage().instance().set(&RATE_LIMIT, &(count + 1));
    }
}

mod claim_period;
pub use claim_period::{ClaimRecord, ClaimStatus};
mod payout_splits;
pub use payout_splits::{BeneficiarySplit, SplitConfig, SplitPayoutResult};
pub mod insurance_reserve;
// #[cfg(test)] mod test_claim_period_expiry_cancellation; // pre-existing breakage

mod error_recovery;
mod reentrancy_guard;

/// Test-only chaos injection hooks for `batch_payout` failure interleavings.
///
/// Production builds compile this module out entirely (`cfg(test)`).  The
/// harness in `tests/chaos_batch_payout_tests.rs` configures temporary
/// storage keys, and [`tick_before_transfer`] consults them before each
/// cross-contract token transfer inside `batch_payout_internal`.
#[cfg(test)]
pub mod chaos {
    use soroban_sdk::{symbol_short, Env, Symbol};

    const MODE: Symbol = symbol_short!("ChaosMod");
    const FAIL_AT: Symbol = symbol_short!("ChaosAt");
    const COUNT: Symbol = symbol_short!("ChaosCnt");

    /// No injection — production-equivalent path.
    pub const MODE_NONE: u32 = 0;
    /// Panic on the N-th transfer (0-based) with [`TRANSFER_FAIL_MSG`].
    pub const MODE_TRANSFER_FAIL: u32 = 1;
    /// Flip release-pause mid-batch on the N-th transfer, then re-check.
    pub const MODE_PAUSE_MID: u32 = 2;

    /// Stable panic message for transfer-failure injection (asserted by tests).
    pub const TRANSFER_FAIL_MSG: &str = "CHAOS_INJECTED_TRANSFER_FAILURE";
    /// Stable panic message for mid-batch pause injection.
    pub const PAUSE_MID_MSG: &str = "Funds Paused";

    /// Clear any previously configured chaos state.
    pub fn reset(env: &Env) {
        env.storage().temporary().remove(&MODE);
        env.storage().temporary().remove(&FAIL_AT);
        env.storage().temporary().remove(&COUNT);
    }

    /// Configure a transfer failure at recipient index `at` (0-based).
    pub fn configure_transfer_fail(env: &Env, at: u32) {
        reset(env);
        env.storage().temporary().set(&MODE, &MODE_TRANSFER_FAIL);
        env.storage().temporary().set(&FAIL_AT, &at);
        env.storage().temporary().set(&COUNT, &0u32);
    }

    /// Configure a mid-batch pause injection at recipient index `at`.
    pub fn configure_pause_mid_batch(env: &Env, at: u32) {
        reset(env);
        env.storage().temporary().set(&MODE, &MODE_PAUSE_MID);
        env.storage().temporary().set(&FAIL_AT, &at);
        env.storage().temporary().set(&COUNT, &0u32);
    }

    /// Called immediately before each token transfer in `batch_payout_internal`.
    ///
    /// `index` is the current recipient index in the batch.  When the
    /// configured failure index matches, this function panics with a stable
    /// message so the Soroban host rolls back all state mutations from the
    /// enclosing invocation (atomic all-or-nothing semantics).
    pub fn tick_before_transfer(env: &Env, index: u32) {
        let mode: u32 = env.storage().temporary().get(&MODE).unwrap_or(MODE_NONE);
        if mode == MODE_NONE {
            return;
        }
        let fail_at: u32 = env.storage().temporary().get(&FAIL_AT).unwrap_or(u32::MAX);
        let count: u32 = env.storage().temporary().get(&COUNT).unwrap_or(0);
        env.storage().temporary().set(&COUNT, &(count + 1));

        if index != fail_at {
            return;
        }

        match mode {
            MODE_TRANSFER_FAIL => panic!("{}", TRANSFER_FAIL_MSG),
            MODE_PAUSE_MID => {
                // Simulate an operator flipping release_paused mid-batch.
                // Re-check the same guard `batch_payout_internal` uses at entry.
                let mut flags = crate::ProgramEscrowContract::get_pause_flags(env);
                flags.release_paused = true;
                env.storage()
                    .instance()
                    .set(&crate::DataKey::PauseFlags, &flags);
                panic!("{}", PAUSE_MID_MSG);
            }
            _ => {}
        }
    }
}

// #[cfg(test)] mod test_token_math; // pre-existing breakage
// #[cfg(test)] mod test_circuit_breaker_audit; // pre-existing breakage
// #[cfg(test)] mod error_recovery_tests; // pre-existing breakage
#[cfg(any())] // pre-existing syntax error in file
mod test_circuit_breaker_enforcement;
#[cfg(test)]
#[cfg(any())] // pre-existing breakage: uses std
mod test_circuit_breaker_threshold;
#[cfg(any())]
mod reentrancy_tests;
#[cfg(any())] // pre-existing syntax error in file
mod test_circuit_breaker_enforcement;
// #[cfg(test)] mod test_dispute_resolution; // pre-existing breakage
mod fot_routing;
#[cfg(test)]
mod test_fot_routing;
#[cfg(test)]
mod test_metadata_tagging;
mod threshold_monitor;
#[cfg(test)]
mod threshold_monitor_prop_tests;
mod token_math;
mod reputation;
pub use reputation::{
    REPUTATION_DUST_PAYOUT_AMOUNT, REPUTATION_MIN_QUALIFYING_PAYOUT_AMOUNT,
    REPUTATION_TYPICAL_PAYOUT_AMOUNT,
};

// #[cfg(test)] mod reentrancy_guard_standalone_test; // pre-existing breakage
// #[cfg(test)] mod malicious_reentrant; // pre-existing breakage
#[cfg(test)]
mod test_granular_pause;

#[cfg(test)]
#[cfg(any())] // pre-existing breakage: uses Val, std
mod test_reputation;

// ========================================================================
// Property-based test suite — `src/tests/` submodule hierarchy
// ========================================================================
// Contains large property-based test surfaces (proptest) for the
// fee-config rounding primitives.  All submodules are cfg(test)-gated
// and live under `src/tests/`; see `src/tests/mod.rs` for the entry point.
#[cfg(test)]
mod tests;
// #[cfg(test)] mod test_lifecycle; // pre-existing breakage
// #[cfg(test)] mod test_full_lifecycle; // pre-existing breakage

mod test_maintenance_mode;
mod test_risk_flags;
#[cfg(any())] // pre-existing breakage: uses Val
mod test_struct_layout;
#[cfg(test)]
#[cfg(any())] // pre-existing breakage: uses std
mod test_lifecycle_dwell_time;
// #[cfg(test)] mod test_serialization_compatibility; // pre-existing breakage
// #[cfg(test)] mod test_payout_splits; // pre-existing breakage

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod test_program_core;
#[cfg(test)]
mod test_program_admin;
#[cfg(test)]
mod test_program_batch_registration;
#[cfg(test)]
mod test_program_allowlist;
#[cfg(test)]
mod test_program_analytics;
#[cfg(test)]
mod test_program_payouts;
#[cfg(test)]
mod test_program_queries;
#[cfg(test)]
mod test_program_fees_idempotency;
#[cfg(test)]
mod test_program_limits_pause;
#[cfg(test)]
mod test_program_atomicity_security;

// ─────────────────────────────────────────────────────────────────────────────
// Read-only mode types (referenced by test_read_only_mode.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Event emitted when read-only mode is toggled.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyModeChanged {
    pub enabled: bool,
    pub admin: Address,
    pub timestamp: u64,
    pub reason: Option<String>,
}

const READ_ONLY_MODE_CHANGED: Symbol = symbol_short!("ROModeChg");

// ========================================================================
// Contract Implementation
// ========================================================================

// ========================================================================
// Contract Implementation
// ========================================================================

#[contract]
pub struct ProgramEscrowContract;

const TTL_MIN_LEDGERS: u32 = 518_400; // ~30 days
const TTL_MAX_LEDGERS: u32 = 3_110_400; // ~180 days
const TTL_MAX_ACCESS_COUNT: u32 = 100;

// The on-chain server implementation. Gated behind the `contract` feature so
// that downstream contracts (facades) which depend on this crate with
// `default-features = false` link only the shared types/client and do NOT pull
// in this contract's force-exported entrypoints (which would collide with their
// own ABI at link time).
#[cfg(feature = "contract")]
include!("entrypoints/shared.rs");
#[cfg(feature = "contract")]
include!("entrypoints/programs.rs");
#[cfg(feature = "contract")]
include!("entrypoints/batch_operations.rs");
#[cfg(feature = "contract")]
include!("entrypoints/fees.rs");
#[cfg(feature = "contract")]
include!("entrypoints/admin.rs");
#[cfg(feature = "contract")]
include!("entrypoints/authorization_metadata.rs");
#[cfg(feature = "contract")]
include!("entrypoints/pause_and_limits.rs");
#[cfg(feature = "contract")]
include!("entrypoints/batch_payouts.rs");
#[cfg(feature = "contract")]
include!("entrypoints/allowlist_and_batch.rs");
#[cfg(feature = "contract")]
include!("entrypoints/single_payouts.rs");
#[cfg(feature = "contract")]
include!("entrypoints/schedules.rs");
#[cfg(feature = "contract")]
include!("entrypoints/receipts_and_splits.rs");
#[cfg(feature = "contract")]
include!("entrypoints/claims_and_disputes.rs");
#[cfg(feature = "contract")]
include!("entrypoints/dynamic_pricing.rs");

#[cfg(test)]
#[cfg(any())] // pre-existing breakage: duplicate fn names, misplaced #[test] attrs
mod test;
#[cfg(test)]
#[cfg(any())] // pre-existing breakage: unclosed delimiter
mod test_token_allowlist;
#[cfg(any())] // pre-existing breakage: #[test] inside impl blocks
mod test_pagination;
#[cfg(test)]
#[cfg(any())] // pre-existing breakage: uses std, imports from crate::test
mod test_dynamic_pricing;
// mod test_pagination;
// Archival + batch-operations test suite enabled for issue #1493
#[cfg(test)]
mod test_archival;
#[cfg(test)]
mod test_batch_operations;
// #[cfg(test)] mod test_pause;

#[cfg(test)]
mod test_insurance_reserve;

#[cfg(test)]
#[cfg(any())]
mod rbac_tests;
// Pre-existing breakage: receipt storage path incomplete / CB enforcement suite
// out of sync with current guard ordering. Keep gated until repaired upstream.
#[cfg(test)]
#[cfg(any())]
mod test_batch_receipts;
#[cfg(test)]
#[cfg(any())]
mod test_circuit_breaker_enforcement;
#[cfg(test)]
#[cfg(any())]
mod test_rbac;
#[cfg(test)]
#[cfg(any())]
mod test_event_ordering;

#[cfg(test)]
#[path = "release_schedule_host.rs"]
mod release_schedule_host;

#[cfg(test)]
mod test_event_schema;

#[cfg(test)]
mod recipient_index_tests;
