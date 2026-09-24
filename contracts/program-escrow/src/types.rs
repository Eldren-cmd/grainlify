//! Domain types, event symbols, storage keys, and constants for the program
//! escrow contract.
//!
//! Extracted from `lib.rs` to keep the root module focused on the
//! `#[contractimpl]` block while preserving the exact same public API.

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Env, String, Symbol, Vec};
use grainlify_core::CorrelationId;



include!("types_parts/events_and_core.rs");
include!("types_parts/idempotency_and_configuration.rs");
include!("types_parts/pause_and_storage.rs");
