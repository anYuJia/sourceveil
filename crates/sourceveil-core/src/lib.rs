//! # sourceveil
//!
//! A semantic-aware, source-to-source obfuscator for Rust/Tauri workspaces.
//!
//! The contract this crate implements:
//!
//! ```text
//! normal project source  ->  transformed copy of the project source
//! ```
//!
//! The output is still ordinary Rust, TypeScript and configuration. It is then
//! built by the ordinary toolchain — `cargo`, `npm`, `vite`, `tauri` — with no
//! modification to rustc, LLVM, or the produced binary. The input tree is never
//! written to.
//!
//! ## Design constraints
//!
//! The priority order is fixed and is not negotiable per-pass:
//!
//! ```text
//! correctness  >  build compatibility  >  runtime performance  >  obfuscation strength
//! ```
//!
//! Concretely that means: every rename is resolved through rust-analyzer's
//! name resolution rather than text matching; anything that cannot be proven
//! safe to transform is kept and reported; and the default profile adds no
//! runtime work to the program being protected.
//!
//! ## Module map
//!
//! - [`config`] — the `obfuscator.toml` schema.
//! - [`plan`] — resolution of config + profile into concrete pass settings.
//! - [`scanner`] — project discovery via `cargo metadata`.
//! - [`benchmark`] — reproducible baseline/transformed build measurements.
//! - [`copier`] — the output workspace copier.
//! - [`rust`] — the semantic analysis and rename passes.
//! - [`mapping`] / [`report`] — run artifacts.
//! - [`verify`] — the post-generation verification pipeline.

pub mod benchmark;
pub mod binary_scan;
pub mod config;
pub mod copier;
pub mod dependencies;
pub mod edits;
pub mod frontend;
pub mod mapping;
pub mod names;
pub mod pipeline;
pub mod plan;
pub mod report;
pub mod rng;
pub mod scanner;
pub mod seed;
pub mod serde;
pub mod strings;
pub mod tauri;
pub mod verify;

pub mod rust;
