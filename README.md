# sourceveil

A semantic-aware, source-to-source obfuscator for Rust/Tauri workspaces.

```
normal project source  ->  transformed copy of the project source
```

The output is still ordinary Rust, TypeScript and configuration. It is built by
the ordinary toolchain — `cargo`, `npm`, `vite`, `tauri` — with no modification
to rustc, LLVM, or the produced binary. The input tree is never written to.

The goal is narrow and specific: **raise the cost of static analysis by removing
stable, searchable business semantics from the source**, and make each release's
naming different from the last while keeping any single release reproducible.

## Guarantees

- **The input tree is never modified.** The transform copies first and edits the
  copy, so this holds by construction rather than by discipline.
- **The output is verified, not assumed to be correct.** The pipeline compiles
  what it produced before reporting success. A transform that breaks the build
  fails loudly instead of handing you a tree that does not compile.
- **Anything that cannot be proven safe is kept, and reported.** Every skipped
  symbol is recorded with a reason. Nothing is skipped silently.
- **Renames are resolved, not pattern-matched.** Each one goes through
  rust-analyzer's name resolution, which is what makes `obj.foo`, `"foo"`,
  `#[serde(rename = "foo")]` and `macro_rules! foo` different things.
- **Reproducible.** Same source plus same seed produces byte-identical output.

## Status

V1, at the prototype stage the design calls for. What is implemented:

| capability | state |
| --- | --- |
| project discovery via `cargo metadata` | done |
| output workspace copier | done |
| semantic symbol rename (fn, type, trait, enum, variant, const, static, module) | done |
| keep rules: config, globs, attributes, inline comments, FFI/ABI | done |
| deterministic and keyed build seeds | done |
| `mapping.json` / `report.json` | done |
| verification pipeline | done |
| Tauri IPC / event rename | not implemented — see below |
| serde-safe field rename | not implemented — see below |
| string protection | not implemented |
| TypeScript analyzer | not implemented |
| module file rename | not implemented |
| dependency wrappers, binary scanner | not implemented |

Unimplemented features are reported in the run output rather than ignored, and
where their absence would break something, the affected symbols are pinned:

- `#[tauri::command]` handlers are **kept**, so existing `invoke("...")` calls
  keep working.
- `#[serde(...)]`-attributed items are **kept**, so the wire format cannot drift.
- Module *identifiers* are renamed; module *files* are not, because
  rust-analyzer implements module rename as a file move and that is a separate
  pass with its own verification.

## Quick start

```bash
cargo build --release

./target/release/cargo-obfuscator transform \
    --input ./my-tauri-app \
    --output ./release-source \
    --seed auto
```

Then build the result the way you always would:

```bash
cd release-source
npm ci --prefix frontend && npm run build --prefix frontend
cd src-tauri && cargo build --release
```

`transform` refuses to write into a directory that already exists and is not
empty. Remove it first, or pass a fresh path.

### Commands

```bash
# What would this project do? Writes nothing.
cargo-obfuscator scan --input ./my-tauri-app

# Transform it.
cargo-obfuscator transform --input ./app --output ./out --config obfuscator.toml

# Re-run verification against an already-generated tree.
cargo-obfuscator verify --output ./out
```

Useful flags: `--seed <auto|random|hmac|u64>`, `--stage <name>` (repeatable),
`--no-verify`, `-v`.

## Configuration

See [`obfuscator.toml`](obfuscator.toml) — it is the schema, documented, with
every value at its default. Deleting it changes nothing.

Precedence is: explicit value > selected profile > built-in default.

### Keeping things

Four mechanisms, checked in this order:

```toml
[keep]
symbols = ["main"]             # exact names
patterns = ["ffi_*"]           # globs against the item name
files = ["src/generated/**"]   # whole files
attributes = ["tokio::main"]   # attribute paths
```

and, in the source itself:

```rust
// obfuscator:keep
fn special_function() {}

// obfuscator:keep-file
```

These are plain comments, deliberately, so adopting the tool does not mean
adding a dependency to your project's own build.

Always kept regardless of configuration: `main`, `#[no_mangle]`,
`#[export_name]`, `#[link_name]`, `#[macro_export]`, `#[proc_macro*]`,
`#[global_allocator]`, `#[panic_handler]`, declarations inside `extern` blocks,
and public items in a crate that anything outside the workspace depends on.

## Build diversification

```bash
--seed auto       # HMAC when OBFUSCATION_SEED_KEY is set, else OS entropy
--seed hmac       # require OBFUSCATION_SEED_KEY
--seed random     # OS entropy
--seed 123456     # explicit
```

The recommended CI setup keys the seed with a secret:

```
build_seed = HMAC-SHA256(OBFUSCATION_SEED_KEY, "<git-sha>:<release-tag>")
```

so that each release differs, any release can be rebuilt, and knowing the commit
SHA alone does not let anyone regenerate the mapping.

## Artifacts

```
.obfuscator/
├── mapping.json     original name -> replacement
├── report.json      what happened, and what was kept and why
└── seed-info.json   how the seed was derived (never the key)
```

`mapping.json` is the answer key — anyone holding it can read a stack trace from
a shipped build straight back to your source. The tool refuses to write it into
anything that looks shippable (`dist`, `build`, `bundle`, `resources`,
`public`, `target`, `node_modules`). Keep it as a private CI artifact.

## CI integration

The ordering matters: **run your quality gates against the original source
first**, then transform, then verify the generated tree, then build. Linting or
unit-testing the obfuscated tree gives you failures you cannot act on, because
the tree is generated.

```yaml
- name: Quality gate on the original source
  run: |
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --all
    npm ci --prefix frontend && npm run typecheck --prefix frontend

- name: Build obfuscator
  run: cargo build --release --manifest-path tools/obfuscator/Cargo.toml

- name: Generate protected workspace
  env:
    # Without this, `--seed auto` falls back to OS entropy: still different per
    # build, but no longer reproducible and no longer keyed to your secret.
    OBFUSCATION_SEED_KEY: ${{ secrets.OBFUSCATION_SEED_KEY }}
  run: |
    ./tools/obfuscator/target/release/cargo-obfuscator transform \
      --input . \
      --output .obfuscated \
      --config obfuscator.toml \
      --seed auto

# The transform verifies its own output. This step is the belt to that
# braces, run from the outside so a bug in the verifier cannot hide itself.
- name: Verify generated workspace
  run: |
    cd .obfuscated/src-tauri && cargo check --release --locked
    cd .. && npm ci --prefix frontend && npm run typecheck --prefix frontend

- name: Build
  working-directory: .obfuscated
  run: |
    npm ci --prefix frontend
    npm run build --prefix frontend
    cd src-tauri && cargo build --release

# Private artifact. This file maps every original name to its replacement:
# shipped publicly, it inverts the obfuscation entirely.
- name: Archive mapping
  uses: actions/upload-artifact@v4
  with:
    name: mapping-${{ github.ref_name }}
    path: .obfuscated/.obfuscator/
```

If the project generates an integrity manifest or resource checksums, run that
*after* the transform and *before* the Rust build. Generating it earlier means
hashing sources that are about to change.

## What this does not defend against

Being explicit, because a threat model that overclaims is worse than none:

- **Dynamic analysis.** A debugger attached to the process sees everything the
  process sees. Renaming raises the cost of *static* analysis. It does not stop
  anyone from setting a breakpoint.
- **Dependencies.** `tokio`, `reqwest` and `openssl` will still be visible in the
  binary. The interesting question is which of *your* functions calls them, and
  that is what this works on.
- **Control flow.** There is no VM, no control-flow flattening, no junk code, no
  opaque predicates. The default profile adds no runtime work to your program.

## Known limits, measured

This is the part worth reading before trusting the tool.

rust-analyzer's reference search **does not reach identifiers inside a macro
token tree**. Measured against `ra_ap_*` 0.0.352:

| call site in the source | rewritten by a rename? |
| --- | --- |
| `target_fn()` | yes |
| `apply_ident!(target_fn)` — ident argument to a `macro_rules!` macro | yes |
| `format!("{}", target_fn())` | **no** |
| `vec![target_fn(), target_fn()]` | **no** |
| `target_fn()` inside a `macro_rules!` body | **no** |
| `target_fn()` inside `#[cfg(test)]` | yes, the test cfg is enabled |
| `target_fn()` inside a `#[cfg(feature = "off")]` block | **no** |

`Analysis::find_all_refs` reports the same set as `Analysis::rename`, so there
is no second API to fall back on. The information is not available.

This is not a missed optimisation — it is a broken build waiting to happen.
Renaming `target_fn` while `format!("{}", target_fn())` stays put produces
source that does not compile.

Two defences:

1. Any symbol whose name occurs inside a macro token tree is **kept**, and
   reported as `macro-call-reference`. This over-keeps — `apply_ident!(target_fn)`
   would in fact have been renamed correctly — and that is the intended trade.
2. The verification pipeline compiles the generated tree, so anything the above
   misses is caught before you ship it.

The practical cost of (1) is real: on the fixture in this repository, 4 of 14
candidates are kept for this reason. A future pass can rewrite macro token trees
directly and recover them.

## Verification

Generation is not success. Every run ends by building what it produced:

```
cargo-metadata   cargo check --all-targets
npm ci           npm run typecheck      (skipped when absent)
npm run build    tauri build --no-bundle
leak-scan        greps the generated tree for the names it claims to have removed
```

`leak-scan` deliberately scans `frontend/dist`. Built frontend output is exactly
where a leaked identifier does the most damage, because it is what ships.

A project with no frontend, or without a `typecheck` script, passes those stages
with a note. A project without a `typecheck` script is not a project that failed
to typecheck.

## Development

The tool pins Rust 1.98 through `rust-toolchain.toml`, because rust-analyzer's
published crates track the rustc release cycle.

```bash
cargo test                      # unit + end-to-end
cargo clippy --all-targets
```

The end-to-end tests in `crates/sourceveil-cli/tests/e2e.rs` run the real binary
over `tests/fixtures/simple-rust` and finish with a real `cargo check`. They are
the only tests that can tell you the transform works; the unit tests only cover
the decisions leading up to it.

`sourceveil-core/Cargo.toml` carries one direct dependency it never calls:
`unicode-ident`, pinned to `=1.0.22`. `ra-ap-rustc_lexer` asserts at compile time
that `unicode-properties` and `unicode-ident` agree on a Unicode version;
`unicode-properties` has no release past 0.1.4 (Unicode 17) while `unicode-ident`
moved to Unicode 18 in 1.0.23. The pin is what keeps that assertion satisfied.
