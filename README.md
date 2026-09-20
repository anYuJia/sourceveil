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
- **Renames are syntax/scope-aware, not text replacements.** Item renames use
  rust-analyzer; local/closure bindings use a lexical scope pass that also
  tracks supported standard macros and implicit format-string captures.
- **Reproducible.** Same source plus same seed produces byte-identical output.

## Status

V1, at the prototype stage the design calls for. What is implemented:

| capability | state |
| --- | --- |
| project discovery via `cargo metadata` | done |
| output workspace copier | done |
| semantic symbol rename (fn, type, trait, enum, variant, const, static, module) | done |
| Rust local-binding and parameter rename | done; enabled by `aggressive` |
| Closure binding rename | ordinary, move/async, nested, destructured and shadowed bindings; supported standard macros and format captures |
| Comment removal | opt-in `--strip-comments` / `[comments] strip = true` |
| keep rules: config, globs, attributes, inline comments, FFI/ABI | done |
| deterministic and keyed build seeds | done |
| `mapping.json` / `report.json` | done |
| verification pipeline | done |
| Tauri command rename (Rust + TypeScript + allow-lists) | done |
| Tauri event rename (Rust + TypeScript) | done |
| serde-safe field / enum-variant rename | done; wire names and Rust paths in documented serde metadata are preserved |
| proc-macro attribute contracts | `thiserror` named format captures follow field renames |
| runtime Rust string protection | done for safe runtime expressions and proven format-macro literal fragments; compile-time/opaque macro contexts are kept |
| TypeScript semantic private-binding rename | done — OXC scope-aware; properties/JSON keys/imports/exports are kept |
| module file rename | done (transactional file/dir moves; enabled by `aggressive`) |
| dependency boundary policy | done (external, private-obfuscate, obfuscate, wrapper) |
| reproducible build/size benchmark | done (cargo-obfuscator benchmark) |
| final binary leak scanner | done — raw UTF-8/UTF-16LE scan for original protocol values |

Unimplemented features are reported in the run output rather than ignored, and
where their absence would break something, the affected symbols are pinned:

- An event that reaches outside the workspace in either direction is
  **kept** — see below.
- Serde fields and variants are owned by a dedicated pass. Under `safe` they
  are kept. Under `balanced`/`aggressive`, members are renamed while their old
  serialize/deserialize names are materialised explicitly. Every documented
  serde container, variant and field attribute is parsed; Rust paths embedded
  in attribute strings are updated after item rename. Unknown future metadata
  is kept and reported instead of guessed at. Details below.
- Module *identifiers* are renamed by default. Physical module-file and
  directory moves are opt-in under `safe`/`balanced` and enabled by
  `aggressive`; they are staged transactionally with declaration edits, so a
  failed move aborts the plan.
- `aggressive` additionally renames Rust local bindings and parameters. Names
  required by traits, external APIs, macros, duplicate field spellings, or
  wire/framework protocols stay pinned and are listed in `report.json`.
- Dependencies are closed-world by explicit policy. external leaves a
  dependency untouched, private-obfuscate transforms only private items in a
  copied path dependency, obfuscate permits the full private dependency pass,
  and wrapper generates a private crate::sv_* boundary for semantically
  resolved calls without editing registry sources.
- Frontend binding renames use OXC's semantic graph. Private functions, classes,
  parameters and module-local constants may move. Object and destructuring
  shorthand is expanded so stable keys/React props stay unchanged while the
  lexical value is renamed; JSX component casing and TypeScript type-predicate
  parameter contracts are preserved. Member properties, imports/exports and
  dynamic `eval`/`with` scopes are kept.

### Serde-safe member renaming

A serde member is both a Rust identifier and a protocol value:

```rust
#[derive(Serialize, Deserialize)]
struct User {
    user_name: String,
}
```

Renaming only the Rust identifier changes the JSON key and still compiles. The
serde pass computes the original serialize and deserialize wire names *before*
the identifier moves, asks rust-analyzer for the semantic rename, and stages
that rename in the same transaction as an explicit wire contract:

```rust
#[derive(Serialize, Deserialize)]
struct X7Qp {
    #[serde(rename = "user_name")]
    m9_k: String,
}
```

The same mechanism covers enum variants, `rename_all`,
`rename_all_fields`, explicit `rename`, aliases, and externally/internally/
adjacently tagged enums. Serialize and deserialize names stay separate: a
directional contract such as

```rust
#[serde(rename(serialize = "outValue", deserialize = "in_value"))]
```

is never collapsed to one string.

The pass models the full documented serde attribute surface, including
`flatten`, `transparent`, `remote`, `untagged`, `other`, conversion containers,
all `skip*` forms, directional renames and bounds, `default = "path"`,
`with`/`serialize_with`/`deserialize_with`, `getter`, `crate`, `borrow`, and
identifier representations. Attributes that embed Rust paths are rewritten to
the generated names while wire strings remain unchanged. Only an unknown
future serde key, an unprovable non-serde derive, an external API boundary, or
an ambiguous compiler identity causes a member to be kept.

The same post-rename contract layer updates named field captures in proven
`thiserror::Error` attributes, so `#[error("{code}: {message}")]` continues to
refer to the renamed fields. Explicit custom format arguments are distinguished
from implicit field captures and remain unchanged.

`tests/fixtures/serde-safety` is an executable protocol corpus. The end-to-end
tests run the original and transformed crates, compare actual serde output byte
for byte, and feed old payloads back through the transformed build. The fixture
also contains an unsupported transparent representation to prove that the pass
can mix renamed and pinned members in one project.

### Tauri commands are one protocol across four places

A command's name is not just a Rust identifier. It is simultaneously:

```text
Rust definition          #[tauri::command] async fn get_user_info()
registration             tauri::generate_handler![commands::get_user_info]
frontend call            invoke("get_user_info")
Rust dispatch            match invoke.message.command() { "get_user_info" => .. }
Rust allow-list          const ALLOWED: &[&str] = &["get_user_info"];
```

Renaming three of the four leaves a project that either does not compile or —
worse — compiles, starts, and silently refuses every call to that command. So
they are changed as one transaction, and any doubt keeps the command whole:

| situation | what happens |
| --- | --- |
| `invoke("get_user_info")` | renamed, both sides |
| `invoke<Response>("activate_license")` | renamed |
| `const CMD = "sync_state"; invoke(CMD)` | renamed, if every use of `CMD` is an `invoke` argument |
| `call("ping")` where `call` is a project wrapper | renamed |
| `invoke(commandName)` | **every command is kept**, with the file and line reported |
| `#[command]` that resolves to clap | kept |
| a name that also appears as a Rust string outside a recognised context | kept |
| original bytes also occur in a retained source/dependency substring | kept and reported; a raw final-binary scan could not prove provenance |

Tauri command argument names are also treated as wire-format keys. The command
macro may embed those bytes in generated dispatch code, so they cannot receive
a global plaintext-absence promise. Independent safe runtime occurrences with
the same spelling (for example an HTTP/query key) are still protected.

The `generate_handler!` list is parsed by hand, because rust-analyzer's
reference search does not reach inside a macro token tree. Only the spans of the
names it recognises are rewritten; nothing else in the token tree is touched.

The short form `#[command]` is accepted only when name resolution lands in the
`tauri-macros` crate, so a clap `#[command]` is never mistaken for one.

`tests/fixtures/tauri-ipc-static` and `tests/fixtures/tauri-ipc-dynamic` are
real Tauri 2 projects — the real crate, the real macros, the real invoke
protocol — built with `default-features = false, features = ["test"]` so they
compile on Linux without webkit2gtk. The static one renames four commands and
checks that the Rust handler list and the *shipped* frontend bundle name exactly
the same set. The dynamic one contains a single `invoke(\`${prefix}_${action}\`)`
and checks that nothing is renamed.

### Events are only renamed when the graph is closed

A command has a registry: `generate_handler!` lists every one, so the set is
knowable. An event has nothing like that. A name can be emitted in Rust,
listened for in TypeScript, relayed back to another window, or produced by a
plugin this tool never sees:

```text
Rust      -> Frontend        app.emit("download-progress", ..)
Frontend  -> Rust            listen("download-progress", ..)
Frontend  -> Frontend        emit(..) / listen(..)
Rust      -> Rust            emit(..) / listen(..)
```

So a rename happens only when at least one producer *and* at least one consumer
are inside the generated workspace. An event with only a listener may be fed by
a plugin; one with only a producer may be consumed by a page this tool cannot
see. Both stay, and the report says which and why.

| situation | what happens |
| --- | --- |
| Rust `emit` and frontend `listen` | renamed, both sides |
| frontend `emit` and Rust `listen` | renamed, both sides |
| Rust `emit` and Rust `listen` | renamed |
| frontend `emit` and frontend `listen` | renamed |
| `win.emit(..)` from `getCurrentWebviewWindow()` | renamed |
| `emitTo("main", "x", ..)` | renamed; the label is left alone |
| a listener with no producer | **kept** — `external-event-source` |
| a producer with no listener | **kept** — `external-event-consumer` |
| `tauri://window-created` | **kept** — `framework-event` |
| `invoke(name)` / `listen(name, ..)` | **every event is kept**, with file and line |

Two things make this safe to run on a real project.

**Provenance is not optional.** `emit`, `listen` and `once` are ordinary names —
socket.io, Node's `EventEmitter` and half the DOM use them. A call is considered
only when its callee traces back to `@tauri-apps/api/event` through an import in
the same file, including aliased and namespace imports and a receiver bound from
`getCurrentWebviewWindow()`. The Rust side resolves the method through the
compiler and requires it to come from the `tauri` crate. Both fixtures contain a
`socket.emit(..)`, an `emitter.once(..)` and a Rust local bus with its own
`emit`, and none of them is touched.

**A runtime-computed name keeps everything.** `listen(eventName, ..)` could be
any event, so one of them keeps the whole namespace, and the report names the
file and line in both languages.

`tests/fixtures/tauri-events-static` covers every call shape on both sides plus
the decoys; `tauri-events-dynamic` adds one dynamic name per language and checks
that nothing is renamed.

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

# Inspect the final PE/ELF/Mach-O for original command/event/string values.
cargo-obfuscator scan-binary \
  --binary ./target/release/my-app \
  --mapping ./out/.obfuscator/mapping.json

# Compare baseline and transformed release builds, source/binary sizes, and
# cold-start samples. The output directory must be fresh.
cargo-obfuscator benchmark \
  --input ./my-tauri-app \
  --output ./benchmark-generated \
  --iterations 5
```

Useful flags: `--seed <auto|random|hmac|u64>`, `--stage <name>` (repeatable),
`--no-verify`, `-v`.

## Configuration

See [`obfuscator.toml`](obfuscator.toml) — it is the schema, documented, with
every value at its default. Deleting it changes nothing.

Precedence is: explicit value > selected profile > built-in default.

### Dependency boundaries

Workspace members are part of the closed world and are transformed together.
Dependencies outside that workspace default to `external`: their source and
public names are left alone. Path dependencies can be included explicitly with
`private-obfuscate` or `obfuscate`. The `wrapper` mode
leaves the dependency itself untouched and generates a private
`crate::sv_*` module in the root crate; only rust-analyzer-resolved
crate-root references are routed through that boundary. Package names accept
either Cargo's hyphenated spelling or the underscore alias used in Rust source.

```toml
[dependencies]
default = "external"
helper-lib = "wrapper"
```

### Closures and comments

`aggressive` enables `[rename] locals = true` and `params = true`. The binding
pass handles all parsed Rust closures, not a list of variable names: parameters,
locals, captures, nested scopes, tuple/record/reference/array patterns, `move`
and `async` closures. Standard formatting macros (including `{name}`,
`{name:width$.precision$}`), `vec!`, `dbg!`, `matches!` (including guards), `log`/`anyhow` formatting macros,
and `serde_json::json!` values are traversed too. Unknown or shadowed macros are
opaque syntax. With the normal `cargo-check` verification stage enabled, exact
missing field/method/path references are completed from rustc diagnostics only
when the mapping is unambiguous; without that stage, affected names are
retained. Macro-generated identifiers that do not exist in source remain
outside the rename surface.
Attribute-driven function parameters such as Tauri command arguments retain
their protocol names; closures inside those functions are still processed.

To remove comments from the generated directory:

```bash
cargo obfuscator transform --input ./project --output ./obfuscated --config ./obfuscator.toml --strip-comments
```

Or configure it persistently (off by default):

```toml
[comments]
strip = true
```

Supported files: Rust (including doc comments), JS/JSX/TS/TSX, CSS, HTML (also
inline JS/CSS), TOML (including Cargo.lock) and JSONC. Strings, URLs, regex literals and executable
shebangs are preserved. TypeScript triple-slash compiler references are
preserved because they are build directives rather than removable prose.
`target`, `node_modules`, `.git`, and `.obfuscator` are
excluded; unsupported comment-bearing formats are reported as warnings.
Keep markers are consumed before cleaning. Removal runs again after each
verification stage to clean generated assets; report file counters count visits
across those passes. Removing tool-directive comments (for example `@ts-ignore`)
can change build behavior, so verify the output. License/attribution comments
are moved to `SOURCEVEIL_NOTICES.txt`; license files are retained. Input files
are never modified.

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

## Final binary scan

Source-level verification is necessary but not sufficient: the optimizer,
framework glue or generated code can still leave protocol values in the final
artifact. `scan-binary` searches the shipped bytes directly for every original
Tauri command/event/protected-string value in `mapping.json`, in both UTF-8
and UTF-16LE. Those hits fail the strict scan, even when a dependency or an
unrelated substring contains the same spelling (for example, `open_file` in a
dependency source path). A raw match does not establish provenance; inspect
the offsets and surrounding bytes instead of treating it as proof that a
particular call site was missed. Hits are never silently excluded.
Original Rust symbol names are weaker
evidence and are reported only as notes, because the same word can survive
legitimately in third-party code, comments embedded in debug data or unrelated
APIs.

The scan is format-agnostic and read-only, so the same command works for PE,
ELF, Mach-O, static libraries and sidecar blobs.

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
  run: cargo build --release --locked --bin cargo-obfuscator

- name: Generate protected workspace
  env:
    # Without this, `--seed auto` falls back to OS entropy: still different per
    # build, but no longer reproducible and no longer keyed to your secret.
    OBFUSCATION_SEED_KEY: ${{ secrets.OBFUSCATION_SEED_KEY }}
  run: |
    ./target/release/cargo-obfuscator transform \
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

### Building the CLI with GitHub Actions

`.github/workflows/ci.yml` runs the full quality gate on Linux, macOS and
Windows and uploads a Linux CLI artifact. `.github/workflows/release.yml`
builds platform archives for all three systems when you push a `v*` tag, and
publishes a GitHub Release automatically. It can also be started manually from
the Actions tab; a manual run produces downloadable artifacts without creating
a release.

For example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Runtime string protection

Under `balanced`, machine-like internal literals such as
`"license-check"`, `"device-validation"` and `"HOLE_PUNCH_REQUEST"` are
selected by default. `[strings] all = true` selects every non-empty runtime
literal, including plain words, HTTP header names and values, MIME strings,
short values and raw regex literals; `aggressive` enables this mode by default.
Each safe occurrence is removed from Rust's static plaintext tables and gets a
build-specific HMAC-derived stream seed and encoded bytes. The generated
expression lazily decodes once into a block-local `OnceLock<String>` and still
evaluates to `&'static str`.

Format strings are handled without violating Rust's compile-time-literal rule.
For proven formatting macros (`format!`, `format_args!`, the
`print!`/`write!`, panic/assert, `anyhow!`/`bail!`/`ensure!` families, and
explicitly qualified `log::...!` macros), each selected literal text fragment
becomes a generated named argument that decodes at runtime. The original
placeholders and their formatting specifications stay in the literal
unchanged, including explicit positions, named captures, dynamic
width/precision and escaped braces. Ordinary string expression arguments in
those macros, `vec!`, and `dbg!` are protected too. The pass also finds nested
formatting macros inside proven expression containers such as `vec!` and
`serde_json::json!`. Shadowed macros and unknown macro DSLs fail closed.

Protection is deliberately not applied to attributes, opaque macro token
trees, const/static initialisers, patterns, ABI strings, const functions or
`no_std` crates. These are reported as retained unsafe occurrences. Importantly,
one retained occurrence no longer prevents safe runtime occurrences with the
same value from being encoded.

Tauri command/event and serde wire strings remain owned by their dedicated
cross-language passes. A runtime occurrence with the same spelling is still
encoded, but the value is recorded in `mapping.strings` only when no retained
Rust/frontend/config/protocol/dependency collision is known. Values shorter
than four bytes and generic values selected solely by `all` (for example
`"navigate"`) are protected but intentionally omitted from the global mapping:
a raw final binary can independently contain those bytes in toolchain or
platform-library data. Resolved dependency sources and compiled dependency
library artifacts are checked too; the latter catches values reconstructed
from numeric byte tables (for example a compression dictionary) that never
appear verbatim in source. Source/binary leak scans can therefore treat every
mapped plaintext as fatal evidence.

The encoding is obfuscation, not a secret store: the client ships both encoded
bytes and a decoder. The goal is to remove the static `strings -> XREF`
shortcut while keeping the hot-path cost to one lazy decode per literal.

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

rust-analyzer's reference search does not reach every identifier inside a macro
token tree or an inactive target-specific `#[cfg]` branch. Measured against
`ra_ap_*` 0.0.352, the raw semantic rename behaves like this:

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
is no second rust-analyzer API to fall back on. SourceVeil closes those gaps in
layers rather than using global replacement:

1. Its syntax pass rewrites bindings and references in supported standard
   macro grammars, nested token trees, implicit format captures, and module
   paths. Tokens are classified by role, so a field named `downloader` is not
   confused with a module of the same name.
2. Items that exist only below a direct `#[cfg(...)]` are handled by a
   kind-shaped, conflict-checked fallback confined to cfg syntax. Same-spelled
   identifiers in active code are not touched.
3. When `cargo-check` verification is selected, the generated tree is compiled
   in a bounded feedback loop. Only rustc's primary spans for missing
   field/method/path diagnostics can be repaired, and only when one exact old
   identifier maps to one generated identifier. Every repair is followed by a
   fresh compiler run; at most six passes are attempted.
4. Without compiler verification, opaque macro references are kept and
   reported as `macro-call-reference`. With verification, an unrepaired or
   ambiguous reference still fails the transform rather than being guessed at.

This covers ordinary macro shells and proc-macro-generated wrapper access while
preserving the central invariant: SourceVeil never performs an unrestricted
project-wide identifier replacement.

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
over the fixtures in `tests/fixtures/` and finish with a real `cargo check`. They
are the only tests that can tell you the transform works; the unit tests only
cover the decisions leading up to it. `simple-rust` covers the rename surface —
cross-file references, FFI, keep rules, determinism. `serde-safety` runs the
fixture before and after the transform and compares serialized output.

`sourceveil-core/Cargo.toml` carries one direct dependency it never calls:
`unicode-ident`, pinned to `=1.0.22`. `ra-ap-rustc_lexer` asserts at compile time
that `unicode-properties` and `unicode-ident` agree on a Unicode version;
`unicode-properties` has no release past 0.1.4 (Unicode 17) while `unicode-ident`
moved to Unicode 18 in 1.0.23. The pin is what keeps that assertion satisfied.
