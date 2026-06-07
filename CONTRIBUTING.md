# Contributing to Hyperion

Issues and PRs are welcome. Each crate has a single clear
responsibility and the codebase is structured so onboarding takes
an afternoon, not a week.

## Quick start

```bash
git clone https://github.com/nechodom/hyperion
cd hyperion
cargo build --release --workspace
cargo test --workspace
```

That's it. The dev path doesn't need root or a real Debian — see
[`docs/RUNBOOK.md`](docs/RUNBOOK.md#local-development) for a
local-dev setup with mock filesystem layout.

## Project layout

```
crates/
├── hyperion-types/        # newtype IDs + DTOs (no I/O)
├── hyperion-validate/     # Domain + SystemUserName parsers
├── hyperion-rpc/          # trait + wire types + codec
├── hyperion-rpc-server/   # Unix-socket server
├── hyperion-rpc-client/   # Unix-socket client
├── hyperion-state/        # SQLite + migrations + audit chain
├── hyperion-adapters/     # system tool wrappers
├── hyperion-core/         # orchestration + secrets + RealAdapter
└── hyperion-auth/         # argon2id + Ed25519 sessions + CSRF
bin/
├── hyperion-agent/        # privileged daemon
├── hyperion-web/          # axum admin UI
└── hctl/                  # CLI
```

The orchestrator lives in `hyperion-core/src/service.rs` — that's
where every public RPC method has its happy path + rollback. Big
file, but `grep "pub async fn"` gives you an index.

## House style

* **`#![forbid(unsafe_code)]`** in every crate.
* **Typed args, never strings.** Domains parse to `Domain`,
  hosting IDs are `HostingId(String)`, etc. — FK mix-ups become
  compile errors.
* **No shell interpolation.** Every system call is
  `Command::new("/usr/bin/foo").arg(...)` — never `sh -c`, never
  string-concatenate user input into a command line.
* **LIFO rollback** for any mutating operation. If step 3 fails,
  steps 2 and 1 must un-do themselves.
* **Audit log** every state change. The chain is BLAKE3-hashed;
  missing rows produce verifiable gaps.

## Adding a new system effect

The canonical recipe — follow it for nginx tweaks, PHP-FPM knobs,
new DB engines, etc.

1. **Adapter function** in `hyperion-adapters` — typed args, no
   shell interpolation. Returns `Result<T, AdapterError>`.
2. **Method on `AdapterPort`** in `hyperion-core` — mockable for
   unit tests.
3. **Orchestration** in `HostingService` with a rollback step
   pushed onto the LIFO stack if it mutates state.
4. **RPC variant** in `hyperion-rpc::codec` + handler in
   `AgentApi` + dispatch in `hyperion-rpc-server`.
5. **CLI subcommand** in `hctl` + UI handler + template in
   `hyperion-web` if user-facing.
6. **Tests at every layer.** Pure-logic ones unconditional; the
   rare integration test that wants `useradd` or `systemctl` gets
   `#[ignore]` and runs only on a real node.

## Multi-node specifically

* Per-hosting actions: read the hosting's `target_node` (via
  `find_hosting_anywhere`), pass it to
  `dispatcher::dispatch_to_node` — never go straight to the local
  socket from a per-hosting handler.
* Forms in the detail page get `target_node` injected as a hidden
  input by the JS shim at the bottom of `hostings_detail.html`.
  The matching `Form` struct just needs `target_node: String`.
* Any RPC the UI calls must be implementable on workers too — no
  master-only assumptions inside agent code.

## Commit messages

```
type(scope): short imperative summary

Optional body explaining WHY, not WHAT — the diff already shows
the what. Reference the issue or commit that triggered the work.
Mention any operator-facing behaviour change.

Co-Authored-By: …
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.
Scopes are the crate or feature name: `feat(jobs)`, `fix(rpc)`,
`docs(readme)`.

## Pull request flow

1. Open an issue or Discussion first if the change is
   non-trivial — saves both of us rebuild time if the design needs
   tweaking.
2. Branch from `main`, single-purpose PRs.
3. `cargo fmt --all` + `cargo clippy --workspace --all-targets`
   + `cargo test --workspace` must pass locally.
4. Mention any operator-facing change in the PR description —
   "operators will see X" is the audit trail for release notes.
5. Squash on merge; the title becomes the commit subject.

## What we say "no" to

* New shell scripts. Anything that touches the system goes through
  an adapter.
* Vendoring third-party PHP. Hyperion provisions PHP; it doesn't
  ship it.
* "Plugins" that load arbitrary code. The trust model is "operator
  trusts root on the box" — anything that widens that needs a real
  threat-model discussion first.
* Feature flags for half-built work. Land it complete or not at
  all; we keep the codebase ready-to-ship.

## Code of conduct

[Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be civil, assume good faith, ping the maintainer at
`hello@nechodom.dev` if anything goes sideways.
