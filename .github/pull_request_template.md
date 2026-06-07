## What

<!-- One-paragraph summary of the change. Operator-facing? CI?
     Refactor? Bug fix? Reference the issue if there is one. -->

## Why

<!-- The motivation. The diff already shows the WHAT — explain
     the WHY here. -->

## Operator-facing change?

<!-- Yes / No. If yes, one bullet per UI / CLI / config knob that
     changed. These show up in the release notes verbatim. -->

- [ ] No operator-facing change.
- [ ] Operator-facing change — described below:

## Test plan

<!-- How did you verify this works? -->

- [ ] `cargo test --workspace` passes.
- [ ] `cargo clippy --workspace --all-targets` passes (no new warnings).
- [ ] `cargo fmt --all -- --check` passes.
- [ ] Manually tested on a real Debian node (when applicable).
- [ ] Added / updated tests covering the change.

## Anti-scope

<!-- Optional but appreciated. What did you DELIBERATELY not change
     in this PR? Helps reviewers calibrate expectations. -->
