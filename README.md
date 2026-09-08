# Braid

**Find the hot ledger entry that is capping your Soroban contract's throughput.**

Protocol 23 executes Soroban transactions in parallel, clustering them by their declared
footprints ([CAP-0063](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0063.md)).
Two transactions that share a ledger entry, where at least one writes it, cannot run at
the same time.

So a single innocuous design choice silently caps your contract's throughput. A counter
used to mint ids. One aggregate holding total supply. A per-user balance that happens to
live in instance storage. Your tests pass, your resource costs look fine, and you find out
from throughput numbers in production — if you find out at all.

Braid reads your contract source and tells you before you deploy.

```console
$ braid analyze contracts/registry

critical contracts/registry/src/lib.rs:37:36  in create_job()
         writes the fixed key `DataKey::Seq` — every caller reaching `create_job`
         touches this same ledger entry

warning  contracts/registry/src/lib.rs:40:36  in create_job()
         `DataKey::Job(id)` looks parameterised, but its identifier was minted from
         `DataKey::Seq` — every caller serialises on that counter

Entry points that cannot run in parallel
  create_job <-> get_job   sequence-derived key `DataKey::Job`
```

## Why this tool can only exist on Soroban

Two Soroban design decisions with no EVM analogue:

- **Footprints are declared, not discovered.** A Soroban transaction states which ledger
  entries it will touch before it executes. That is exactly the information the analysis
  needs, available without running anything.
- **Parallelism is footprint-derived.** Conflict is decided by declared footprints rather
  than observed optimistically at runtime, which makes it a *static property of the
  contract's storage design* — analysable ahead of time, and fixable by changing keys.

On EVM, state access is dynamic and parallelism is optimistic, so the equivalent analysis
is undecidable in general.

## The four key classes

| Class | Example | Parallel-safe? |
| --- | --- | --- |
| **static** | `DataKey::Admin` | No, if written. Every caller touches one entry. |
| **subject-derived** | `DataKey::Balance(addr)` | Yes. Different callers, different entries. |
| **sequence-derived** | `DataKey::Job(id)` where `id` came from `DataKey::Seq` | **No — and this is the trap.** The key looks parameterised, but minting the id read and bumped a shared counter. |
| **unresolvable** | anything Braid cannot follow | Unknown, reported as unknown. Never assumed safe. |

There is a fifth rule that catches people out and does not fit the table: **everything in
`instance()` storage lives in one ledger entry.** A per-address key in instance storage is
not parallel-safe, because the address never separated anything. Braid reports that as
critical, and it is the finding most likely to be new information.

## Install

```sh
cargo install --path crates/braid-cli
# or, from a clone:
cargo build --release && ./target/release/braid --help
```

## Use

```sh
braid analyze .                          # human-readable report
braid analyze . --quiet                  # hide info findings
braid analyze . --format json            # stable machine output, schema v1
braid analyze . --format html -o out.html  # self-contained interactive report
braid analyze . --fail-on critical       # exit 1 when it matters, for CI
```

`--fail-on` accepts `critical`, `warning`, `info`, or `none`. Omit it and Braid always
exits 0, so you can adopt it without breaking a pipeline on day one.

### GitHub Actions

```yaml
- uses: dtolnay/rust-toolchain@stable
- run: cargo install --git https://github.com/YOUR-ORG/braid braid-cli
- run: braid analyze contracts --fail-on critical
```

## What Braid is not

Not a security scanner — [`scout-audit`](https://github.com/CoinFabrik/scout-audit) covers
that. Not a resource profiler — [`soroban-cost-linter`](https://github.com/Tollcraft) and
`soroban-budget-assert` cover that. Not an upgrade-safety checker —
[`soroban-upgrade-safeguard`](https://github.com/Dydex/soroban-upgrade-safeguard) covers
that.

Braid answers exactly one question, and tries to answer it well.

## Accuracy

Braid is syntactic. It does not resolve types or expand macros, so it will miss key
derivations that route through code it cannot follow — and when that happens it says
`unresolvable` rather than reporting a clean result. A false sense of safety is the one
failure mode worth engineering against.

The fixture corpus in `fixtures/` encodes every claim the analyser makes, and
`cargo test` asserts them. If you find a contract Braid gets wrong, a fixture reproducing
it is the most useful possible bug report.

## Status

Working, tested, unaudited, and not yet run against a large corpus of real contracts.
`cargo test` is green: 11 tests over 5 fixtures.

## Licence

Apache-2.0.
