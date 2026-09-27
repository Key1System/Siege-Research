# Phase 4 — control-flow graphs — BUILT, NOT YET VERIFIED LIVE

Date: 2026-09-19. Siege was not running. **Nothing below is measured.**

| file | role |
|---|---|
| `src/analysis/cfg.h` | `block_t`, `block_term`, `cfg_stats_t`, `Cfg` |
| `src/analysis/cfg.cpp` | two-pass basic-block construction + reachability |
| `src/analysis/routes_cfg.inc` | `/cfg` `/cfg_dot` |

**Builds clean** (2026-09-19 12:51).

## The one structural difference from phases 1–3

**There is no `/cfg_build`.** Phases 1–3 are indexes: built once over the
image, held resident, queried in microseconds. A CFG is built on demand for
ONE function and thrown away.

That inversion is arithmetic, not taste. A basic block costs ~24 bytes plus
edges; 340,000 functions at ~15 blocks each is well over 100 MB of graph on
top of the ~170 MB the xref index already holds — to answer a question almost
always asked about one function at a time. Building a single CFG is
microseconds over a few KB of already-decoded bytes. Caching it would be
paying a permanent memory cost to avoid a cost that is already free.

## Why two passes

A block boundary exists wherever a branch *lands*, and you cannot know where
branches land until the whole function is decoded.

A single-pass "split when you see a jump" therefore produces blocks with an
incoming edge in the middle. Those look fine — right instruction count, right
size — but every later analysis built on them (dominators, liveness,
structuring) is wrong, and the cause is hard to trace back. So: pass 1 decodes
and collects terminators plus targets; pass 2 cuts at the leaders.

## What it cannot see — stated in the response, not just here

Indirect branches (`jmp rax`, jump tables) terminate a block and contribute
**no** edges, because their targets are not statically knowable.

Consequences, both reported:

- `indirect_exits` — blocks whose successors are unknown.
- `unreachable` — blocks with no path from the entry. When `indirect_exits` is
  non-zero these are usually **jump-table targets, not dead code**, and `/cfg`
  says exactly that in a `completeness_note` rather than leaving the caller to
  infer it.

This is the same discipline as the xref index: the blind spot is counted and
surfaced, so a consumer is wrong loudly rather than quietly.

## Output

`/cfg` returns blocks with `begin/end/insns/term/succ`, plus **cyclomatic
complexity** (`E - N + 2`) — one number for "how hard is this function".

`/cfg_dot` returns Graphviz DOT. A block list in JSON is close to unreadable;
DOT is what every graph viewer accepts, so the output is something you can
actually look at — which is most of what a disassembler's graph view is for.
Entry blocks are green, returns red, indirect exits yellow, and conditional
edges are labelled T/F so an if/else reads without tracing addresses by hand.

## Successor ordering is a contract

For `cond_jump`, `succ[0]` is the **taken** branch and `succ[1]` the
fallthrough. A structuring pass reading `succ[0]` as "the then-branch" depends
on that, so it is stated here and in `cfg.cpp` rather than left implicit.

## First live checks

1. `/cfg {"rva":"0x41E870"}` — `Reflex::GetTransforms`, 2,081 bytes and
   known-good from phase 1. Expect multiple blocks and `cyclomatic` > 1. **A
   single block for a 2 KB function means the terminator detection is
   broken.**
2. `/cfg_dot` on the same, and actually render it.
3. A function with `indirect_exits > 0` — confirm `unreachable` is non-zero
   too and the `completeness_note` appears.

Check 1 is the one that can fail.
