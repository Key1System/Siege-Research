# Bytecode-Internal audit — 65 findings, adversarially verified

Produced by a 211-agent workflow: 5 subsystem auditors, then 3 independent
refuters per finding (each told to default to "refuted" when uncertain).
176 of 195 refuters returned before the session limit stopped the run.

**Refutation rate by area** — this is a quality signal about the auditors, not
just the code:

| area | refuted / total | read |
|---|---|---|
| memory | 2 / 28 (7%) | findings held up almost entirely |
| crypto | 2 / 25 (8%) | held up |
| ipc | 8 / 55 (15%) | held up, but verification was cut short — treat as provisional |
| emulation | 8 / 39 (21%) | mostly held |
| **hwbp** | **15 / 29 (52%)** | **half were refuted — treat this area's findings with suspicion** |

The hwbp auditor was substantially wrong about half of what it reported. That
is exactly what the adversarial pass is for, and it is why the findings below
are ordered by severity *and* annotated with which area they came from.

---

## CRITICAL

**1. Write primitives exist in a read-only tool** — `src/core/mem.h`
`write_raw`, `write_raw_force`, and `write<T>` are present, and
`write_raw_force` flips `.text` to `PAGE_EXECUTE_READWRITE`. The project's
stated hard constraint is read-only. Whether or not they are currently called,
their existence is a loaded gun; a stray call site or a future edit turns this
into a memory-modifying tool.
*Fix: delete them outright, not `#if 0`.*

**2. `identify_site()` never populates `tls_off`** — `src/crypto/decrypt.cpp`
`/decrypt` called with only a `site` therefore reads `TLS[0]` and returns
`ok=true` with a wrong plaintext. A confident wrong answer is worse than an
error — this is the failure mode that has already cost this project hours
elsewhere.

**3. Default QEMU64 CPU model lacks AVX** — `src/emu/emulator.cpp`
Every AVX instruction is either a wrong answer or a spurious fault. Siege is
compiled with AVX.

**4. XMM/YMM state is never initialised or returned** — `src/emu/emulator.cpp`
SSE/AVX results are invisible and inputs are always zero. Any emulated function
touching float/vector math silently produces garbage.

**5. `timeout_ms` is unbounded on every breakpoint route** — `src/ipc/server.cpp`
A caller can wedge the DR lock for up to 49 days with debug registers armed.

**6. `WSACleanup()` runs while client threads are still in `handle_client()`** —
`src/ipc/server.cpp`. `m_conns` reaches zero before those threads finish, so
teardown proceeds under them.

---

## HIGH

**memory**
- `read_raw` leaves the destination **partly written** when the memcpy faults
  mid-copy, while returning false. A caller that inspects the buffer anyway
  sees a mix of new and stale bytes.
- `scan_float` ignores `module_only`, `kinds`, `budget_ms` and the lo/hi clamp
  — an unbounded whole-address-space scan regardless of what was requested.

**crypto**
- `decrypt()` hardcodes ROL-by-4 for T7 and **discards the rotate immediate
  that `identify_site` actually decoded**. Correct only while the build happens
  to use 4.
- `decrypt()` silently falls back from the game thread's TLS to the calling
  thread's, then to the load-time template. Three different answers, one
  `ok=true`.
- `mba.cpp` is a 3-candidate brute force, not a simplifier. Every identity
  declared in `mba.h` is dead code.
- **No detector or resolver for `(K1 + [global]) ^ K2`** — the single highest-value
  missing capability, and the one that resolves obfuscated call targets offline.

**emulation**
- `EFLAGS` defaults to 0, which is an impossible x86 state (reserved bit 1 must
  be set).
- `hook_saw_stop` can report `reached_stop` for a stop address the run merely
  passed through earlier.
- A page that is readable but decommitted or guarded mid-run is silently mapped
  as **zeros** and the run continues — producing a plausible wrong result.

**ipc**
- JSON emitter writes bare `nan`/`inf`, producing responses no JSON parser
  accepts.
- `/func_range` allocates a caller-controlled buffer with no ceiling.
- `ipc::stop()`'s drain barrier does not cover the breakpoint routes, so
  teardown proceeds while a capture holds the DR lock.

**hwbp** *(52% of this area's findings were refuted — verify before acting)*
- `clear()` never disarms the calling thread's own debug registers.
- Slot selection is a non-atomic find-then-claim across four entry points.

---

## The ergonomics cluster (ipc, all `low` severity but high practical value)

These are about driving the tool programmatically, which is the actual use case:

- No route resolves a bone→world pipeline in one call — the highest-value
  round-trip collapse available.
- `/batch` cannot reference a previous member's result, so every pointer-chain
  hop costs a round trip.
- No route lists available routes or their parameters; a driver must hardcode
  them.
- `/scan_aob` and `/find_ptr` cannot resume — a timed-out scan restarts from
  the beginning.
- `/read` returns space-separated hex text: ~3× the wire cost plus client-side
  parsing.
- No structure decode against a caller-supplied field list.
- No cooperative cancel token, so long routes cannot be aborted.
- `/health` exposes no lock diagnostics, so "blocked on a lock" and "doing
  work" are indistinguishable.

---

## Caveats on this audit

- **ipc findings are provisional.** Most of that area's refuters were lost to
  the session limit, so its 23 findings did not complete verification.
- **hwbp findings are suspect.** A 52% refutation rate means the auditor was
  unreliable there; re-check each before changing code.
- Six refuters failed on a content-safeguard error rather than returning a
  verdict, so a handful of findings have 2 votes rather than 3.
