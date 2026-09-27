> **SUPERSEDED 2026-09-18 — see `00_START/README.md`.**
> Kept for its detail and history. Where it disagrees with that file,
> that file is correct.

# Siege Research — Consolidated Inventory

> ## ⚠️ 2026-09-15 — START WITH `SESSION_HANDOFF.md`
>
> A later session solved the skeleton/bone problem and mapped the TLS
> block. **Read `SESSION_HANDOFF.md` in this directory first** — it is the
> single entry point and contains every address, key, and command needed
> to resume.
>
> New since this inventory was written:
>
> | Location | What |
> |---|---|
> | `SESSION_HANDOFF.md` | ⭐ start here — complete resume doc |
> | `01_active_decrypter/recon_notes/SIEGE_RECON_V5.md` | all findings, with the full iteration and correction log |
> | `C:\Users\hhhuh\Downloads\Bytecode-Internal\` | the in-process RE tool (injects into the game, HTTP API on :9998) |
>
> Headline results:
> - **Bone matrices solved** — the thing §16e called "Not yet cracked".
>   Live transforms read for 5 characters at once.
> - **TLS mapped** — 10,673 slots, 5,985 identified as crypto keys,
>   validated 9/9 against hand-decoded ground truth.
> - **Template T7 verified end-to-end** on live captured data.
>
> ⚠️ **Most V4 signatures and all T1 constants are DEAD in the current
> build** — see `SESSION_HANDOFF.md §10` before reusing anything from
> `CRYPTO_MAP.md`.


Generated 2026-07-31. **Updated once after a second sweep** — the first pass
missed roughly 700 KB of dense text research (v1-v4 recon docs, findings
maps, and live-session artifacts). All now in `01_active_decrypter/recon_notes/`.

## Tree

```
Siege-Research/
├── INVENTORY.md                     ← this file
├── 01_active_decrypter/                   ← YOUR RESEARCH + ACTIVE CODE
│   ├── Siege External/                    main decrypter project (~4 MB)
│   │   ├── CRYPTO_MAP.md                  central template catalog (T1-T6)
│   │   ├── src/crypto/                    per-template implementations
│   │   │   ├── decrypt_t1.h               TLS-rotated MBA (pure constants)
│   │   │   ├── decrypt_t5.h               HealthState decrypt
│   │   │   ├── decrypter.cpp/h            top-level decrypter
│   │   │   ├── tls.h, types.h             infra
│   │   │   ├── trampoline.h               T2 stack-hashed MBA trampoline
│   │   │   ├── site_registry.cpp          the site table
│   │   │   ├── watch.cpp                  runtime instrumentation
│   │   │   ├── skel_probe.h               probing scaffolding
│   │   │   └── server.cpp                 (offset/query server?)
│   │   ├── dll_project/dllmain.cpp        internal-DLL entrypoint
│   │   ├── src/main.cpp                   external EXE entrypoint
│   │   ├── r6s_recon.lua                  Lua companion (Cheat Engine or IDA?)
│   │   ├── R6S_Recon.CT                   Cheat Engine table
│   │   ├── SiegeExternal.sln, vcxprojs    VS solution
│   │   └── assets/, third_party/          UI assets + deps
│   ├── Siege Internal/                    internal-DLL stub (skeleton)
│   ├── recon_notes/                       ← THE HUGE RESEARCH WORK
│   │   ├── SIEGE_RECON_V4.md              44 KB  — v4, IDB + live process
│   │   ├── recon_v3_clean.md              86 KB  — v3 distilled findings
│   │   ├── recon_v2_reverified.md         47 KB  — v2, re-verified pass
│   │   ├── r6_research_notes.md          ~55 KB  — dx-repo research notes
│   │   ├── r6_live_verified.md           ~14 KB  — live-verified findings
│   │   ├── FINDINGS_entity_map.md         24 KB  — entity map findings
│   │   ├── FINDINGS_real_GM.md             6 KB  — real GameManager findings
│   │   ├── rainbow-external-debug.log    109 KB  — debug log from live runs
│   │   └── r6_recon_v1_v2_v3/             the original r6/ directory:
│   │       ├── siegerecon2.md            236 KB  — 5537-line master doc
│   │       ├── SIEGE_RECON.md             48 KB  — first recon
│   │       ├── output.md                  29 KB  — script output archive
│   │       ├── siegerecon3.md             23 KB  — v3 iteration
│   │       ├── README.md                   7 KB
│   │       ├── manifest.json               3 KB  — session manifest
│   │       ├── live_session_log.json       6 KB  — live session log
│   │       ├── junk_scan.json              0 KB  — empty (placeholder)
│   │       └── ubx_sweep.json              0 KB  — empty (placeholder)
│   └── prior_sdk_R6ExternalEsp/           reference SDK from prior iteration
│       ├── r6_decrypt.h                   72 KB  — big decrypter research file
│       ├── r6_offsets.h                   12 KB
│       ├── r6_entity.h                     6 KB
│       └── r6_math.h                       2 KB
├── 02_ida_dump/                     2.9 GB — IDA reverse-engineering session
│   ├── RainbowSix_dump.exe           411 MB   dumped game binary
│   ├── RainbowSix_dump.exe.i64       2.66 GB  packed IDA database
│   ├── RainbowSix_dump.exe.til       type library
│   ├── RainbowSix_dump.exe.nam       named-address table
│   ├── RainbowSix_dump.exe.id2       small metadata
│   └── mainbuildforce.dll.i64        24 MB    older BE anti-cheat DLL session
├── 03_rust_dumper_shared/            0.1 MB — (misnamed; these were RUST-game
│   │                                          not Siege — kept in case any
│   │                                          decrypt technique cross-applies)
│   ├── decrypt_analyzer/
│   ├── decrypt_sweep/
│   └── decryption/
├── 04_older_versions/                22 MB — prior iterations preserved
│   ├── CodingProjects_Siege_External_UNFINISHED/    early external stub
│   ├── RustWork_KingVone-Clean_Siege_External/      snapshot from KingVone
│   ├── Discord_Desktop_256_Projs_Siege/             discord-backup snapshot
│   ├── Discord_Desktop_257_Projs_Siege/             discord-backup snapshot
│   ├── GameCheats_General_CHEATS_siege/             older cheat prototype
│   └── SPOILER_R6_Made_by_H/                        codecave patcher for
│                                                    Camera/Actor decrypt sites
│                                                    (Decryptions.h is the key)
└── 05_reference_cheats/              0.0 MB — 3rd-party sources NOT copied
    └── REFERENCE_LOCATIONS.md        paths to downloaded UC repos (10 GB total,
                                     left where they are to save disk)
```

## Sources — where the research was hiding

Roughly 700 KB of dense reversing notes were scattered across places I
initially filtered out. Recovered from:

| File | Original location | Lines |
|---|---|---|
| `siegerecon2.md` | `Downloads\Game Cheats\Rainbow Six Siege\r6\` | 5,537 |
| `SIEGE_RECON_V4.md` | `Downloads\RustWork\KingVone-Clean\` | 1,053 |
| `r6_research_notes.md` | inside `dxrainbowinternal-main_[unknowncheats.me]_\` | 1,003 |
| `SIEGE_RECON.md` (v1) | `Downloads\Game Cheats\Rainbow Six Siege\r6\` | 972 |
| `siegerecon3.md` | `Downloads\Game Cheats\Rainbow Six Siege\r6\` | 563 |
| `FINDINGS_entity_map.md` | inside `R6 External-Esp\siege\` | 500 |
| `r6_live_verified.md` | inside `dxrainbowinternal-main_[unknowncheats.me]_\` | 314 |
| `recon_v3_clean.md` (was `message (2).txt`) | `Downloads\` root | ~1000 |
| `recon_v2_reverified.md` (was `message (3).txt`) | `Downloads\` root | ~1500 |
| `output.md` | `Downloads\Game Cheats\Rainbow Six Siege\r6\` | 299 |
| `FINDINGS_real_GM.md` | inside `R6 External-Esp\siege\` | 122 |
| **Total** | | **~10,600 lines of research** |

Plus the 72 KB `r6_decrypt.h` header from the R6 External-Esp SDK.

## What I originally missed (and why)

- **`.txt` files at the Downloads root** (`message (2).txt`, `message (3).txt`)
  — I assumed these were Discord chat exports; they're actually recon v2/v3
  saved via the "download as text" pattern.
- **Research MDs *inside* what looked like downloaded 3rd-party repos**
  (`dxrainbowinternal-main`, `R6 External-Esp/siege/`) — you'd added your
  own findings docs into other people's project trees.
- **`SIEGE_RECON_V4.md` in `RustWork\KingVone-Clean\`** — the V4 doc was
  filed under Rust-work directory, not the Siege project directory.
- **The whole `r6/` subdir with 5 recon MDs + manifest** — got skipped
  because I filtered `Rainbow Six Siege\` broadly.

## The active project

- **Central research doc**: `01_active_decrypter/Siege External/CRYPTO_MAP.md`
  (the T1–T6 template catalog)
- **Recon chronology**: `01_active_decrypter/recon_notes/` — read in order
  `SIEGE_RECON.md → siegerecon2.md → siegerecon3.md → recon_v2 → recon_v3
  → SIEGE_RECON_V4.md → r6_research_notes.md → r6_live_verified.md`
- **Code**: `01_active_decrypter/Siege External/src/crypto/`
- **Prior-iteration SDK** for cross-reference: `01_active_decrypter/prior_sdk_R6ExternalEsp/r6_decrypt.h`

## The IDA session

`02_ida_dump/RainbowSix_dump.exe.i64` is the packed IDA database with all
annotations from the 2026-07-17 reversing pass (which per CRYPTO_MAP.md is
the source of truth for the T1–T6 template catalog). Just open the `.i64`
in IDA — it regenerates the `.id0/.id1/.id2/.nam/.til` unpacked working
files (3 GB) on first open.

Per `SIEGE_RECON_V4.md`:
- IDB image base: `0x7FF6FBEB0000`
- Live process image base: `0x7FF60FF00000`
- **ASLR delta: `-0xEBFB0000`** — subtract from any IDA VA to get live VA
- 304,472 functions in the IDB

## What was intentionally NOT copied

- The 10 GB `Game Cheats/Rainbow Six Siege/` reference tree of downloaded
  UC-forum cheats (`rainbow-external-main`, `dxrainbowinternal-main`,
  `UnknownsR6Src`, etc). Paths saved in `05_reference_cheats/`.
- Build artifacts (`x64/`, `obj/`, `.pdb`, `.obj`, `.ilk`).
- The 3 GB `.id0`/`.id1` unpacked IDB (regenerated on IDA open).
