# The UI — rebuilt as a disassembler workspace

`src/ui/web.h`, served from memory at `http://127.0.0.1:9998/`.
886 lines, 38 KB. **Verified live**: serves, all panes present, 37 routes wired.

## What changed and why

The old UI was 218 lines and five tabbed forms (memory / scan / tls / decrypt /
breakpoints). It predated ~50 routes — the function db, xrefs, strings, CFG,
RTTI, imports, vtables, constructors, routines and MBA solving were all
unreachable from the browser.

More importantly the SHAPE was wrong. Tabbed forms make you choose between
looking at a function and looking at its callers. In reverse engineering you
need both at once, which is why IDA and Ghidra are laid out the way they are.

## Layout

```
+----------------------------------------------------------------+
| BYTECODE  <- ->  [ goto address / name / string ]  [build all]  |
+------------+--------------------------------+------------------+
| NAVIGATOR  | CENTER                          | CONTEXT          |
|            |                                 |                  |
| funcs      | disasm | cfg | hex | object |   | function         |
| strings    | routine | emulate | scan | tls  | string / class   |
| vtables    |                                 | xrefs TO   (n)   |
| classes    |   <content for current addr>    | xrefs FROM (n)   |
| imports    |                                 |                  |
+------------+--------------------------------+------------------+
|            CONSOLE  — raw /route + JSON, with log               |
+----------------------------------------------------------------+
```

- **left** a persistent navigator. "Where am I" is asked constantly, so the
  list never disappears behind a tab.
- **centre** content for the current address.
- **right** context for that SAME address — this is the pane that makes it a
  workspace. Seeing a function and its callers simultaneously is the single
  most useful thing in a disassembler.
- **bottom** a console, because some answers are raw JSON and pretending
  otherwise loses information.

## One address drives everything

There is a single piece of application state: the current RVA. Click a caller
in the context pane and the disassembly, CFG, hex and context all follow.
That is what makes 80 endpoints feel like one tool instead of 80 forms.

Consequences that fall out of it for free:
- **every address anywhere is a link**, including operands inside the
  disassembly — you can walk a call graph by clicking
- **alt+left / alt+right** navigate history, everywhere
- the goto bar accepts an address, an RVA, **or a string**: a non-hex entry
  is searched in the string index and resolved to the function that USES it,
  which is how you find code in a stripped binary

## Panes

| pane | routes |
|---|---|
| disasm | `/disasm` `/decompile` |
| cfg | `/cfg` `/cfg_dot` |
| hex | `/read` (16-byte rows with ASCII) |
| object | `/obj_fields` `/obj_scan` — colour-coded field classification |
| routine | `/rt_at` `/rt_shapes` `/rt_verify` — forward AND inverse formula |
| emulate | `/mba_solve` `/mba_globals` |
| scan | `/scan_aob` |
| tls | `/tls_read` `/tls_verify` `/rt_by_tls` |

Navigator: `/func_list` `/str_find` `/vt_top` `/rtti_find` `/imp_find`.
Context: `/func_at` `/xref_to` `/xref_from` `/str_at` `/rtti_at`, fetched in
PARALLEL so the pane fills in one round trip rather than four.

## Honesty carried into the UI

The API is careful to surface its own blind spots; the UI would waste that if
it rendered only the happy path. So:

- every address shows its **segment** as a coloured tag (green = executable,
  purple = data) — this project once built a finding on a `.data` address
  decoded as instructions
- `mid-function` is tagged when an address is not a function entry
- CFG shows `indirect` and `misaligned` counts as warning tags
- `/obj_scan` renders an incomplete scan with a red **incomplete** tag, because
  a truncated scan returning 0 must never read as "absent"
- routines show `complete`/`incomplete` and `invertible`/`lossy` tags
- the classes pane says outright that this target is `/GR-`, so an empty
  result is expected rather than a bug

## Verified live

```
GET /                     38,129 bytes, all panes present
build all                 14 s total:
   xrefs    11,495,588
   strings  56,482
   imports  34,383
   rtti     91
   vtables  57,752
context pane (string)     text + xref count
context pane (function)   begin/size/entry/segment + xrefs to/from
context pane (vtable)     8,132 refs, honest "no RTTI" note
```

Every route the UI calls was tested and responds.
