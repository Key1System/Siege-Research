# RTTI recovery — WORKS, but the game's own classes are NOT there

Date: 2026-09-19. **Measured live**, Siege pid 21800, image base 0x7FF6399B0000-ish
(base changes per launch; everything below is RVA).

## The engine works

```
POST /rtti_build {"budget_ms":20000}
  anchor_found      true
  typeinfo_vtable   0x7FF6399B0800
  type_descriptors  141
  classes           91
  rejected_col      180        <- validators doing their job
  rejected_novtable 0          <- every valid COL found its vtable
  multi_vtable      1
  ms                546
```

Anchor found, validators rejecting cleanly, 91 classes with demangled names and
exact vtable RVAs in half a second. The implementation is correct.

## THE FINDING: the game is built with /GR- (RTTI disabled)

**141 TypeDescriptors in a 457 MB game engine is far too few.** A binary this
size has thousands of polymorphic classes. And every single recovered class is
THIRD-PARTY:

| group | examples |
|---|---|
| MSVC STL | `std::locale::_Locimp`, `std::num_put<...>`, `std::moneypunct<...>` |
| Microsoft glTF | `Microsoft::glTF::Document`, `::Mesh`, `::Node`, `::Skin`, `::Camera` |
| rapidjson | `GenericSchemaValidator<...>` |
| Havok | `?A0x2debf5b7::hkcdGskFunctionSetInterface` |

Not one Ubisoft game class. No `Player`, no `Entity`, no `Character`, no
`Reflex*`. All 91 vtables lie in one narrow `.rdata` band, `0x11FB0838` to
`0x123C1F58` — the statically-linked-library region.

**Conclusion: Ubisoft compiled the engine with `/GR-`,** which is normal for a
shipping game (RTTI costs size and inhibits some optimisation). The only RTTI in
the image belongs to third-party libraries built with it enabled.

This is a NEGATIVE RESULT, and it is worth as much as a positive one: it closes
off a whole line of attack permanently. No amount of improving the RTTI parser
will find `PlayerController` here, because the metadata was never emitted.

## What this means for the heap problem

`/rtti_find {"q":"Player"}` returning nothing is **correct behaviour**, not a
bug. The vtable-name shortcut is unavailable for game classes on this target.

The vtable-ANCHORED approach still works — an object's first qword is still a
vtable pointer, and scanning for a known vtable address still finds every
instance. What is gone is the ability to get that address *by name*. The vtable
RVA must come from somewhere else:

1. **The known one.** `+0x121CBFC8` is already established for the player from
   prior work. Note it sits just above the glTF band, i.e. plausibly in the
   game's own vtable region — consistent with this finding.
2. **`/xref_stores`** on that RVA -> the constructor (phase 2, needs live
   verification first).
3. **String-anchored location** (see `specs/SPEC_SIGNATURES.md` §4) — the game
   does have strings even without RTTI, and a string xref reaches the code that
   uses it. This is now the PRIMARY naming route.
4. **Vtable-shaped scanning without names**: runs of qwords pointing into
   executable segments, preceded by a null or a non-code qword. Finds the
   vtables; does not name them.

## Also worth noting

- `rejected_col: 180` vs `classes: 91` — the validators rejected twice as many
  candidates as they accepted. That is the `pSelf` self-RVA check and the
  CHD loop-closure check working exactly as the spec predicted.
- `rejected_novtable: 0` — every COL that passed validation had a findable
  vtable. No half-recovered classes.
- `multi_vtable: 1` — one class with a secondary (multiple-inheritance) vtable,
  flagged so it is not mistaken for a primary one during a heap scan.
- The demangler handled namespaces correctly (`Microsoft::glTF::Material::
  PBRMetallicRoughness`) and correctly LEFT ALONE the template names it cannot
  decode, emitting the raw mangled string rather than a plausible-looking wrong
  one.
