// crypto/site_registry.h — per-site metadata table.
//
// Every named crypto SiteId maps to a SiteInfo row. Adding a new site
// means:
//   1. Add its SiteId in types.h.
//   2. Add a row here with the template + constants + TLS offset.
//   3. If it's T2 (trampoline), add the corresponding probe registration
//      in trampoline.cpp.
//
// The unified decrypter (decrypter.h) consumes this table to dispatch
// each decrypt request to the right template.
#pragma once
#include "types.h"

namespace crypto {

// Lookup a site by ID. Returns nullptr for unknown / Invalid.
const SiteInfo* find_site(SiteId id) noexcept;

// Iterate every registered site (for testing / dumping).
size_t site_count() noexcept;
const SiteInfo* site_at(size_t idx) noexcept;

} // namespace crypto
