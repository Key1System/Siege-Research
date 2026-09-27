// crypto/trampoline.cpp — T2 site probe installation + dispatch.
#include "trampoline.h"
#include <vector>
#include <string_view>
#include <mutex>

namespace crypto::trampoline {

// Registry of all T2 site probes. Populated by install_probes() at
// DLL_PROCESS_ATTACH. Grows over time as we identify meaningful T2
// sites to instrument.
static std::vector<T2Site>& registry() noexcept {
    static std::vector<T2Site> r;
    return r;
}

static std::mutex& registry_mutex() noexcept {
    static std::mutex m;
    return m;
}

// Simple built-in probe helper: for a T2 getter that reads
// [rcx+field_off] as its encrypted qword and returns the plain.
template <int FIELD_OFF>
static uint64_t generic_probe(void* game_fn, uint64_t enc) noexcept {
    StructGetterProbe<FIELD_OFF> dummy{};
    dummy.set_enc(enc);
    return call<uint64_t, void*>(game_fn, &dummy);
}

// Register a probe for a T2 site. game_fn_addr must have been resolved
// (module base + RVA, or sig scan). If game_fn_addr is null, the probe
// is skipped.
static void register_probe(const char* name, void* game_fn_addr,
                            int field_off, T2ProbeFn probe) noexcept {
    if (!game_fn_addr || !probe) return;
    std::lock_guard<std::mutex> lk(registry_mutex());
    registry().push_back({ name, game_fn_addr, field_off, probe });
}

// Called by dllmain after resolving addresses. Populate the registry
// with all T2 sites we can safely trampoline through.
//
// This is a scaffold — real sites get added here as we identify them.
// For each site we need:
//   - The game function's RVA
//   - The offset within its input struct that holds the ciphertext
//   - A probe function (usually generic_probe<FIELD_OFF>)
void install_probes(uint64_t /*module_base*/) noexcept {
    // Example (commented out — no real T2 sites hooked yet):
    //
    // register_probe("SomeComponent_GetEncryptedThing",
    //                (void*)(module_base + 0x00ABCDEF),
    //                /*field_off=*/0x38,
    //                &generic_probe<0x38>);
}

Result decrypt(const char* site_name, uint64_t enc) {
    if (!site_name) return Result::fail();
    std::string_view name(site_name);
    std::lock_guard<std::mutex> lk(registry_mutex());
    for (const auto& s : registry()) {
        if (name == s.name) {
            return Result::of(s.probe(enc));
        }
    }
    return Result::fail();
}

} // namespace crypto::trampoline
