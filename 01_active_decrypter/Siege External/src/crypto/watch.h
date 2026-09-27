// crypto/watch.h — live discovery + observability for siege_crypto.dll.
//
// Runs on a dedicated background thread inside the DLL. Every N seconds
// it walks through everything the DLL knows about and dumps a fresh
// report to the console. Turns the DLL from a static decrypter into a
// live discovery tool.
//
// What gets logged per cycle:
//   - all TLS key values across every offset any known site uses
//   - per-site: sample decrypt of the LIVE encrypted qword the game
//     currently has in its data-holder (for T7/T4 sites), or a
//     round-trip self-check (for T1)
//   - VMProtect / stub statistics if reachable
//   - drift detection: if a TLS key changed since last cycle, flag it
//
// This is a diagnostic surface only — never modifies game state.
#pragma once
#include <cstdint>

namespace crypto::watch {

// Start the watcher on a background thread. Idempotent — safe to call
// multiple times, only the first has effect.
bool start(uint32_t interval_ms = 2000) noexcept;

// Stop the watcher (called from DLL_PROCESS_DETACH).
void stop() noexcept;

// Force an immediate report (from anywhere, e.g. an HTTP endpoint).
void report_now() noexcept;

} // namespace crypto::watch
