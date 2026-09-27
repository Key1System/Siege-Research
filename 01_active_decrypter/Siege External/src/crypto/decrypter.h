// crypto/decrypter.h — the unified public API for the R6 decrypter.
//
// Callers pick a SiteId and pass the encrypted qword; the dispatcher
// looks up the site metadata and forwards to the right template inverse.
//
// This header is what the rest of Siege External + the DLL's exported
// C API rely on. Everything else in the crypto/ folder is
// implementation detail.
#pragma once
#include "types.h"

namespace crypto {

// Decrypt a 64-bit encrypted qword using the site's template.
// Returns { plain, ok }.
Result decrypt(SiteId site, uint64_t enc);

// Decrypt many values from the same site — hot-loop path (fetches TLS
// keys once for the whole batch).
void   decrypt_batch(SiteId site, const uint64_t* enc, uint64_t* out, size_t n);

// Convenience for T5: decrypt the HealthState at DamageComponent+0x184.
// dmg_comp is a live pointer inside our own process address space.
Result32 decrypt_health(const void* dmg_comp);

// One-time DLL initialization. Resolves TlsIndex pointer and installs
// T2 trampoline probes.
bool init(uint64_t module_base, uint32_t* tls_index_ptr);

} // namespace crypto

// ── C ABI exports ──────────────────────────────────────────────────
// These are visible to any client (LoadLibrary + GetProcAddress) so
// external tools or Lua wrappers can drive the decrypter without linking
// C++.
extern "C" {

// Init the decrypter. Returns 0 on success, non-zero on failure.
// tls_index_ptr must point at the game's TlsIndex dword (usually
// resolved via a fixed RVA or sig scan at load time).
__declspec(dllexport)
int  siege_crypto_init(void* module_base, void* tls_index_ptr);

// Decrypt one qword. site is the numeric value of SiteId.
// Returns 0 on failure; check *ok for real result.
__declspec(dllexport)
unsigned long long siege_crypto_decrypt(unsigned int site,
                                         unsigned long long enc,
                                         int* ok);

// Decrypt HealthState. Returns the raw 32-bit state; *ok = 1 on success.
__declspec(dllexport)
unsigned int siege_crypto_decrypt_health(const void* dmg_comp, int* ok);

// Diagnostic: dump the site table to a caller-provided string buffer.
// Returns number of bytes written (excluding NUL).
__declspec(dllexport)
int  siege_crypto_dump_sites(char* buf, int buf_len);

} // extern "C"
