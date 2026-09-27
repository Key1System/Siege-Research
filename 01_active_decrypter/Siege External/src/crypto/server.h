// crypto/server.h — minimal in-process HTTP server for the crypto DLL.
//
// Listens on 127.0.0.1:9998 by default. Exposes the decrypter's C API
// over HTTP so any client (Bytecode, curl, browser, Lua) can drive it
// without linking C++ or doing CreateRemoteThread.
//
// Design:
//   - Single blocking accept loop on a background thread.
//   - Per-request thread (cheap, request rate is low).
//   - Minimal HTTP/1.1 parser: request line, headers, optional body.
//   - JSON responses hand-formatted (no external deps).
//
// Endpoints:
//   GET  /ping                  → { ok, version }
//   GET  /sites                 → { sites: [...] }
//   POST /decrypt               body: { site: <SiteId int>, enc: <hex or int> }
//                               → { ok, plain: "0x..." }
//   POST /decrypt_health        body: { damage_comp: <hex or int> }
//                               → { ok, state: <int>, name: "DBNO"/... }
//   POST /tls_read              body: { off: <int> }
//                               → { ok, qword: "0x...", rot: <int> }
//
// This is the CURRENT thread's TLS — because the DLL runs inside R6,
// "current thread" == whatever R6 thread was handling the accept().
// For crypto sites whose keys are the same across all game threads,
// that's fine. If we ever hit a site whose key varies per-thread we'll
// add a `tid` parameter and route accordingly.
#pragma once
#include <cstdint>

namespace crypto::server {

// Start the HTTP server on 127.0.0.1:port in a background thread.
// Returns true if the socket bound successfully.
bool start(uint16_t port = 9998) noexcept;

// Stop the server (rarely called — server dies with DLL unload).
void stop() noexcept;

} // namespace crypto::server
