// crypto/tls.h — internal TLS access.
//
// Running inside RainbowSix.exe, we get the current thread's TLS block
// via the standard TEB indirection:
//
//     TEB = gs:[0x30]                              (via NtCurrentTeb())
//     TLS_array = TEB->ThreadLocalStoragePointer   (TEB + 0x58)
//     TLS_block = TLS_array[TlsIndex]
//     key       = TLS_block[SITE_OFF]
//
// TlsIndex is a process-global dword that identifies the module's TLS
// slot. On R6 the main exe uses index 0, but we always read it fresh
// from the address the game's own crypto uses. If we're running in the
// same process, this is a direct load — no NtQueryInformationThread.
//
// Snapshotting is optional; every crypto read is cheap. But for hot
// paths (per-frame decrypt of the same site across N entities) we cache
// the TLS pointer once per call chain.
#pragma once
#include <cstdint>
#include <cstddef>
#include <Windows.h>
#include <winternl.h>

namespace crypto::tls {

// Points to the process-global dword holding the module's TLS slot
// index. On R6 this is at IDB `0x7FF70C6253BC`. Callers set this once
// at DLL_PROCESS_ATTACH (usually via a sig scan or fixed RVA).
inline uint32_t* g_tls_index_ptr = nullptr;

inline void set_tls_index_ptr(uint32_t* p) noexcept {
    g_tls_index_ptr = p;
}

// Read the current thread's TLS pointer array (an array of module TLS
// blocks, one per TLS-using DLL). The public winternl.h _TEB doesn't
// name `ThreadLocalStoragePointer` — it lives at TEB + 0x58 on x64.
__forceinline void** thread_tls_array() noexcept {
    // gs:[0x58] resolves to *(TEB + 0x58) which is ThreadLocalStoragePointer.
    return reinterpret_cast<void**>(__readgsqword(0x58));
}

// Fetch our module's TLS block (i.e. TLS[TlsIndex]). Returns nullptr if
// TlsIndex hasn't been resolved yet.
__forceinline uint8_t* tls_block() noexcept {
    if (!g_tls_index_ptr) return nullptr;
    void** arr = thread_tls_array();
    if (!arr) return nullptr;
    return reinterpret_cast<uint8_t*>(arr[*g_tls_index_ptr]);
}

// Read a qword from TLS[off].
__forceinline uint64_t read_qword(uint32_t off) noexcept {
    uint8_t* blk = tls_block();
    return blk ? *reinterpret_cast<const uint64_t*>(blk + off) : 0;
}

// Read a byte from TLS[off].
__forceinline uint8_t read_byte(uint32_t off) noexcept {
    uint8_t* blk = tls_block();
    return blk ? blk[off] : 0;
}

// Read a dword from TLS[off].
__forceinline uint32_t read_dword(uint32_t off) noexcept {
    uint8_t* blk = tls_block();
    return blk ? *reinterpret_cast<const uint32_t*>(blk + off) : 0;
}

// Convenience: TLS rotate amount masked to the ROR range.
__forceinline uint8_t rot_amount(uint32_t off) noexcept {
    return static_cast<uint8_t>(read_qword(off) & 0x3F);
}

// Fast-path snapshot for hot loops: fetch the TLS block once, then use
// `Snapshot::qword(off)` to read multiple keys without redoing the TEB
// walk on each read.
struct Snapshot {
    uint8_t* block;

    Snapshot() noexcept : block(tls_block()) {}

    __forceinline bool valid() const noexcept { return block != nullptr; }

    __forceinline uint64_t qword(uint32_t off) const noexcept {
        return block ? *reinterpret_cast<const uint64_t*>(block + off) : 0;
    }
    __forceinline uint32_t dword(uint32_t off) const noexcept {
        return block ? *reinterpret_cast<const uint32_t*>(block + off) : 0;
    }
    __forceinline uint8_t byte_(uint32_t off) const noexcept {
        return block ? block[off] : 0;
    }
    __forceinline uint8_t rot(uint32_t off) const noexcept {
        return static_cast<uint8_t>(qword(off) & 0x3F);
    }
};

} // namespace crypto::tls
