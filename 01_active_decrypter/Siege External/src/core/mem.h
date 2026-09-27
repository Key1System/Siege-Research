#pragma once
#include "proc.h"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace core {

inline bool rpm(HANDLE h, uint64_t addr, void* buf, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(h, (LPCVOID)addr, buf, n, &got) && got == n;
}

template <typename T>
inline T read(HANDLE h, uint64_t addr) {
    T v{};
    rpm(h, addr, &v, sizeof(T));
    return v;
}

// Enumerate committed regions [lo, hi).
inline std::vector<MEMORY_BASIC_INFORMATION> regions(HANDLE h,
                                                     uint64_t lo,
                                                     uint64_t hi)
{
    std::vector<MEMORY_BASIC_INFORMATION> out;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t cur = lo;
    while (cur < hi &&
           VirtualQueryEx(h, (LPCVOID)cur, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS))
        {
            out.push_back(mbi);
        }
        cur = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return out;
}

} // namespace core
