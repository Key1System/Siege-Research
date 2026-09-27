#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <cstdint>

namespace core {

struct Module {
    uint64_t base = 0;
    uint64_t size = 0;
    std::wstring name;
};

struct Proc {
    DWORD  pid    = 0;
    HANDLE handle = nullptr;
    Module main;
    HWND   hwnd   = nullptr;
};

inline bool attach(const wchar_t* exe_name, Proc& out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD found_pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe_name) == 0) {
                found_pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!found_pid) return false;

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                           FALSE, found_pid);
    if (!h) return false;

    HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, found_pid);
    if (msnap == INVALID_HANDLE_VALUE) { CloseHandle(h); return false; }

    MODULEENTRY32W me{ sizeof(me) };
    Module main{};
    if (Module32FirstW(msnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, exe_name) == 0) {
                main.base = (uint64_t)me.modBaseAddr;
                main.size = me.modBaseSize;
                main.name = me.szModule;
                break;
            }
        } while (Module32NextW(msnap, &me));
    }
    CloseHandle(msnap);

    if (!main.base) { CloseHandle(h); return false; }

    out.pid = found_pid;
    out.handle = h;
    out.main = main;

    struct FindData { DWORD pid; HWND hwnd; };
    FindData fd{ found_pid, nullptr };
    EnumWindows([](HWND hw, LPARAM lp) -> BOOL {
        auto* d = (FindData*)lp;
        DWORD wpid = 0; GetWindowThreadProcessId(hw, &wpid);
        if (wpid == d->pid && GetWindow(hw, GW_OWNER) == nullptr && IsWindowVisible(hw)) {
            d->hwnd = hw;
            return FALSE;
        }
        return TRUE;
    }, (LPARAM)&fd);
    out.hwnd = fd.hwnd;
    return true;
}

inline void detach(Proc& p) {
    if (p.handle) { CloseHandle(p.handle); p.handle = nullptr; }
    p.pid = 0;
}

} // namespace core
