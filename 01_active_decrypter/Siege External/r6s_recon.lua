-- =============================================================
-- R6S Recon — Cheat Engine Lua mirror of Siege External
--
-- What it does (in order):
--   1. Attach to RainbowSix.exe
--   2. Locate ViewData via the constant-float signature
--   3. Read camera position + view-projection matrix
--   4. Enumerate hknpCharacterRigidBody instances by vtable
--   5. For each body, resolve the CharacterController wrapper
--   6. Read world position (CC + 0xA0) and W2S each entity
--
-- Everything is read-only. No writes, no injections.
-- =============================================================

-- ---------------- config ----------------
local TARGET_EXE    = "RainbowSix.exe"

-- Live vtable (from recon MD §2.2). If it moves across builds,
-- re-derive: IDA 0x7FF70BC248E0 + (live_base - 0x7FF6FBEB0000).
local VT_BODY       = 0x7FF61FC748E0

-- ViewData signature (recon MD §13). Sits at ViewData + 0x2A4.
local VD_SIG = "A4 70 7D BF 00 00 00 00 00 00 00 00 00 00 A0 40 " ..
               "00 00 A0 C0 00 00 00 00 00 00 00 00 CD CC 4C 3F " ..
               "00 00 00 3F 00 00 80 3E"
local VD_SIG_OFF        = 0x2A4
local VD_CAM_POS_OFF    = 0x190
local VD_VIEW_PROJ_OFF  = 0x250

-- hknpCharacterRigidBody (recon MD §2.3)
local BODY_VTABLE       = 0x00
local BODY_ID           = 0x18
local BODY_MANAGER      = 0x30

-- RigidBody / CharacterController (recon MD §5.2)
local CC_BODY_PTR       = 0x00
local CC_VTABLE         = 0x10
local CC_VTABLE2        = 0x18
local CC_WORLD_POS      = 0x70 + 0x30   -- row 3 of the 4x4 = +0xA0
local CC_DAMPING        = 0xF0
local CC_BODY_ID_QWORD  = 0xF8

-- Rendering (assumes 1920x1080 — change if needed)
local SCREEN_W = 1920
local SCREEN_H = 1080
local MAX_DIST = 500.0

-- ---------------- helpers ----------------

local function log(fmt, ...)
    print(string.format("[R6S] " .. fmt, ...))
end

local function attach_r6()
    local list = getProcessList()
    for pid_str, name in pairs(list) do
        if name:lower():find(TARGET_EXE:lower(), 1, true) then
            openProcess(name)
            local base = getAddress(TARGET_EXE)
            log("attached: %s  base=0x%X", name, base)
            return base
        end
    end
    return nil
end

-- Scan committed memory for a pattern. Returns list of hit addresses.
local function scan_pattern(pattern, limit)
    limit = limit or 8
    local scan = createMemScan()
    scan.OnlyOneResult = false
    scan.firstScan(
        soExactValue, vtByteArray, nil, pattern, "",
        0, 0x7FFFFFFFFFFF, "", fsmNotAligned, "1", true, true, false, false)
    scan.waitTillDone()
    local fl = createFoundList(scan)
    fl.initialize()
    local hits = {}
    for i = 0, math.min(limit, fl.Count) - 1 do
        local a = tonumber("0x" .. fl.Address[i])
        if a then table.insert(hits, a) end
    end
    fl.destroy()
    scan.destroy()
    return hits
end

-- Scan for a specific qword value. Returns list of addresses whose qword == target.
local function scan_qword(target, limit, start_addr, stop_addr)
    limit = limit or 64
    start_addr = start_addr or 0x10000
    stop_addr  = stop_addr  or 0x7FFFFFFFFFFF
    local scan = createMemScan()
    scan.OnlyOneResult = false
    scan.firstScan(
        soExactValue, vtQword, nil, string.format("%d", target), "",
        start_addr, stop_addr, "", fsmNotAligned, "1", true, true, false, false)
    scan.waitTillDone()
    local fl = createFoundList(scan)
    fl.initialize()
    local hits = {}
    for i = 0, math.min(limit, fl.Count) - 1 do
        local a = tonumber("0x" .. fl.Address[i])
        if a then table.insert(hits, a) end
    end
    fl.destroy()
    scan.destroy()
    return hits
end

local function readVec3(addr)
    return {
        x = readFloat(addr + 0) or 0,
        y = readFloat(addr + 4) or 0,
        z = readFloat(addr + 8) or 0,
    }
end

local function readMat4(addr)
    local m = {}
    for i = 0, 15 do
        m[i] = readFloat(addr + i * 4) or 0
    end
    return m
end

local function dist3(a, b)
    local dx, dy, dz = a.x - b.x, a.y - b.y, a.z - b.z
    return math.sqrt(dx * dx + dy * dy + dz * dz)
end

local function world_to_screen(m, world)
    local cx = world.x * m[0]  + world.y * m[4]  + world.z * m[8]  + m[12]
    local cy = world.x * m[1]  + world.y * m[5]  + world.z * m[9]  + m[13]
    local cw = world.x * m[3]  + world.y * m[7]  + world.z * m[11] + m[15]
    if cw < 0.001 then return nil end
    local sx = (SCREEN_W * 0.5) + (cx / cw) * (SCREEN_W * 0.5)
    local sy = (SCREEN_H * 0.5) - (cy / cw) * (SCREEN_H * 0.5)
    return { x = sx, y = sy, w = cw }
end

-- ---------------- pipeline ----------------

local function find_view_data()
    log("scanning for ViewData signature ...")
    local hits = scan_pattern(VD_SIG, 4)
    log("  got %d sig hits", #hits)
    for _, sig in ipairs(hits) do
        local vd = sig - VD_SIG_OFF
        local m = readMat4(vd + VD_VIEW_PROJ_OFF)
        if m[15] == m[15] and math.abs(m[15]) < 1e9 then
            return vd
        end
    end
    return nil
end

local function enumerate_bodies()
    log("scanning for bodies via vtable 0x%X ...", VT_BODY)
    local hits = scan_qword(VT_BODY, 128)
    local bodies = {}
    for _, addr in ipairs(hits) do
        local vt = readQword(addr + BODY_VTABLE)
        if vt == VT_BODY then
            table.insert(bodies, addr)
        end
    end
    log("  %d bodies (from %d raw hits)", #bodies, #hits)
    return bodies
end

local function resolve_cc(body)
    -- Narrow ±64 MB scan around the body.
    local lo = math.max(0x10000, body - 0x4000000)
    local hi = body + 0x4000000
    local hits = scan_qword(body, 16, lo, hi)
    for _, cand in ipairs(hits) do
        local vt1 = readQword(cand + CC_VTABLE)
        local vt2 = readQword(cand + CC_VTABLE2)
        if vt1 and vt2 and vt1 >= 0x7FF000000000 and vt2 >= 0x7FF000000000 then
            local d = readFloat(cand + CC_DAMPING)
            if d and d == d then
                return cand
            end
        end
    end
    return nil
end

-- ---------------- main ----------------

local function main()
    print("=== R6S Recon ===")
    local base = attach_r6()
    if not base then
        log("FAILED to attach — is R6 running?")
        return
    end

    local vd = find_view_data()
    if not vd then
        log("FAILED to find ViewData — are you in-match / firing range?")
        return
    end
    log("ViewData: 0x%X", vd)
    local cam = readVec3(vd + VD_CAM_POS_OFF)
    log("  camera=(%.2f, %.2f, %.2f)", cam.x, cam.y, cam.z)

    local bodies = enumerate_bodies()

    -- Read a fresh matrix + cam pos for the W2S pass.
    cam = readVec3(vd + VD_CAM_POS_OFF)
    local m = readMat4(vd + VD_VIEW_PROJ_OFF)

    log("--- entities ---")
    for i, body in ipairs(bodies) do
        local cc = resolve_cc(body)
        if cc then
            local pos = readVec3(cc + CC_WORLD_POS)
            local d = dist3(pos, cam)
            local s = world_to_screen(m, pos)
            local screen_s = s and string.format("screen=(%.0f, %.0f)", s.x, s.y) or "off-screen"
            log("[%d] body=0x%X cc=0x%X pos=(%.2f,%.2f,%.2f) dist=%.1f %s",
                i, body, cc, pos.x, pos.y, pos.z, d, screen_s)
        else
            log("[%d] body=0x%X cc=?  (no CC found in ±64 MB)", i, body)
        end

        if d and d <= MAX_DIST then
            -- Placeholder for drawing — CE Lua can't easily paint an
            -- overlay window, but this is where you'd send it to your
            -- own drawer (or the CE main form's OnPaint).
        end
    end

    print("=== done ===")
end

main()
