// crypto/server.cpp — minimal HTTP server implementation.
//
// Loopback-only. Single accept loop, one thread per request. Uses
// WinSock2 directly — no dependencies on Bytecode's HTTP stack.
//
// Kept small on purpose. Error handling is best-effort: bad requests
// get a 400 response, unknown routes get 404, server errors get 500.
#include "server.h"
#include "decrypter.h"
#include "site_registry.h"
#include "tls.h"
#include "decrypt_t5.h"
#include "watch.h"

#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <atomic>
#include <thread>
#include <string>
#include <string_view>

#pragma comment(lib, "Ws2_32.lib")

namespace crypto::server {

namespace {

std::atomic<bool> g_running{false};
SOCKET            g_listen = INVALID_SOCKET;
std::thread       g_accept_thread;

// ── Tiny helpers ──────────────────────────────────────────────────

// Parse "0x..." or decimal into uint64. Returns false on bad input.
bool parse_u64(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    const char* c = s.c_str();
    // Skip whitespace + optional quotes (in case JSON was sloppy).
    while (*c == ' ' || *c == '\t' || *c == '"') ++c;
    int base = 10;
    if (c[0] == '0' && (c[1] == 'x' || c[1] == 'X')) { c += 2; base = 16; }
    char* end = nullptr;
    unsigned long long v = _strtoui64(c, &end, base);
    if (end == c) return false;
    out = v;
    return true;
}

// Extract a JSON string/number value for a given key. Very naive — good
// enough for `{"key": <value>}` shapes. Returns "" if key not found.
std::string extract_json_val(const std::string& body, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t k = body.find(needle);
    if (k == std::string::npos) return "";
    size_t colon = body.find(':', k);
    if (colon == std::string::npos) return "";
    size_t p = colon + 1;
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
    if (p >= body.size()) return "";
    if (body[p] == '"') {
        size_t end = body.find('"', p + 1);
        if (end == std::string::npos) return "";
        return body.substr(p + 1, end - p - 1);
    }
    // Number or literal — read until , } whitespace.
    size_t end = p;
    while (end < body.size() &&
           body[end] != ',' && body[end] != '}' &&
           body[end] != ' ' && body[end] != '\r' && body[end] != '\n') ++end;
    return body.substr(p, end - p);
}

// ── Response helpers ──────────────────────────────────────────────

void send_all(SOCKET s, const char* buf, int len) {
    while (len > 0) {
        int n = send(s, buf, len, 0);
        if (n <= 0) return;
        buf += n; len -= n;
    }
}

void send_response(SOCKET s, int status, const char* status_text,
                    const std::string& body) {
    char hdr[256];
    int hn = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n",
        status, status_text, body.size());
    send_all(s, hdr, hn);
    if (!body.empty()) send_all(s, body.data(), (int)body.size());
}

void send_json(SOCKET s, const std::string& body) {
    send_response(s, 200, "OK", body);
}
void send_err(SOCKET s, int code, const char* text) {
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"ok\":false,\"error\":\"%s\"}", text);
    send_response(s, code, text, buf);
}

// ── Endpoint handlers ─────────────────────────────────────────────

std::string handle_ping() {
    return R"({"ok":true,"version":"siege_crypto 1.0"})";
}

std::string handle_sites() {
    std::string out = "{\"ok\":true,\"count\":";
    char nbuf[32];
    snprintf(nbuf, sizeof(nbuf), "%zu", crypto::site_count());
    out += nbuf;
    out += ",\"sites\":[";
    for (size_t i = 0; i < crypto::site_count(); ++i) {
        const crypto::SiteInfo* si = crypto::site_at(i);
        if (!si) continue;
        if (i > 0) out += ",";
        char row[512];
        snprintf(row, sizeof(row),
            "{\"id\":%u,\"tmpl\":%u,"
            "\"k1\":\"0x%llX\",\"k2\":\"0x%llX\",\"k3\":\"0x%llX\","
            "\"tls_off\":\"0x%X\",\"name\":\"%s\"}",
            static_cast<unsigned>(si->id),
            static_cast<unsigned>(si->tmpl),
            (unsigned long long)si->k1,
            (unsigned long long)si->k2,
            (unsigned long long)si->k3,
            si->tls_off,
            si->name ? si->name : "");
        out += row;
    }
    out += "]}";
    return out;
}

std::string handle_decrypt(const std::string& body) {
    uint64_t site_id = 0, enc = 0;
    if (!parse_u64(extract_json_val(body, "site"), site_id))
        return R"({"ok":false,"error":"missing or bad 'site'"})";
    if (!parse_u64(extract_json_val(body, "enc"), enc))
        return R"({"ok":false,"error":"missing or bad 'enc'"})";
    auto r = crypto::decrypt(static_cast<crypto::SiteId>(site_id), enc);
    char out[256];
    snprintf(out, sizeof(out),
        "{\"ok\":%s,\"plain\":\"0x%llX\",\"site\":%llu,\"enc\":\"0x%llX\"}",
        r.ok ? "true" : "false",
        (unsigned long long)r.plain,
        (unsigned long long)site_id,
        (unsigned long long)enc);
    return out;
}

std::string handle_decrypt_health(const std::string& body) {
    uint64_t dmg = 0;
    if (!parse_u64(extract_json_val(body, "damage_comp"), dmg))
        return R"({"ok":false,"error":"missing or bad 'damage_comp'"})";
    // The DLL runs in-process, so this is a direct pointer deref.
    auto r = crypto::decrypt_health(reinterpret_cast<void*>(dmg));
    const char* name = crypto::t5::to_string(
        static_cast<crypto::t5::HealthState>(r.plain));
    char out[256];
    snprintf(out, sizeof(out),
        "{\"ok\":%s,\"state\":%u,\"name\":\"%s\",\"damage_comp\":\"0x%llX\"}",
        r.ok ? "true" : "false",
        (unsigned)r.plain, name,
        (unsigned long long)dmg);
    return out;
}

std::string handle_tls_read(const std::string& body) {
    uint64_t off = 0;
    if (!parse_u64(extract_json_val(body, "off"), off))
        return R"({"ok":false,"error":"missing or bad 'off'"})";
    uint64_t q = crypto::tls::read_qword(static_cast<uint32_t>(off));
    char out[192];
    snprintf(out, sizeof(out),
        "{\"ok\":true,\"off\":\"0x%llX\",\"qword\":\"0x%llX\",\"rot\":%u}",
        (unsigned long long)off,
        (unsigned long long)q,
        (unsigned)(q & 0x3F));
    return out;
}

// ── Per-connection worker ─────────────────────────────────────────

void serve_client(SOCKET client) {
    // Receive up to 8 KB — plenty for our tiny endpoints.
    char buf[8192];
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n = recv(client, buf + total, (int)sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = 0;
        // Stop once we've got the full header + body length.
        char* hdr_end = strstr(buf, "\r\n\r\n");
        if (!hdr_end) continue;
        int hdr_len = (int)(hdr_end + 4 - buf);
        // Look for Content-Length.
        int cl = 0;
        char* cl_ptr = strstr(buf, "Content-Length:");
        if (cl_ptr) cl = atoi(cl_ptr + 15);
        if (total >= hdr_len + cl) break;
    }
    buf[total < (int)sizeof(buf) ? total : (int)sizeof(buf) - 1] = 0;

    // Parse request line: METHOD SP PATH SP HTTP/x.y
    char method[16] = {}, path[256] = {};
    if (sscanf_s(buf, "%15s %255s", method, (unsigned)_countof(method),
                                     path, (unsigned)_countof(path)) != 2) {
        send_err(client, 400, "malformed request");
        closesocket(client); return;
    }

    // Extract body (after the CRLFCRLF).
    std::string body;
    if (char* be = strstr(buf, "\r\n\r\n")) {
        body = be + 4;
    }

    std::string resp;
    if (strcmp(path, "/ping") == 0) {
        resp = handle_ping();
    } else if (strcmp(path, "/sites") == 0) {
        resp = handle_sites();
    } else if (strcmp(path, "/decrypt") == 0) {
        resp = handle_decrypt(body);
    } else if (strcmp(path, "/decrypt_health") == 0) {
        resp = handle_decrypt_health(body);
    } else if (strcmp(path, "/tls_read") == 0) {
        resp = handle_tls_read(body);
    } else if (strcmp(path, "/watch") == 0) {
        crypto::watch::report_now();
        resp = R"({"ok":true,"kicked":true})";
    } else {
        send_err(client, 404, "unknown route");
        closesocket(client);
        return;
    }
    send_json(client, resp);
    closesocket(client);
}

// ── Accept loop ────────────────────────────────────────────────────

void accept_loop(uint16_t port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;

    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) { WSACleanup(); return; }

    BOOL on = TRUE;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(g_listen, (sockaddr*)&a, sizeof(a)) != 0) {
        closesocket(g_listen); WSACleanup(); return;
    }
    if (listen(g_listen, 8) != 0) {
        closesocket(g_listen); WSACleanup(); return;
    }

    printf("[siege_crypto] HTTP server listening on 127.0.0.1:%u\n", port);
    fflush(stdout);

    while (g_running.load()) {
        SOCKET c = accept(g_listen, nullptr, nullptr);
        if (c == INVALID_SOCKET) {
            if (!g_running.load()) break;
            continue;
        }
        // Fire-and-forget worker thread.
        std::thread(serve_client, c).detach();
    }
    closesocket(g_listen);
    WSACleanup();
}

} // namespace

bool start(uint16_t port) noexcept {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return false;
    g_accept_thread = std::thread(accept_loop, port);
    g_accept_thread.detach();
    return true;
}

void stop() noexcept {
    g_running.store(false);
    if (g_listen != INVALID_SOCKET) closesocket(g_listen);
}

} // namespace crypto::server
