#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <cmath>
#include <ctime>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
  #include <windows.h>
  #include <io.h>
  #include <direct.h>
#else
  #include <unistd.h>
  #include <sys/file.h>
  #include <sys/statvfs.h>
  #include <dirent.h>
#endif
#include <algorithm>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#ifdef _WIN32
#include <direct.h>

static inline struct tm* localtime_r(const time_t* t, struct tm* out) {
    struct tm* v = localtime(t);
    if (v) *out = *v; else memset(out, 0, sizeof *out);
    return out;
}

static inline void sleep(unsigned sec) { Sleep((DWORD)sec * 1000UL); }
static inline void usleep(unsigned usec) { Sleep(usec ? (usec / 1000 > 0 ? usec / 1000 : 1) : 0); }

struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    unsigned long long f_blocks;
    unsigned long long f_bfree;
    unsigned long long f_bavail;
};
static inline int statvfs(const char* path, struct statvfs* vs) {
    ULARGE_INTEGER avail, total, freeb;
    if (!GetDiskFreeSpaceExA(path, &avail, &total, &freeb)) return -1;
    vs->f_bsize = 4096;
    vs->f_frsize = 4096;
    vs->f_blocks = total.QuadPart / 4096;
    vs->f_bfree  = freeb.QuadPart / 4096;
    vs->f_bavail = avail.QuadPart / 4096;
    return 0;
}

struct dirent { char d_name[MAX_PATH]; };
struct DIR_s {
    HANDLE h = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAA fd;
    bool first = true;
    dirent ent;
};
typedef DIR_s DIR;

static inline DIR* opendir(const char* path) {
    std::string pat = std::string(path ? path : ".") + "\\*";
    DIR* d = new DIR();
    d->h = FindFirstFileA(pat.c_str(), &d->fd);
    if (d->h == INVALID_HANDLE_VALUE) { delete d; return nullptr; }
    return d;
}
static inline struct dirent* readdir(DIR* d) {
    if (!d) return nullptr;
    if (d->first) {
        d->first = false;
    } else if (!FindNextFileA(d->h, &d->fd)) {
        return nullptr;
    }
    strncpy(d->ent.d_name, d->fd.cFileName, MAX_PATH - 1);
    d->ent.d_name[MAX_PATH - 1] = 0;
    return &d->ent;
}
static inline void closedir(DIR* d) {
    if (!d) return;
    if (d->h != INVALID_HANDLE_VALUE) FindClose(d->h);
    delete d;
}

#ifndef POSIX_FADV_SEQUENTIAL
#define POSIX_FADV_SEQUENTIAL 2
#endif
static inline int posix_fadvise(int, long long, long long, int) { return 0; }

static inline void make_dirs(const std::string& path) {
    if (path.empty()) return;
    std::string cur;
    for (size_t i = 0; i <= path.size(); i++) {
        char c = i < path.size() ? path[i] : '/';
        if (c == '/' || c == '\\') {
            if (!cur.empty()) _mkdir(cur.c_str());
            if (i < path.size()) cur += '/';
        } else {
            cur += c;
        }
    }
}
#else
static inline void make_dirs(const std::string& path) {
    if (path.empty()) return;
    std::string cur;
    for (size_t i = 0; i <= path.size(); i++) {
        char c = i < path.size() ? path[i] : '/';
        if (c == '/' || c == '\\') {
            if (!cur.empty()) mkdir(cur.c_str(), 0755);
            if (i < path.size()) cur += '/';
        } else {
            cur += c;
        }
    }
}
#endif

static const int SCOOP_SIZE = 32;
static const int SCOOPS_PER_NONCE = 8192;
static const int HEADER_SIZE = 512;
static const uint32_t PLOT_FORMAT_V4 = 4;
static const std::string ZERO_HASH(64, '0');
static const double EFFECTIVE_CAPACITY_CAP_GB = 10 * 1024;
static const int SCAN_CHUNK_TARGET_BYTES = 32 * 1024 * 1024;

static const char* RESET = "\033[0m";
static const char* GREEN = "\033[92m";
static const char* CYAN = "\033[96m";
static const char* YELLOW = "\033[93m";
static const char* RED = "\033[91m";
static const char* BOLD = "\033[1m";
static const char* MAGENTA = "\033[95m";

static std::string g_wallet_path_override;
static std::string wallet_path() {
    if (!g_wallet_path_override.empty()) return g_wallet_path_override;
    const char* env = getenv("HOME");
    std::string base = env ? env : ".";
    return base + "/wallet.json";
}

static std::string hex_encode(const uint8_t* d, size_t n) {
    static const char* hc = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s += hc[d[i] >> 4];
        s += hc[d[i] & 15];
    }
    return s;
}
static bool hex_decode(const std::string& s, std::vector<uint8_t>& out) {
    std::string t = (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? s.substr(2) : s;
    if (t.size() % 2) return false;
    out.clear();
    out.reserve(t.size() / 2);
    auto hv = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < t.size(); i += 2) {
        int a = hv(t[i]), b = hv(t[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back((uint8_t)((a << 4) | b));
    }
    return true;
}
static std::string base64_encode(const uint8_t* d, size_t n) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)d[i] << 16;
        if (i + 1 < n) v |= (uint32_t)d[i+1] << 8;
        if (i + 2 < n) v |= d[i+2];
        s += T[(v >> 18) & 63];
        s += T[(v >> 12) & 63];
        s += (i + 1 < n) ? T[(v >> 6) & 63] : '=';
        s += (i + 2 < n) ? T[v & 63] : '=';
    }
    return s;
}
static std::string str_tolower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}
static std::string str_trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
static bool file_exists(const std::string& p) { struct stat st; return stat(p.c_str(), &st) == 0; }
#ifdef _WIN32
typedef struct _stat64 PlotStat;
#define plot_stat _stat64
static inline int fseek64(FILE* f, long long off, int whence) { return _fseeki64(f, off, whence); }
#else
typedef struct stat PlotStat;
#define plot_stat stat
static inline int fseek64(FILE* f, long long off, int whence) { return fseeko(f, (off_t)off, whence); }
#endif
static long long file_size(const std::string& p) { PlotStat st; return plot_stat(p.c_str(), &st) == 0 ? (long long)st.st_size : -1; }
static double mono_sec() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

struct Json {
    enum Type { Null, FalseT, TrueT, Num, Str, Arr, Obj } type = Null;
    double num = 0;
    std::string str;
    std::vector<Json> arr;
    std::map<std::string, Json> obj;
    bool is_null() const { return type == Null; }
    bool is_bool() const { return type == FalseT || type == TrueT; }
    bool is_num() const { return type == Num; }
    bool is_str() const { return type == Str; }
    bool is_arr() const { return type == Arr; }
    bool is_obj() const { return type == Obj; }
    bool truthy() const {
        switch (type) {
            case Null: case FalseT: return false;
            case TrueT: return true;
            case Num: return num != 0;
            case Str: return !str.empty();
            case Arr: return !arr.empty();
            case Obj: return !obj.empty();
        }
        return false;
    }
    const Json* get(const std::string& k) const {
        if (!is_obj()) return nullptr;
        auto it = obj.find(k);
        return it == obj.end() ? nullptr : &it->second;
    }
    std::string as_str(const std::string& d = "") const {
        if (is_str()) return str;
        if (is_num()) { char b[64]; snprintf(b, sizeof b, "%.17g", num); return b; }
        if (type == TrueT) return "true";
        if (type == FalseT) return "false";
        return d;
    }
    long long as_int(long long d = 0) const {
        if (is_num()) return (long long)num;
        if (is_str()) { try { return std::stoll(str); } catch (...) {} }
        if (is_bool()) return type == TrueT ? 1 : 0;
        return d;
    }
    double as_num(double d = 0) const {
        if (is_num()) return num;
        if (is_str()) { try { return std::stod(str); } catch (...) {} }
        return d;
    }
    std::string dump() const {
        std::string s;
        dump_to(s);
        return s;
    }
    void dump_to(std::string& s) const {
        switch (type) {
            case Null: s += "null"; break;
            case FalseT: s += "false"; break;
            case TrueT: s += "true"; break;
            case Num: {
                if (num == (long long)num && fabs(num) < 1e15) {
                    char b[32]; snprintf(b, sizeof b, "%lld", (long long)num); s += b;
                } else {
                    char b[64]; snprintf(b, sizeof b, "%.17g", num); s += b;
                }
                break;
            }
            case Str: {
                s += '"';
                for (char c : str) {
                    unsigned char uc = (unsigned char)c;
                    switch (c) {
                        case '"': s += "\\\""; break;
                        case '\\': s += "\\\\"; break;
                        case '\n': s += "\\n"; break;
                        case '\r': s += "\\r"; break;
                        case '\t': s += "\\t"; break;
                        default:
                            if (uc < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", uc); s += b; }
                            else s += c;
                    }
                }
                s += '"';
                break;
            }
            case Arr: {
                s += '[';
                for (size_t i = 0; i < arr.size(); i++) { if (i) s += ','; arr[i].dump_to(s); }
                s += ']';
                break;
            }
            case Obj: {
                s += '{';
                bool first = true;
                for (auto& kv : obj) {
                    if (!first) s += ',';
                    first = false;
                    Json k; k.type = Str; k.str = kv.first;
                    k.dump_to(s);
                    s += ':';
                    kv.second.dump_to(s);
                }
                s += '}';
                break;
            }
        }
    }
    static Json s(const std::string& v) { Json j; j.type = Str; j.str = v; return j; }
    static Json n(double v) { Json j; j.type = Num; j.num = v; return j; }
    static Json i(long long v) { Json j; j.type = Num; j.num = (double)v; return j; }
    static Json b(bool v) { Json j; j.type = v ? TrueT : FalseT; return j; }
    static Json object() { Json j; j.type = Obj; return j; }
    static Json array() { Json j; j.type = Arr; return j; }
};

struct JsonParser {
    const char* p;
    const char* end;
    JsonParser(const std::string& s) : p(s.data()), end(s.data() + s.size()) {}
    void ws() { while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++; }
    bool parse(Json& out) { ws(); return value(out); }
    bool value(Json& out) {
        if (p >= end) return false;
        char c = *p;
        if (c == 'n') { if (end - p >= 4 && memcmp(p, "null", 4) == 0) { p += 4; out.type = Json::Null; return true; } return false; }
        if (c == 't') { if (end - p >= 4 && memcmp(p, "true", 4) == 0) { p += 4; out.type = Json::TrueT; return true; } return false; }
        if (c == 'f') { if (end - p >= 5 && memcmp(p, "false", 5) == 0) { p += 5; out.type = Json::FalseT; return true; } return false; }
        if (c == '"') {
            p++;
            out.type = Json::Str;
            out.str.clear();
            while (p < end && *p != '"') {
                if (*p == '\\') {
                    p++;
                    if (p >= end) return false;
                    switch (*p) {
                        case 'n': out.str += '\n'; break;
                        case 'r': out.str += '\r'; break;
                        case 't': out.str += '\t'; break;
                        case 'b': out.str += '\b'; break;
                        case 'f': out.str += '\f'; break;
                        case '/': out.str += '/'; break;
                        case '\\': out.str += '\\'; break;
                        case '"': out.str += '"'; break;
                        case 'u': {
                            if (end - p < 5) return false;
                            unsigned code = 0;
                            for (int i = 0; i < 4; i++) {
                                char h = p[1 + i];
                                code <<= 4;
                                if (h >= '0' && h <= '9') code |= h - '0';
                                else if (h >= 'a' && h <= 'f') code |= h - 'a' + 10;
                                else if (h >= 'A' && h <= 'F') code |= h - 'A' + 10;
                                else return false;
                            }
                            p += 4;
                            if (code < 0x80) out.str += (char)code;
                            else if (code < 0x800) {
                                out.str += (char)(0xC0 | (code >> 6));
                                out.str += (char)(0x80 | (code & 63));
                            } else {
                                out.str += (char)(0xE0 | (code >> 12));
                                out.str += (char)(0x80 | ((code >> 6) & 63));
                                out.str += (char)(0x80 | (code & 63));
                            }
                            break;
                        }
                        default: return false;
                    }
                    p++;
                } else {
                    out.str += *p++;
                }
            }
            if (p >= end) return false;
            p++;
            return true;
        }
        if (c == '[') {
            p++;
            out.type = Json::Arr;
            out.arr.clear();
            ws();
            if (p < end && *p == ']') { p++; return true; }
            while (true) {
                Json v;
                if (!value(v)) return false;
                out.arr.push_back(std::move(v));
                ws();
                if (p < end && *p == ',') { p++; ws(); continue; }
                if (p < end && *p == ']') { p++; return true; }
                return false;
            }
        }
        if (c == '{') {
            p++;
            out.type = Json::Obj;
            out.obj.clear();
            ws();
            if (p < end && *p == '}') { p++; return true; }
            while (true) {
                ws();
                Json k;
                if (!value(k) || !k.is_str()) return false;
                ws();
                if (p >= end || *p != ':') return false;
                p++;
                ws();
                Json v;
                if (!value(v)) return false;
                out.obj[k.str] = std::move(v);
                ws();
                if (p < end && *p == ',') { p++; continue; }
                if (p < end && *p == '}') { p++; return true; }
                return false;
            }
        }
        const char* start = p;
        if (*p == '-') p++;
        if (p < end && *p == '0') p++;
        else while (p < end && isdigit((unsigned char)*p)) p++;
        if (p < end && *p == '.') { p++; while (p < end && isdigit((unsigned char)*p)) p++; }
        if (p < end && (*p == 'e' || *p == 'E')) {
            p++;
            if (p < end && (*p == '+' || *p == '-')) p++;
            while (p < end && isdigit((unsigned char)*p)) p++;
        }
        if (p == start) return false;
        out.type = Json::Num;
        out.num = strtod(std::string(start, p).c_str(), nullptr);
        return true;
    }
};

static bool json_parse(const std::string& s, Json& out) {
    JsonParser jp(s);
    if (!jp.parse(out)) return false;
    return true;
}

struct Sha256 {
    uint32_t h[8];
    uint64_t len_bytes;
    uint8_t buf[64];
    size_t buf_len;
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    Sha256() { reset(); }
    void reset() {
        h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
        h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
        len_bytes = 0; buf_len = 0;
    }
    void compress(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const uint8_t* data, size_t len) {
        len_bytes += len;
        while (len > 0) {
            size_t take = 64 - buf_len;
            if (take > len) take = len;
            memcpy(buf + buf_len, data, take);
            buf_len += take;
            data += take;
            len -= take;
            if (buf_len == 64) { compress(buf); buf_len = 0; }
        }
    }
    void final(uint8_t out[32]) {
        uint64_t bit_len = len_bytes * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buf_len != 56) update(&zero, 1);
        uint8_t lenbuf[8];
        for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(bit_len >> (56 - i*8));
        update(lenbuf, 8);
        for (int i = 0; i < 8; i++) {
            out[i*4]=(uint8_t)(h[i]>>24); out[i*4+1]=(uint8_t)(h[i]>>16);
            out[i*4+2]=(uint8_t)(h[i]>>8); out[i*4+3]=(uint8_t)h[i];
        }
    }
};
static void sha256(const uint8_t* d, size_t n, uint8_t out[32]) { Sha256 c; c.update(d, n); c.final(out); }
static void sha256(const std::vector<uint8_t>& v, uint8_t out[32]) { sha256(v.data(), v.size(), out); }

static void put_be32(uint8_t* out, uint32_t v) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8); out[3] = (uint8_t)v;
}
static void put_be64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint32_t get_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
static void put_le32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static void put_le64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

static bool canonical_seed(const std::string& chain_id, const std::string& miner,
                           const std::string& plot_id, uint64_t nonce_index, uint8_t seed[32]) {
    if (chain_id.empty() || (chain_id.size() > 1 && chain_id[0] == '0')) return false;
    for (char c : chain_id) if (c < '0' || c > '9') return false;
    if (chain_id.size() > 255) return false;
    std::vector<uint8_t> address, id;
    if (!hex_decode(miner, address) || address.size() != 20 ||
        !hex_decode(plot_id, id) || id.size() != 32) return false;

    uint8_t nonce[8];
    put_be64(nonce, nonce_index);
    std::vector<uint8_t> seed_data;
    static const char nonce_domain[] = "CCPOC:PLOT:V4:NONCE\0";
    seed_data.insert(seed_data.end(), nonce_domain, nonce_domain + sizeof(nonce_domain) - 1);
    seed_data.push_back((uint8_t)chain_id.size());
    seed_data.insert(seed_data.end(), chain_id.begin(), chain_id.end());
    seed_data.insert(seed_data.end(), address.begin(), address.end());
    seed_data.insert(seed_data.end(), id.begin(), id.end());
    seed_data.insert(seed_data.end(), nonce, nonce + sizeof(nonce));
    sha256(seed_data, seed);
    return true;
}

static void canonical_leaf_next(const uint8_t seed[32], uint16_t slot,
                               const uint8_t previous[32], uint8_t out[32]) {
    static const char leaf_domain[] = "CCPOC:PLOT:V4:LEAF\0";
    std::vector<uint8_t> input;
    input.reserve(sizeof(leaf_domain) - 1 + 32 + 2 + 32);
    input.insert(input.end(), leaf_domain, leaf_domain + sizeof(leaf_domain) - 1);
    input.insert(input.end(), seed, seed + 32);
    uint8_t slot_bytes[2] = { (uint8_t)(slot >> 8), (uint8_t)slot };
    input.insert(input.end(), slot_bytes, slot_bytes + sizeof(slot_bytes));
    input.insert(input.end(), previous, previous + 32);
    sha256(input, out);
}

static void canonical_leaf_for_slot(const uint8_t seed[32], uint16_t slot, uint8_t out[32]) {
    static const char leaf_domain[] = "CCPOC:PLOT:V4:LEAF\0";
    uint8_t slot_bytes[2] = { 0, 0 };
    std::vector<uint8_t> input;
    input.reserve(sizeof(leaf_domain) - 1 + 32 + 2);
    input.insert(input.end(), leaf_domain, leaf_domain + sizeof(leaf_domain) - 1);
    input.insert(input.end(), seed, seed + 32);
    input.insert(input.end(), slot_bytes, slot_bytes + sizeof(slot_bytes));
    sha256(input, out);
    for (uint16_t s = 1; s <= slot; ++s) {
        uint8_t next[32];
        canonical_leaf_next(seed, s, out, next);
        memcpy(out, next, sizeof(next));
    }
}

static bool canonical_leaf(const std::string& chain_id, const std::string& miner,
                           const std::string& plot_id, uint64_t index, uint8_t out[32]) {
    uint8_t seed[32];
    if (!canonical_seed(chain_id, miner, plot_id, index / SCOOPS_PER_NONCE, seed)) return false;
    canonical_leaf_for_slot(seed, (uint16_t)(index % SCOOPS_PER_NONCE), out);
    return true;
}

static bool v4_challenge_slot(const std::string& challenge_id, uint32_t& slot) {
    std::vector<uint8_t> id;
    if (!hex_decode(challenge_id, id) || id.size() != 32) return false;
    static const char domain[] = "CCPOC:CHALLENGE:V4\0";
    std::vector<uint8_t> input(domain, domain + sizeof(domain) - 1);
    input.insert(input.end(), id.begin(), id.end());
    uint8_t digest[32];
    sha256(input, digest);
    slot = (((uint32_t)digest[30] << 8) | digest[31]) & (SCOOPS_PER_NONCE - 1);
    return true;
}

static bool v4_sample_indexes(const std::string& challenge_id, uint64_t total_leaves,
                              const std::string& plot_id, std::vector<uint64_t>& out,
                              uint64_t excluded) {
    out.clear();
    std::vector<uint8_t> challenge, id;
    if (!hex_decode(challenge_id, challenge) || challenge.size() != 32 ||
        !hex_decode(plot_id, id) || id.size() != 32 || total_leaves == 0) return false;
    static const char domain[] = "CCPOC:SAMPLE:V4\0";
    uint8_t total[8], round[4] = {0, 0, 0, 4};
    put_be64(total, total_leaves);
    std::set<uint64_t> seen{excluded};
    // Mirror the node bound in deriveCapacitySampleIndexes, which throws when
    // counter > count*1024 + excluded.size*1024 + 1024 (count=16, excluded=1 -> 18432).
    const uint32_t work_bound = 16u * 1024u + 1024u + 1024u;
    for (uint32_t counter = 0; out.size() < 16 && counter <= work_bound; ++counter) {
        uint8_t cb[4]; put_be32(cb, counter);
        std::vector<uint8_t> input(domain, domain + sizeof(domain) - 1);
        input.insert(input.end(), challenge.begin(), challenge.end());
        input.insert(input.end(), id.begin(), id.end());
        input.insert(input.end(), total, total + sizeof(total));
        input.insert(input.end(), round, round + sizeof(round));
        input.insert(input.end(), cb, cb + sizeof(cb));
        uint8_t digest[32]; sha256(input, digest);
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i) value = (value << 8) | digest[i];
        // Node uses a 2^64 rejection bound before modulo. UINT64_MAX cannot represent 2^64.
        const uint64_t remainder = (uint64_t)(0 - total_leaves) % total_leaves;
        if (remainder && value > UINT64_MAX - remainder) continue;
        uint64_t index = value % total_leaves;
        if (seen.insert(index).second) out.push_back(index);
    }
    return out.size() == 16;
}

static inline uint64_t rotl64(uint64_t x, int n) { if (n == 0) return x; return (x << n) | (x >> (64 - n)); }
static void keccak_f1600(uint64_t st[25]) {
    static const uint64_t RC[24] = {
        0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
        0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
        0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
        0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
        0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
        0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
    };
    static const int R[25] = {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    };
    for (int round = 0; round < 24; round++) {
        uint64_t C[5], D[5], B[25];
        for (int x = 0; x < 5; x++)
            C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
        for (int x = 0; x < 5; x++)
            D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                st[x + 5*y] ^= D[x];
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                B[y + 5*((2*x + 3*y) % 5)] = rotl64(st[x + 5*y], R[x + 5*y]);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                st[x + 5*y] = B[x + 5*y] ^ ((~B[((x+1)%5) + 5*y]) & B[((x+2)%5) + 5*y]);
        st[0] ^= RC[round];
    }
}
static void keccak256(const uint8_t* data, size_t n, uint8_t out[32]) {
    uint64_t st[25] = {0};
    const size_t rate = 136;
    size_t off = 0;
    while (off + rate <= n) {
        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t v = 0;
            memcpy(&v, data + off + i*8, 8);
            st[i] ^= v;
        }
        keccak_f1600(st);
        off += rate;
    }
    uint8_t block[136] = {0};
    size_t rem = n - off;
    memcpy(block, data + off, rem);
    block[rem] = 0x01;
    block[rate - 1] |= 0x80;
    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t v = 0;
        memcpy(&v, block + i*8, 8);
        st[i] ^= v;
    }
    keccak_f1600(st);
    for (int i = 0; i < 4; i++) memcpy(out + i*8, &st[i], 8);
}
static void keccak256(const std::string& s, uint8_t out[32]) { keccak256((const uint8_t*)s.data(), s.size(), out); }

struct Hud {
    std::atomic<bool> active{false};
    std::string line;
    void show(const std::string& l) {
        if (!isatty(1)) return;
        line = l;
        printf("\r%80s\r%s", "", line.c_str());
        fflush(stdout);
    }
    void clear() {
        if (!isatty(1) || line.empty()) return;
        printf("\r%80s\r", "");
        fflush(stdout);
        line.clear();
    }
};
static Hud g_hud;
static FILE* g_log_fp = nullptr;
static std::mutex g_log_mu;
static void log_line(const char* color, const char* level, const std::string& msg) {
    char tbuf[32];
    time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tmv);
    std::lock_guard<std::mutex> lk(g_log_mu);
    g_hud.clear();
    fprintf(stdout, "%s [%s%s%s] %s\n", tbuf, color, level, RESET, msg.c_str());
    fflush(stdout);
    if (g_log_fp) {
        fprintf(g_log_fp, "%s [%s] %s\n", tbuf, level, msg.c_str());
        fflush(g_log_fp);
    }
}
static void log_info(const std::string& m) { log_line(GREEN, "INFO", m); }
static void log_warn(const std::string& m) { log_line(YELLOW, "WARNING", m); }
static void log_error(const std::string& m) { log_line(RED, "ERROR", m); }
static void log_debug(const std::string& m) { log_line(CYAN, "DEBUG", m); }
static void log_win(const std::string& m) { log_line(GREEN, "WIN", m); }

static void notify(const std::string& title, const std::string& body) {
    if (system("command -v termux-notification >/dev/null 2>&1") != 0) return;
    auto shell_quote = [](const std::string& value) {
        std::string quoted = "'";
        for (char c : value) {
            if (c == '\'') quoted += "'\\''";
            else quoted += c;
        }
        quoted += "'";
        return quoted;
    };
    std::string cmd = "termux-notification --title " + shell_quote(title) + " --content " + shell_quote(body) + " --id choco-miner >/dev/null 2>&1 &";
    (void)system(cmd.c_str());
}

static std::string fmt_dur(long long s) {
    char b[32];
    if (s >= 3600) snprintf(b, sizeof b, "%lldh%02lldm", s / 3600, (s % 3600) / 60);
    else if (s >= 60) snprintf(b, sizeof b, "%lldm%02llds", s / 60, s % 60);
    else snprintf(b, sizeof b, "%llds", s);
    return b;
}

static FILE* g_csv = nullptr;
static void csv_stats(long long height, long long deadline, long long best, double mbps,
                      long long uptime, size_t plots) {
    if (!g_csv) return;
    fprintf(g_csv, "%ld,%lld,%lld,%lld,%.2f,%lld,%zu\n", (long)time(nullptr), height,
            deadline, best, mbps, uptime, plots);
    fflush(g_csv);
}

struct Wallet {
    std::string address;
    std::string public_key; 
    std::string private_key;
    bool valid = false;
};

using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

static std::string derive_address_from_pubbytes(const std::vector<uint8_t>& pub) {
    if (pub.size() == 64) {
        uint8_t h[32];
        keccak256(pub.data(), pub.size(), h);
        return "0x" + hex_encode(h + 12, 20);
    }
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) return "";
    EC_POINT* pt = EC_POINT_new(group);
    BN_CTX* ctx = BN_CTX_new();
    std::string out;
    if (EC_POINT_oct2point(group, pt, pub.data(), pub.size(), ctx)) {
        uint8_t buf[65];
        size_t n = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
        if (n == 65) {
            uint8_t h[32];
            keccak256(buf + 1, 64, h);
            out = "0x" + hex_encode(h + 12, 20);
        }
    }
    EC_POINT_free(pt);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return out;
}

static Wallet load_wallet_file(const std::string& path) {
    Wallet w;
    std::ifstream f(path);
    if (!f) return w;
    f.seekg(0, std::ios::end);
    const std::streamoff size = f.tellg();
    if (size <= 0 || size > 64 * 1024) return w;
    f.seekg(0, std::ios::beg);
    std::stringstream ss;
    ss << f.rdbuf();
    Json j;
    if (!json_parse(ss.str(), j) || !j.is_obj()) return w;
    if (const Json* a = j.get("address")) w.address = a->as_str();
    if (w.address.empty())
        if (const Json* a = j.get("wallet_address")) w.address = a->as_str();
    if (const Json* k = j.get("publicKey")) w.public_key = k->as_str();
    if (w.public_key.empty())
        if (const Json* k = j.get("public_key")) w.public_key = k->as_str();
    if (const Json* k = j.get("privateKey")) w.private_key = k->as_str();
    if (w.private_key.empty())
        if (const Json* k = j.get("private_key")) w.private_key = k->as_str();
    w.valid = !w.address.empty() || !w.public_key.empty();
    return w;
}

static void write_wallet_file(const std::string& path, const Wallet& w) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); return; }
    fprintf(f, "{\n  \"address\": \"%s\",\n  \"publicKey\": \"%s\",\n  \"privateKey\": \"%s\"\n}\n",
            w.address.c_str(), w.public_key.c_str(), w.private_key.c_str());
    fclose(f);
    chmod(path.c_str(), 0600);
}

static bool generate_keypair(std::string& priv_hex, std::string& pub_hex) {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return false;
    if (!EC_KEY_generate_key(key)) { EC_KEY_free(key); return false; }
    const BIGNUM* priv = EC_KEY_get0_private_key(key);
    char* ph = BN_bn2hex(priv);
    std::string p = ph ? ph : "";
    if (ph) OPENSSL_free(ph);
    while (p.size() < 64) p = "0" + p;
    priv_hex = str_tolower(p);
    const EC_POINT* pub = EC_KEY_get0_public_key(key);
    EC_GROUP* g = (EC_GROUP*)EC_KEY_get0_group(key);
    BN_CTX* ctx = BN_CTX_new();
    uint8_t buf[33];
    size_t n = EC_POINT_point2oct(g, pub, POINT_CONVERSION_COMPRESSED, buf, 33, ctx);
    if (n == 33) pub_hex = hex_encode(buf, 33);
    BN_CTX_free(ctx);
    EC_KEY_free(key);
    return !pub_hex.empty();
}

struct MinerKey {
    EC_KEY* key = nullptr;    
    ~MinerKey() { if (key) EC_KEY_free(key); }
};

static MinerKey* load_private_key(const std::string& priv_hex) {
    std::vector<uint8_t> raw;
    if (!hex_decode(priv_hex, raw) || raw.size() != 32) return nullptr;
    BIGNUM* priv = BN_bin2bn(raw.data(), 32, nullptr);
    if (!priv) return nullptr;
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) { BN_free(priv); return nullptr; }
    if (EC_KEY_set_private_key(key, priv) != 1) {
        BN_free(priv); EC_KEY_free(key); return nullptr;
    }
    EC_GROUP* g = (EC_GROUP*)EC_KEY_get0_group(key);
    EC_POINT* pub = EC_POINT_new(g);
    BN_CTX* ctx = BN_CTX_new();
    if (EC_POINT_mul(g, pub, priv, nullptr, nullptr, ctx) != 1 ||
        EC_KEY_set_public_key(key, pub) != 1) {
        EC_POINT_free(pub); BN_CTX_free(ctx); BN_free(priv); EC_KEY_free(key); return nullptr;
    }
    EC_POINT_free(pub);
    BN_CTX_free(ctx);
    BN_free(priv);
    auto* mk = new MinerKey();
    mk->key = key;
    return mk;
}

static std::string sign_proof_message(const std::string& message, MinerKey* mk) {
    if (!mk || !mk->key) return "";
    uint8_t digest[32];
    keccak256(message, digest);
    ECDSA_SIG* sig = ECDSA_do_sign(digest, 32, mk->key);
    if (!sig) return "";
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    BIGNUM* n = nullptr;
    BN_hex2bn(&n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    BIGNUM* halfn = BN_dup(n);
    BN_rshift1(halfn, halfn);
    BIGNUM* s_copy = BN_dup(s);
    if (BN_cmp(s_copy, halfn) > 0) {
        BN_sub(s_copy, n, s_copy);
    }
    uint8_t sig65[65];
    sig65[0] = 0;
    BN_bn2binpad(r, sig65 + 1, 32);
    BN_bn2binpad(s_copy, sig65 + 33, 32);
    std::string b64 = base64_encode(sig65, 65);
    BN_free(n); BN_free(halfn); BN_free(s_copy);
    ECDSA_SIG_free(sig);
    return b64;
}

static std::string pub_compressed_hex(MinerKey* mk) {
    if (!mk || !mk->key) return "";
    EC_GROUP* g = (EC_GROUP*)EC_KEY_get0_group(mk->key);
    const EC_POINT* pub = EC_KEY_get0_public_key(mk->key);
    BN_CTX* ctx = BN_CTX_new();
    uint8_t buf[33];
    size_t n = EC_POINT_point2oct(g, pub, POINT_CONVERSION_COMPRESSED, buf, 33, ctx);
    BN_CTX_free(ctx);
    return n == 33 ? hex_encode(buf, 33) : "";
}

static std::string proof_message(const std::string& challenge_id, const std::string& miner,
                                 long long deadline, const std::string& plot_id) {
    Json d = Json::object();
    d.obj["challenge_id"] = Json::s(challenge_id);
    d.obj["deadline"] = Json::s(std::to_string(deadline));
    d.obj["miner"] = Json::s(str_tolower(miner));
    d.obj["plot_id"] = Json::s(plot_id);
    d.obj["type"] = Json::s("poc_proof");
    return d.dump();
}

static std::string g_user_agent = [] {
    const char* e = getenv("USER_AGENT");
    return e ? e : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
}();
struct HttpResp {
    long code = 0;
    std::string body;
    bool ok = false;
};

static size_t curl_write_cb(char* p, size_t sz, size_t n, void* ud) {
    auto* s = (std::string*)ud;
    constexpr size_t MAX_HTTP_BODY = 8 * 1024 * 1024;
    if (sz != 0 && n > (MAX_HTTP_BODY - std::min(MAX_HTTP_BODY, s->size())) / sz) return 0;
    const size_t bytes = sz * n;
    if (s->size() + bytes > MAX_HTTP_BODY) return 0;
    s->append(p, bytes);
    return bytes;
}

static HttpResp http_raw(const std::string& method, const std::string& url, const std::string& body,
                         int timeout, bool /*verify_ssl*/) {
    HttpResp r;
    CURL* c = curl_easy_init();
    if (!c) return r;
    std::string out;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT, g_user_agent.c_str());
    curl_easy_setopt(c, CURLOPT_TIMEOUT, (long)timeout);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    struct curl_slist* hdr = nullptr;
    if (!body.empty()) {
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body.size());
        hdr = curl_slist_append(hdr, "Content-Type: application/json");
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    }
    CURLcode rc = curl_easy_perform(c);
    if (rc == CURLE_OK) {
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.code);
        r.body = std::move(out);
        r.ok = true;
    }
    if (hdr) curl_slist_free_all(hdr);
    curl_easy_cleanup(c);
    return r;
}

static bool http_json(const std::string& method, const std::string& url, const Json* payload,
                      Json& out, int timeout = 10, int retries = 3, bool verify_ssl = true,
                      bool quiet_4xx = false) {
    for (int attempt = 0; attempt < retries; attempt++) {
        HttpResp r = http_raw(method, url, payload ? payload->dump() : std::string(), timeout, verify_ssl);
        if (r.ok) {
            if (r.code == 404 && quiet_4xx) return false;
            if (r.code >= 400 && r.code < 500 && r.code != 429) {
                log_error(method + " " + url + " -> HTTP " + std::to_string(r.code) + ": " + r.body.substr(0, 500));
                return false;
            }
            if (r.code >= 200 && r.code < 300) {
                if (json_parse(r.body, out)) return true;
                log_error("Invalid JSON from " + url + ": " + r.body.substr(0, 200));
                return false;
            }
            long wait = 1L << attempt;
            log_warn("Request failed (attempt " + std::to_string(attempt + 1) + "/" + std::to_string(retries) +
                     "): HTTP " + std::to_string(r.code) + " " + r.body.substr(0, 200) +
                     ", retrying in " + std::to_string(wait) + "s");
            sleep(wait);
        } else {
            long wait = 1L << attempt;
            log_warn("Request failed (attempt " + std::to_string(attempt + 1) + "/" + std::to_string(retries) +
                     "): network error, retrying in " + std::to_string(wait) + "s");
            sleep(wait);
        }
    }
    return false;
}

static bool http_get(const std::string& url, Json& out, int timeout = 10, int retries = 3, bool verify_ssl = true) {
    return http_json("GET", url, nullptr, out, timeout, retries, verify_ssl, false);
}
static bool http_post(const std::string& url, const Json& payload, Json& out, bool verify_ssl = true, bool quiet_4xx = false, int timeout = 10) {
    return http_json("POST", url, &payload, out, timeout, 3, verify_ssl, quiet_4xx);
}

static bool fetch_balance(const std::string& base, const std::string& addr, bool verify_ssl, double& bal) {
    Json r;
    if (!http_get(base + "/api/accounts?address=" + addr, r, 10, 1, verify_ssl)) return false;
    if (const Json* b = r.get("balance")) {
        bal = (double)b->as_int(0) / 1e18;
        return true;
    }
    return false;
}

static bool fetch_block(const std::string& base, long long height, bool verify_ssl, Json& blk) {
    Json r;
    if (!http_get(base + "/api/block/" + std::to_string(height), r, 5, 1, verify_ssl)) return false;
    if (r.get("height") || r.get("block_height")) { blk = std::move(r); return true; }
    return false;
}

static bool fetch_mature_plot_roots(const std::string& base, const std::string& miner,
                                    bool verify_ssl, std::map<std::string, std::string>& roots) {
    roots.clear();
    Json response;
    if (!http_get(base + "/api/poc/plots/" + str_tolower(miner), response, 5, 1, verify_ssl)) return false;
    const Json* plots = response.get("plots");
    if (!plots || !plots->is_arr()) return false;
    for (const auto& plot : plots->arr) {
        const Json* id = plot.get("plot_id");
        const Json* root = plot.get("merkle_root");
        if (!id || !root) continue;
        std::string plot_id = str_tolower(id->as_str());
        std::string merkle_root = str_tolower(root->as_str());
        if (plot_id.size() == 64 && merkle_root.size() == 64) roots[plot_id] = merkle_root;
    }
    return true;
}

static long long plot_scoop_count(double size_gb) {
    if (!std::isfinite(size_gb) || size_gb <= 0) return 0;
    const long double bytes = (long double)size_gb * 1024.0L * 1024.0L * 1024.0L;
    if (bytes > (long double)10 * 1024 * 1024 * 1024 * 1024) return 0;
    const long double leaves = bytes / SCOOP_SIZE;
    const long double rounded = std::round(leaves);
    if (std::fabs(leaves - rounded) > 0.000001L || rounded < SCOOPS_PER_NONCE ||
        std::fmod(rounded, SCOOPS_PER_NONCE) != 0) return 0;
    return (long long)rounded;
}
static long long merkle_tree_internal_node_count(long long n) {
    long long total = 0;
    while (n > 1) {
        n = (n + 1) / 2;
        total += n;
    }
    return total;
}
static long long plot_total_size(long long total_scoops) {
    return HEADER_SIZE + total_scoops * SCOOP_SIZE + merkle_tree_internal_node_count(total_scoops) * 32;
}

struct Tier { double lo, hi; const char* id; double mult; };
static const Tier TIERS[] = {
    {0, 32, "tier_1", 1.0},
    {32, 500, "tier_2", 1.6},
    {500, 5120, "tier_3", 2.4},
    {5120, EFFECTIVE_CAPACITY_CAP_GB, "tier_4", 3.2},
    {EFFECTIVE_CAPACITY_CAP_GB, 1e18, "tier_5", 3.2},
};
static double compute_effective_capacity_gb(double size_gb) {
    double size = std::max(0.001, size_gb);
    double capped = std::min(size, EFFECTIVE_CAPACITY_CAP_GB);
    double mult = 1.0;
    for (auto& t : TIERS)
        if (t.lo <= size && size < t.hi) { mult = t.mult; break; }
    static const double bp[] = {0, 32, 500, 5120, EFFECTIVE_CAPACITY_CAP_GB};
    double total = 0;
    for (int i = 0; i < 4; i++) {
        if (capped <= bp[i]) break;
        double seg = std::min(capped, bp[i+1]) - bp[i];
        total += sqrt(seg);
        if (capped <= bp[i+1]) break;
    }
    return total * mult;
}
static long long compute_deadline(const uint8_t* scoop, size_t scoop_len,
                                  const std::vector<uint8_t>& sig, long long bt) {
    Sha256 c;
    c.update(scoop, scoop_len);
    if (!sig.empty()) c.update(sig.data(), sig.size());
    uint8_t d[32];
    c.final(d);
    uint64_t q = 0;
    for (int i = 0; i < 8; i++) q = (q << 8) | d[i];
    long long dl = (long long)(q / (uint64_t)std::max(1LL, bt));
    return std::max(1LL, std::min(dl, 86400LL));
}

struct PlotMeta {
    std::string path;
    uint64_t total_scoops = 0;
    std::string plot_id;
    std::string merkle_root;
    uint32_t version = 0;
    uint32_t scoop_size = 32;
    std::string miner;
    std::string chain_id;
    bool valid = false;
};

static PlotMeta get_plot_meta(const std::string& path) {
    PlotStat st;
    if (plot_stat(path.c_str(), &st) != 0) return PlotMeta{};
    PlotMeta m;
    m.path = path;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return m;
    uint8_t hdr[HEADER_SIZE] = {0};
    size_t got = fread(hdr, 1, HEADER_SIZE, f);
    fclose(f);
    if (got != HEADER_SIZE || memcmp(hdr, "CCPOC4PL", 8) != 0) return m;
    m.version = get_le32(hdr + 8);
    m.scoop_size = get_le32(hdr + 12);
    m.total_scoops = get_le64(hdr + 16);
    m.plot_id = hex_encode(hdr + 32, 32);
    m.miner = "0x" + hex_encode(hdr + 64, 20);
    m.merkle_root = hex_encode(hdr + 84, 32);
    const uint8_t chain_len = hdr[116];
    if (chain_len == 0) return m;
    m.chain_id.assign((const char*)hdr + 120, chain_len);
    if (m.version != PLOT_FORMAT_V4 || m.scoop_size != SCOOP_SIZE ||
        m.total_scoops < SCOOPS_PER_NONCE || m.total_scoops % SCOOPS_PER_NONCE != 0 ||
        m.total_scoops > (uint64_t)(10LL * 1024 * 1024 * 1024 * 1024 / SCOOP_SIZE)) return m;
    long long expected = plot_total_size(m.total_scoops);
    if (st.st_size != expected) { log_error("Plot " + path + " size mismatch"); return PlotMeta{}; }
    if (m.plot_id == std::string(64, '0') || m.merkle_root == ZERO_HASH) return PlotMeta{};
    m.valid = true;
    return m;
}

static bool check_disk_space(const std::string& plot_path, double required) {
    std::string dir = plot_path;
    auto slash = dir.find_last_of('/');
    if (slash != std::string::npos) dir = dir.substr(0, slash); else dir = ".";
    struct statvfs vs;
    if (statvfs(dir.c_str(), &vs) != 0) return true;
    double free_b = (double)vs.f_frsize * vs.f_bavail;
    if (free_b < required) {
        char b[128];
        snprintf(b, sizeof b, "Not enough disk space: %.2f GB free, need %.2f GB", free_b/1e9, required/1e9);
        log_error(b);
        return false;
    }
    return true;
}

static void log_progress(const char* stage, long long current, long long total,
                         double elapsed = -1, double total_bytes = -1) {
    int pct = total > 0 ? (int)std::min(100.0, std::max(0.0, current * 100.0 / total)) : 100;
    int width = 32;
    int filled = std::max(0, std::min(width, pct * width / 100));
    std::string bar(filled, '#');
    bar += std::string(width - filled, '-');
    std::string line = "  [" + std::string(stage) + "] [" + bar + "] " + std::to_string(pct) + "%";
    if (elapsed > 0.5) {
        if (std::string(stage) == "WRIT" && total_bytes > 0) {
            double mbps = (total_bytes * pct / 100.0) / elapsed / 1e6;
            char b[64]; snprintf(b, sizeof b, " | %.1f MB/s", mbps);
            line += b;
            if (pct < 100 && pct > 0) {
                double rem = elapsed / pct * (100 - pct);
                char e[32]; snprintf(e, sizeof e, " | ETA %dm%02ds", (int)(rem/60), (int)rem % 60);
                line += e;
            }
        } else {
            double rate = current / elapsed;
            char b[64]; snprintf(b, sizeof b, " | %.0f items/s", rate);
            line += b;
            if (pct < 100 && pct > 0) {
                double rem = elapsed / pct * (100 - pct);
                char e[32]; snprintf(e, sizeof e, " | ETA %dm%02ds", (int)(rem/60), (int)rem % 60);
                line += e;
            }
        }
    }
    if (isatty(1)) {
        printf("\r%s", line.c_str());
        fflush(stdout);
        if (pct >= 100) printf("\n");
    } else {
        log_info(line);
    }
}

static std::vector<uint8_t> g_random_bytes(size_t n) {
    std::vector<uint8_t> b(n);
    RAND_bytes(b.data(), (int)n);
    return b;
}
static std::string random_hex(size_t n) {
    auto b = g_random_bytes(n);
    return hex_encode(b.data(), n);
}

struct PlotResult {
    std::string plot_id;
    double size_gb = 0;
    long long total_scoops = 0;
    std::string merkle_root;
    bool ok = false;
    std::string path;
};

struct PlotTempCleanup {
    std::vector<std::string> paths;
    ~PlotTempCleanup() {
        for (const auto& path : paths) if (!path.empty()) unlink(path.c_str());
    }
};

static bool cp_merkle_parallel_pass(const std::string& in_path, const std::string& out_path,
                                    long long count, int workers) {
    long long new_len = (count + 1) / 2;
    FILE* in = fopen(in_path.c_str(), "rb");
    FILE* out = fopen(out_path.c_str(), "wb");
    if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return false; }
    const long long CHUNK = 256 * 1024;
    std::atomic<long long> next{0};
    std::map<long long, std::vector<uint8_t>> results;
    std::mutex res_mu;
    std::mutex input_mu;
    std::atomic<bool> read_failed{false};
    long long total_chunks = (new_len + CHUNK - 1) / CHUNK;
    auto worker = [&]() {
        while (true) {
            long long ci = next.fetch_add(1);
            if (ci >= total_chunks) break;
            long long start = ci * CHUNK;
            long long cnt = std::min(CHUNK, new_len - start);
            std::vector<uint8_t> raw(cnt * 64);
            std::vector<uint8_t> outb(cnt * 32);
            {
                std::lock_guard<std::mutex> input_lock(input_mu);
                const long long first_leaf = start * 2;
                const long long leaves_to_read = std::min(cnt * 2, count - first_leaf);
                const size_t bytes_to_read = (size_t)leaves_to_read * 32;
                if (fseek64(in, first_leaf * 32, SEEK_SET) != 0 || fread(raw.data(), 1, bytes_to_read, in) != bytes_to_read) {
                    read_failed.store(true);
                    break;
                }
                if (leaves_to_read < cnt * 2) {
                    memcpy(raw.data() + (size_t)leaves_to_read * 32,
                           raw.data() + (size_t)(leaves_to_read - 1) * 32, 32);
                }
            }
            for (long long i = 0; i < cnt; i++)
                sha256(raw.data() + i * 64, 64, outb.data() + i * 32);
            std::lock_guard<std::mutex> lk(res_mu);
            results[ci] = std::move(outb);
        }
    };
    std::vector<std::thread> ths;
    for (int i = 0; i < workers; i++) ths.emplace_back(worker);
    for (auto& t : ths) t.join();
    bool write_ok = !read_failed.load();
    for (long long ci = 0; ci < total_chunks && write_ok; ci++) {
        auto it = results.find(ci);
        if (it == results.end() || fwrite(it->second.data(), 1, it->second.size(), out) != it->second.size()) write_ok = false;
    }
    if (ferror(in) || ferror(out)) write_ok = false;
    if (fclose(in) != 0) write_ok = false;
    if (fflush(out) != 0 || ferror(out)) write_ok = false;
    if (fclose(out) != 0) write_ok = false;
    return write_ok;
}


static PlotResult create_plot_file(const std::string& plot_path, const std::string& plot_id,
                                   const std::string& miner_address, const std::string& chain_id,
                                   double size_gb, bool progress) {
    PlotResult res;
    long long total_scoops = plot_scoop_count(size_gb);
    if (total_scoops < SCOOPS_PER_NONCE) {
        log_error("v4 plot capacity must be an exact multiple of 256 KiB, from 256 KiB through 10 TiB");
        return res;
    }
    std::vector<uint8_t> address, plot_id_bytes;
    if (!hex_decode(miner_address, address) || address.size() != 20 ||
        !hex_decode(plot_id, plot_id_bytes) || plot_id_bytes.size() != 32 ||
        chain_id.empty() || chain_id.size() > 255) {
        log_error("Invalid v4 chain ID, miner address, or 32-byte plot ID");
        return res;
    }
    for (char c : chain_id) if (c < '0' || c > '9') { log_error("chain_id must be canonical unsigned decimal"); return res; }
    if (chain_id.size() > 1 && chain_id[0] == '0') { log_error("chain_id must be canonical unsigned decimal"); return res; }
    std::string dir = plot_path;
    auto sl = dir.find_last_of('/');
    if (sl != std::string::npos) {
        std::string d = dir.substr(0, sl);
        make_dirs(d);
    }
    long long plot_size = plot_total_size(total_scoops);
    if (file_exists(plot_path)) {
        log_error("Refusing to overwrite existing plot: " + plot_path);
        return res;
    }
    if (!check_disk_space(plot_path, plot_size * 1.3)) return res;

    log_info("Plot ID: " + plot_id + ", Miner: " + miner_address + ", chain_id=" + chain_id);
    {
        char b[128];
        snprintf(b, sizeof b, "Total scoops: %lld, File size: %.2f GB", total_scoops, plot_size/1e9);
        log_info(b);
    }

    int workers = std::max(1, (int)std::thread::hardware_concurrency() - 1);
    if (const char* tn = getenv("THREAD_NUMBER")) { int v = atoi(tn); if (v > 0) workers = v; }
    workers = std::min(workers, 64);

    std::string leaf_path = plot_path + ".tmp.leaf";
    std::string merkle_all = plot_path + ".tmp.merkle_all";
    std::string staging_path = plot_path + ".tmp.plot";
    PlotTempCleanup temp_cleanup;
    temp_cleanup.paths = {leaf_path, merkle_all, staging_path};
    std::string root = ZERO_HASH;
    double t0 = mono_sec();
    double t1 = t0, t2 = t0;

    {
        log_info("  [HASH] Computing SHA-256 leaf hashes (parallel)...");
        long long leaf_count = 0;
        FILE* lf = fopen(leaf_path.c_str(), "wb");
        if (!lf) { log_error("Cannot open leaf file"); return res; }
        const long long BATCH = (500000 / SCOOPS_PER_NONCE) * SCOOPS_PER_NONCE;
        int last_log = 0;
        while (leaf_count < total_scoops) {
            long long batch = std::min(BATCH, total_scoops - leaf_count);
            std::vector<std::vector<uint8_t>> parts(workers);
            std::atomic<int> wi{0};
            auto work = [&]() {
                while (true) {
                    int ci = wi.fetch_add(1);
                    if (ci >= workers) break;
                    const long long nonce_count = batch / SCOOPS_PER_NONCE;
                    const long long nonces_per_chunk = std::max(1LL, (nonce_count + workers - 1) / workers);
                    const long long nonce_offset = ci * nonces_per_chunk;
                    const long long chunk_nonces = std::min(nonces_per_chunk, nonce_count - nonce_offset);
                    if (chunk_nonces <= 0) { parts[ci].clear(); continue; }
                    const long long offset = nonce_offset * SCOOPS_PER_NONCE;
                    const long long cs = chunk_nonces * SCOOPS_PER_NONCE;
                    parts[ci].resize(cs * 32);
                    uint64_t cached_nonce = UINT64_MAX;
                    uint8_t nonce_seed[32];
                    uint8_t previous_leaf[32];
                    uint32_t next_slot = 0;
                    for (long long i = 0; i < cs; ++i) {
                        const uint64_t index = (uint64_t)(leaf_count + offset + i);
                        const uint64_t nonce = index / SCOOPS_PER_NONCE;
                        if (nonce != cached_nonce) {
                            if (!canonical_seed(chain_id, miner_address, plot_id, nonce, nonce_seed)) {
                                parts[ci].clear();
                                break;
                            }
                            const uint16_t slot = (uint16_t)(index % SCOOPS_PER_NONCE);
                            canonical_leaf_for_slot(nonce_seed, slot, previous_leaf);
                            cached_nonce = nonce;
                            next_slot = (uint32_t)slot + 1;
                        } else {
                            uint8_t next[32];
                            canonical_leaf_next(nonce_seed, (uint16_t)next_slot, previous_leaf, next);
                            memcpy(previous_leaf, next, sizeof(next));
                            ++next_slot;
                        }
                        memcpy(parts[ci].data() + (size_t)i * 32, previous_leaf, sizeof(previous_leaf));
                    }
                }
            };
            std::vector<std::thread> ths;
            for (int i = 0; i < workers; i++) ths.emplace_back(work);
            for (auto& t : ths) t.join();
            bool write_ok = true;
            size_t batch_written = 0;
            for (int ci = 0; ci < workers; ci++) {
                if (!parts[ci].empty()) {
                    const size_t n = fwrite(parts[ci].data(), 1, parts[ci].size(), lf);
                    batch_written += n;
                    if (n != parts[ci].size()) write_ok = false;
                }
            }
            if (batch_written != (size_t)batch * SCOOP_SIZE) write_ok = false;
            if (!write_ok) { fclose(lf); log_error("Short write while creating v4 leaves"); return res; }
            leaf_count += batch;
            int pct = (int)(leaf_count * 100 / total_scoops);
            if (progress && pct >= last_log + 1) {
                last_log = pct;
                log_progress("HASH", leaf_count, total_scoops);
            }
        }
        const bool leaves_flushed = fflush(lf) == 0 && !ferror(lf);
        const int leaves_close_result = fclose(lf);
        if (!leaves_flushed || leaves_close_result != 0) {
            log_error("Failed to flush complete v4 leaf file");
            return res;
        }
        t1 = mono_sec();
        char b[64]; snprintf(b, sizeof b, "  [HASH] 100%% done (%.1fs)", t1 - t0);
        log_info(b);
    }

    long long current_count = total_scoops;
    std::string input_path = leaf_path;
    int level = 0;
    int est_levels = 1;
    while ((1LL << (est_levels - 1)) < current_count) est_levels++;
    {
        FILE* mf = fopen(merkle_all.c_str(), "wb");
        if (!mf) { log_error("Cannot open merkle file"); return res; }
        int last_log = 0;
        while (current_count > 1) {
            std::string out_path = plot_path + ".tmp.merk" + std::to_string(level);
            temp_cleanup.paths.push_back(out_path);
            if (!cp_merkle_parallel_pass(input_path, out_path, current_count, workers)) {
                fclose(mf);
                log_error("Failed to compute v4 Merkle level from complete input leaves");
                return res;
            }
            if (input_path != leaf_path) unlink(input_path.c_str());
            input_path = out_path;
            FILE* rf = fopen(out_path.c_str(), "rb");
            if (!rf) { fclose(mf); log_error("Could not read completed v4 Merkle level"); return res; }
            std::vector<uint8_t> buf(4 * 1024 * 1024);
            size_t n;
            bool level_ok = true;
            while ((n = fread(buf.data(), 1, buf.size(), rf)) > 0) {
                if (fwrite(buf.data(), 1, n, mf) != n) { level_ok = false; break; }
            }
            if (ferror(rf)) level_ok = false;
            fclose(rf);
            if (!level_ok) { fclose(mf); log_error("Short read/write while assembling v4 Merkle levels"); return res; }
            current_count = (current_count + 1) / 2;
            level++;
            int pct = std::min(99, level * 100 / est_levels);
            if (progress && pct >= last_log + 1) { last_log = pct; log_progress("MERK", level, est_levels); }
        }
        const bool merkle_flushed = fflush(mf) == 0 && !ferror(mf);
        const int merkle_close_result = fclose(mf);
        if (!merkle_flushed || merkle_close_result != 0) {
            log_error("Failed to flush complete v4 Merkle levels");
            return res;
        }
        FILE* rf = fopen(input_path.c_str(), "rb");
        if (!rf) { log_error("Could not read v4 Merkle root"); return res; }
        uint8_t rd[32];
        const bool root_ok = fread(rd, 1, sizeof(rd), rf) == sizeof(rd) && !ferror(rf);
        fclose(rf);
        if (!root_ok) { log_error("Short read of v4 Merkle root"); return res; }
        root = hex_encode(rd, 32);
        if (root == ZERO_HASH) { log_error("Invalid all-zero v4 Merkle root"); return res; }
        unlink(input_path.c_str());
        t2 = mono_sec();
        char b[128]; snprintf(b, sizeof b, "  [MERK] 100%% done (%.1fs) root=%s...", t2 - t1, root.substr(0,32).c_str());
        log_info(b);
    }

    log_info("  [WRIT] Writing canonical v4 plot file...");
    std::vector<uint8_t> root_bytes;
    if (!hex_decode(root, root_bytes) || root_bytes.size() != 32) {
        log_error("Invalid v4 Merkle root");
        return res;
    }
    uint8_t header[HEADER_SIZE] = {0};
    memcpy(header, "CCPOC4PL", 8);
    put_le32(header + 8, PLOT_FORMAT_V4);
    put_le32(header + 12, SCOOP_SIZE);
    put_le64(header + 16, (uint64_t)total_scoops);
    memcpy(header + 32, plot_id_bytes.data(), 32);
    memcpy(header + 64, address.data(), 20);
    memcpy(header + 84, root_bytes.data(), 32);
    header[116] = (uint8_t)chain_id.size();
    memcpy(header + 120, chain_id.data(), chain_id.size());
    FILE* f = fopen(staging_path.c_str(), "wb");
    if (!f) { log_error("Cannot create v4 plot file"); return res; }
    bool write_ok = fwrite(header, 1, sizeof(header), f) == sizeof(header);
    const std::string parts_to_append[] = {leaf_path, merkle_all};
    std::vector<uint8_t> copy_buf(4 * 1024 * 1024);
    for (const auto& part : parts_to_append) {
        FILE* src = fopen(part.c_str(), "rb");
        if (!src) { write_ok = false; break; }
        size_t nread;
        while ((nread = fread(copy_buf.data(), 1, copy_buf.size(), src)) > 0) {
            if (fwrite(copy_buf.data(), 1, nread, f) != nread) { write_ok = false; break; }
        }
        if (ferror(src)) write_ok = false;
        fclose(src);
        if (!write_ok) break;
    }
    if (fflush(f) != 0 || ferror(f)) write_ok = false;
    if (fclose(f) != 0) write_ok = false;
    unlink(leaf_path.c_str());
    unlink(merkle_all.c_str());
    for (int l = 0; l < level; ++l) unlink((plot_path + ".tmp.merk" + std::to_string(l)).c_str());
    if (!write_ok) { log_error("Failed writing complete v4 plot file"); return res; }
    {
        char b[64]; snprintf(b, sizeof b, "  [WRIT] 100%% done (%.1fs)", mono_sec() - t2);
        log_info(b);
    }

    long long fsize = file_size(staging_path);
    if (fsize != plot_size) {
        log_error("File size mismatch: " + std::to_string(fsize) + " vs " + std::to_string(plot_size));
        return res;
    }
    {
        FILE* vf = fopen(staging_path.c_str(), "rb");
        if (!vf) { log_error("Could not reread completed v4 plot"); return res; }
        uint8_t sr[32];
        const bool header_ok = fseek64(vf, 84, SEEK_SET) == 0 && fread(sr, 1, sizeof(sr), vf) == sizeof(sr);
        fclose(vf);
        if (!header_ok || hex_encode(sr, 32) != root) { log_error("Root mismatch in written plot"); return res; }
    }
    if (file_exists(plot_path) || rename(staging_path.c_str(), plot_path.c_str()) != 0) {
        log_error("Could not atomically publish v4 plot without overwriting an existing file");
        return res;
    }
    char b[160];
    snprintf(b, sizeof b, "Plot created: %s (%.3f GB, root=%s...)", plot_path.c_str(), fsize/1e9, root.substr(0,32).c_str());
    log_info(b);
    res.plot_id = plot_id;
    res.size_gb = size_gb;
    res.total_scoops = total_scoops;
    res.merkle_root = root;
    res.path = plot_path;
    res.ok = true;
    return res;
}

static std::vector<std::vector<uint8_t>> read_merkle_proof(const std::string& path, long long total_scoops,
                                                           long long scoop_index, int scoop_size = SCOOP_SIZE) {
    std::vector<std::vector<uint8_t>> proof;
    long long tree_start = HEADER_SIZE + total_scoops * scoop_size;
    long long idx = scoop_index, count = total_scoops, tree_offset = 0;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return proof;
    while (count > 1) {
        long long sibling = idx ^ 1;
        if (sibling < count) {
            std::vector<uint8_t> node(count == total_scoops ? scoop_size : 32);
            if (count == total_scoops) {
                if (fseek64(f, HEADER_SIZE + sibling * scoop_size, SEEK_SET) != 0) { fclose(f); return {}; }
                if (fread(node.data(), 1, node.size(), f) != node.size()) node.clear();
            } else {
                if (fseek64(f, tree_start + (tree_offset + sibling) * 32, SEEK_SET) != 0) { fclose(f); return {}; }
                if (fread(node.data(), 1, 32, f) != 32) node.clear();
            }
            if (!node.empty()) proof.push_back(std::move(node));
        }
        idx >>= 1;
        long long next = (count + 1) / 2;
        if (count != total_scoops) tree_offset += count;
        count = next;
    }
    fclose(f);
    return proof;
}

static size_t expected_merkle_proof_length(uint64_t leaf_count, uint64_t index) {
    size_t length = 0;
    while (leaf_count > 1) {
        if ((index ^ 1) < leaf_count) ++length;
        index >>= 1;
        leaf_count = (leaf_count + 1) / 2;
    }
    return length;
}

static std::mutex g_scan_mu;
static std::map<std::string, std::pair<long long,long long>> g_scan_prog; 
static std::map<std::string, long long> g_scan_best;
static void scan_set(const std::string& p, long long done, long long total, long long best = -1) {
    std::lock_guard<std::mutex> lk(g_scan_mu);
    g_scan_prog[p] = {done, total};
    if (best >= 0) {
        auto it = g_scan_best.find(p);
        if (it == g_scan_best.end() || best < it->second) g_scan_best[p] = best;
    }
}
static void scan_clear(const std::string& p) {
    std::lock_guard<std::mutex> lk(g_scan_mu);
    g_scan_prog.erase(p);
    g_scan_best.erase(p);
}
static std::string fmt_gb(long long b) {
    char s[32]; snprintf(s, sizeof s, "%.2fGB", b / (1024.0*1024*1024));
    return s;
}
struct Reporter {
    std::atomic<bool> stop{false};
    std::thread th;
    double start_ts = 0;
    void start() {
        start_ts = mono_sec();
        th = std::thread([this]() {
            static const char* frames[] = {"|", "/", "-", "\\"};
            int fr = 0;
            long long last_done = 0;
            double last_ts = mono_sec();
            while (!stop.load()) {
                long long done = 0, total = 0;
                long long best = -1;
                {
                    std::lock_guard<std::mutex> lk(g_scan_mu);
                    for (auto& kv : g_scan_prog) {
                        done += kv.second.first;
                        total += kv.second.second;
                    }
                    for (auto& kv : g_scan_best)
                        if (best < 0 || kv.second < best) best = kv.second;
                }
                if (total > 0) {
                    double now = mono_sec();
                    double dt = now - last_ts;
                    double rate = dt > 0 && done >= last_done ? (done - last_done) / dt : 0;
                    long long rem = std::max(0LL, total - done);
                    std::string bd = best >= 0 ? std::to_string(best) + "s" : "...";
                    std::string eta = rate > 0 ? fmt_dur((long long)(rem / rate)) : "...";
                    double mbps = rate > 0 ? rate / 1e6 : 0;
                    char line[160];
                    const char* dl_color = best >= 0 && best <= 3600 ? GREEN : (best >= 0 ? YELLOW : "");
                    snprintf(line, sizeof line, "%s read %s %s | %s%.1f MB/s%s | best %s%s%s | ETA %s",
                             frames[fr % 4], fmt_gb(done).c_str(), fmt_gb(total).c_str(),
                             CYAN, mbps, RESET, dl_color, bd.c_str(), RESET, eta.c_str());
                    g_hud.show(line);
                    last_done = done; last_ts = now;
                    fr++;
                } else fr = 0;
                usleep(200000);
            }
            g_hud.clear();
        });
    }
    void finish() {
        stop.store(true);
        if (th.joinable()) th.join();
    }
};

struct Proof {
    long long deadline = 0;
    long long bytes_read = 0;
    long long total_scoops = 0;
    long long scoop_index = 0;
    int scoop_num = 0;
    long long read_count = 0;
    std::string proof_digest;
    std::string scoop_data_hex;
    std::vector<std::string> merkle_proof_hex;
    struct Sample { uint64_t index; std::string leaf; std::vector<std::string> proof; };
    std::vector<Sample> capacity_samples;
    bool valid = false;
};

static Proof build_poc_proof(const std::string& plot_path, const Json& challenge,
                             const std::string& expected_miner, const std::string& expected_chain_id,
                             const std::vector<uint8_t>& sig, long long bt, long long max_dl = 86400,
                             long long stop_deadline = -1, std::atomic<bool>* stop_event = nullptr) {
    Proof pr;
    PlotMeta meta = get_plot_meta(plot_path);
    if (!meta.valid || meta.miner != str_tolower(expected_miner)) return pr;
    long long total_scoops = meta.total_scoops;
    if (meta.chain_id != expected_chain_id) return pr;
    std::string gen_sig;
    if (auto* g = challenge.get("challenge_seed")) gen_sig = g->as_str();
    else if (auto* g = challenge.get("generation_signature")) gen_sig = g->as_str();
    std::string challenge_id;
    if (auto* c = challenge.get("challenge_id")) challenge_id = c->as_str();
    uint32_t scoop_num = 0;
    if (gen_sig.empty() || !v4_challenge_slot(challenge_id, scoop_num)) return pr;

    long long best_deadline = -1;
    std::vector<uint8_t> best_scoop;
    long long best_idx = 0;
    try {
        FILE* f = fopen(plot_path.c_str(), "rb");
        if (!f) return pr;
        const uint64_t leaf_count = meta.total_scoops;
        for (uint64_t idx = scoop_num; idx < leaf_count; idx += SCOOPS_PER_NONCE) {
            if (stop_event && stop_event->load()) break;
            std::array<uint8_t, SCOOP_SIZE> leaf{};
            const uint64_t offset = HEADER_SIZE + idx * SCOOP_SIZE;
            if (fseek64(f, (long long)offset, SEEK_SET) != 0 || fread(leaf.data(), 1, leaf.size(), f) != leaf.size()) {
                fclose(f);
                log_error("Short or failed v4 target-leaf read from " + plot_path);
                return pr;
            }
            pr.bytes_read += leaf.size();
            const long long dl = compute_deadline(leaf.data(), leaf.size(), sig, bt);
            if (best_deadline < 0 || dl < best_deadline) {
                best_deadline = dl;
                best_scoop.assign(leaf.begin(), leaf.end());
                best_idx = (long long)idx;
            }
            scan_set(plot_path, (long long)(idx + SCOOPS_PER_NONCE), (long long)leaf_count, best_deadline);
            if (stop_deadline > 0 && best_deadline <= stop_deadline) {
                if (stop_event) stop_event->store(true);
                break;
            }
        }
        fclose(f);
        scan_clear(plot_path);
        if (best_deadline <= 0) { pr.deadline = 0; pr.total_scoops = total_scoops; return pr; }
        if (best_deadline > max_dl) { pr.total_scoops = total_scoops; return pr; }
        uint8_t expected_target[32];
        if (!canonical_leaf(meta.chain_id, meta.miner, meta.plot_id, (uint64_t)best_idx, expected_target) ||
            memcmp(expected_target, best_scoop.data(), sizeof(expected_target)) != 0) {
            log_error("Stored v4 target leaf is not canonical");
            return pr;
        }
        auto proof_nodes = read_merkle_proof(plot_path, total_scoops, best_idx, SCOOP_SIZE);
        if (proof_nodes.size() != expected_merkle_proof_length(leaf_count, (uint64_t)best_idx)) {
            log_error("Incomplete v4 target Merkle path"); return pr;
        }
        for (auto& nd : proof_nodes) pr.bytes_read += (long long)nd.size();
        Sha256 digest_ctx;
        digest_ctx.update(best_scoop.data(), best_scoop.size());
        const std::string deadline_text = std::to_string(best_deadline);
        digest_ctx.update((const uint8_t*)deadline_text.data(), deadline_text.size());
        uint8_t digest_bytes[32]; digest_ctx.final(digest_bytes);
        pr.proof_digest = hex_encode(digest_bytes, 32);
        pr.scoop_data_hex = hex_encode(best_scoop.data(), best_scoop.size());
        for (auto& nd : proof_nodes) pr.merkle_proof_hex.push_back(hex_encode(nd.data(), nd.size()));
        pr.scoop_num = scoop_num;
        pr.deadline = best_deadline;
        pr.scoop_index = best_idx;
        pr.total_scoops = total_scoops;
        pr.read_count = (total_scoops + SCOOPS_PER_NONCE - 1) / SCOOPS_PER_NONCE;

        std::vector<uint64_t> sample_indexes;
        if (!v4_sample_indexes(challenge_id, leaf_count, meta.plot_id, sample_indexes, (uint64_t)best_idx)) {
            log_error("Could not derive canonical v4 capacity samples");
            return Proof{};
        }
        FILE* sf = fopen(plot_path.c_str(), "rb");
        if (!sf) return Proof{};
        for (uint64_t sample_index : sample_indexes) {
            std::array<uint8_t, SCOOP_SIZE> sample_leaf{};
            const uint64_t offset = HEADER_SIZE + sample_index * SCOOP_SIZE;
            if (fseek64(sf, (long long)offset, SEEK_SET) != 0 || fread(sample_leaf.data(), 1, sample_leaf.size(), sf) != sample_leaf.size()) {
                fclose(sf);
                log_error("Short or failed v4 capacity-sample read from " + plot_path);
                return Proof{};
            }
            uint8_t expected_sample[32];
            if (!canonical_leaf(meta.chain_id, meta.miner, meta.plot_id, sample_index, expected_sample) ||
                memcmp(expected_sample, sample_leaf.data(), sizeof(expected_sample)) != 0) {
                fclose(sf); log_error("Stored v4 capacity-sample leaf is not canonical"); return Proof{};
            }
            auto sample_path = read_merkle_proof(plot_path, total_scoops, (long long)sample_index, SCOOP_SIZE);
            if (sample_path.size() != expected_merkle_proof_length(leaf_count, sample_index)) {
                fclose(sf); log_error("Incomplete v4 capacity-sample Merkle path"); return Proof{};
            }
            Proof::Sample sample;
            sample.index = sample_index;
            sample.leaf = hex_encode(sample_leaf.data(), sample_leaf.size());
            for (const auto& node : sample_path) {
                sample.proof.push_back(hex_encode(node.data(), node.size()));
                pr.bytes_read += (long long)node.size();
            }
            pr.bytes_read += sample_leaf.size();
            pr.capacity_samples.push_back(std::move(sample));
        }
        fclose(sf);
        pr.valid = true;
        return pr;
    } catch (const std::exception& e) {
        log_error(std::string("build_poc_proof error: ") + e.what());
        return pr;
    }
}

static void run_mining(const std::string& miner_addr, const std::string& chain_id,
                       const std::vector<std::string>& seeds,
                       const std::vector<std::string>& plot_files, MinerKey* key, bool verify_ssl,
                       int interval, int max_workers, long long stop_deadline, const std::string& pool_url) {
    long long scans = 0, accepted = 0, total_bytes_read = 0;
    double start_time = mono_sec();
    std::set<std::string> submitted_challenges;
    std::deque<std::string> submitted_order;
    const size_t MAX_SUBMITTED = 1000;
    struct Pending { std::string ch; long long height; };
    bool has_pending = false;
    Pending pending;
    long long max_dl_cache = 21600;

    if (!key) {
        log_error("v4 proof submission requires a wallet private key");
        return;
    }
    log_info("Starting v4 mining loop; only mature chain-registered plots will be scanned...");

    auto submit_payload_to = [&](const std::string& base, const Json& payload, const std::string& ch_id,
                                 long long height) -> bool {
        Json resp;
        try {
            if (http_post(base + "/api/mining/submit-proof", payload, resp, verify_ssl) && resp.get("ok") && resp.get("ok")->truthy()) {
                accepted++;
                submitted_challenges.insert(ch_id);
                submitted_order.push_back(ch_id);
                if (submitted_order.size() > MAX_SUBMITTED) {
                    submitted_challenges.erase(submitted_order.front());
                    submitted_order.pop_front();
                }
                has_pending = true; pending = {ch_id, height};
                if (auto* bl = resp.get("bloco")) {
                    long long rew_raw = 0;
                    if (auto* rc = bl->get("reward_cc")) rew_raw = rc->as_int(0);
                    double bal;
                    std::string bs;
                    if (fetch_balance(base, miner_addr, verify_ssl, bal)) {
                        char b[64]; snprintf(b, sizeof b, "  balance=%.4f CC", bal); bs = b;
                    }
                    char b[128];
                    long long h = 0;
                    if (auto* hv = bl->get("height")) h = hv->as_int(0);
                    snprintf(b, sizeof b, ">>> BLOCK FORGED! height=%lld reward=%.2f CC%s", h, rew_raw/1e18, bs.c_str());
                    log_win(b);
                    notify("ChocoHub: bloco forjado!", std::string("height=") + std::to_string(h) + " reward=" + std::to_string(rew_raw/1e18) + " CC");
                    submitted_challenges.clear();
                    submitted_order.clear();
                } else {
                    double bal;
                    std::string bs;
                    if (fetch_balance(base, miner_addr, verify_ssl, bal)) {
                        char b[80]; snprintf(b, sizeof b, "  balance=%s%.4f%s CC", GREEN, bal, RESET); bs = b;
                    }
                    log_info(">>> Proof accepted (total: " + std::to_string(accepted) + ")" + bs);
                }
                return true;
            }
            log_warn("Submit rejected by " + base + ": " + resp.dump());
        } catch (const std::exception& e) {
            log_error("Submit error on " + base + ": " + e.what());
        }
        return false;
    };

    while (true) {
        try {
            Json challenge;
            std::string active_seed;
            for (auto& s : seeds) {
                if (http_get(s + "/api/mining/challenge", challenge, 10, 1, verify_ssl)) {
                    if (challenge.get("challenge_id")) { active_seed = s; break; }
                }
            }
            if (!challenge.get("challenge_id")) {
                log_warn("No challenge available from any seed");
                sleep(interval);
                continue;
            }
            std::string ch_id = challenge.get("challenge_id")->as_str();
            long long height = 0;
            if (auto* h = challenge.get("block_height")) height = h->as_int();
            else if (auto* h = challenge.get("height")) height = h->as_int();

            if (has_pending && height > pending.height) {
                Json blk;
                if (fetch_block(active_seed, pending.height + 1, verify_ssl, blk)) {
                    std::string winner;
                    if (auto* w = blk.get("miner")) winner = str_tolower(w->as_str());
                    long long bh = pending.height + 1;
                    if (auto* h = blk.get("height")) bh = h->as_int();
                    else if (auto* h = blk.get("block_height")) bh = h->as_int();
                    if (winner == miner_addr) {
                        double rew = 0;
                        if (auto* rw = blk.get("rewards"); rw && rw->is_arr()) {
                            for (auto& r : rw->arr) {
                                if (auto* m = r.get("miner"))
                                    if (str_tolower(m->as_str()) == miner_addr) {
                                        if (auto* rc = r.get("reward_cc")) rew = rc->as_int(0) / 1e18;
                                        break;
                                    }
                            }
                        }
                        double bal;
                        std::string bs;
                        if (fetch_balance(active_seed, miner_addr, verify_ssl, bal)) {
                            char b[64]; snprintf(b, sizeof b, "  balance=%.4f CC", bal); bs = b;
                        }
                        char b[128];
                        snprintf(b, sizeof b, ">>> YOU WON! block #%lld (+%.4f CC)%s", bh, rew, bs.c_str());
                        log_win(b);
                        char nb[128];
                        snprintf(nb, sizeof nb, "block #%lld +%.4f CC", bh, rew);
                        notify("ChocoHub: voce venceu!", nb);
                    } else {
                        log_info("[#" + std::to_string(bh) + "] Block forged by " + winner.substr(0,12) +
                                 "... - your proof for ch=" + pending.ch.substr(0,12) + "... did not win");
                    }
                }
                has_pending = false;
            }
            if (submitted_challenges.count(ch_id)) {
                log_debug("Challenge " + ch_id.substr(0,12) + " already submitted");
                sleep(interval);
                continue;
            }
            std::string gen_sig;
            if (auto* g = challenge.get("challenge_seed")) gen_sig = g->as_str();
            else if (auto* g = challenge.get("generation_signature")) gen_sig = g->as_str();
            std::vector<uint8_t> sig(gen_sig.begin(), gen_sig.end());
            long long bt = 86400;
            if (auto* b = challenge.get("base_target")) bt = b->as_int(86400);
            long long max_dl = max_dl_cache;
            {
                Json stats;
                if (http_get(active_seed + "/api/stats", stats, 5, 1, verify_ssl)) {
                    if (auto* m = stats.get("max_deadline")) {
                        max_dl = m->as_int(max_dl);
                        max_dl_cache = max_dl;
                    }
                }
            }
            std::map<std::string, std::string> registered_roots;
            if (!fetch_mature_plot_roots(active_seed, miner_addr, verify_ssl, registered_roots)) {
                log_warn("Could not fetch this node's mature on-chain plot registrations");
                sleep(interval);
                continue;
            }
            std::vector<std::string> mineable_plots;
            for (const auto& path : plot_files) {
                PlotMeta meta = get_plot_meta(path);
                auto registered = registered_roots.find(meta.plot_id);
                if (meta.valid && meta.chain_id == chain_id && meta.miner == miner_addr &&
                    registered != registered_roots.end() && registered->second == meta.merkle_root) {
                    mineable_plots.push_back(path);
                }
            }
            if (mineable_plots.empty()) {
                log_warn("No mature registered v4 plot matches this miner, chain_id, plot ID, and root; add the commitment to genesis or register it on-chain");
                sleep(interval);
                continue;
            }
            std::atomic<bool> scan_stop{false};
            std::vector<Proof> proof_results(mineable_plots.size());
            std::atomic<size_t> next_plot{0};
            const int scan_workers = std::max(1, std::min(max_workers, (int)mineable_plots.size()));
            std::vector<std::thread> scan_threads;
            for (int worker = 0; worker < scan_workers; ++worker) {
                scan_threads.emplace_back([&]() {
                    for (;;) {
                        const size_t index = next_plot.fetch_add(1);
                        if (index >= mineable_plots.size()) break;
                        proof_results[index] = build_poc_proof(mineable_plots[index], challenge,
                            miner_addr, chain_id, sig, bt, max_dl, stop_deadline, &scan_stop);
                    }
                });
            }
            Reporter rep;
            rep.start();
            for (auto& thread : scan_threads) thread.join();
            Proof best;
            std::string best_plot;
            for (size_t i = 0; i < proof_results.size(); i++) {
                scans++;
                Proof p = std::move(proof_results[i]);
                total_bytes_read += p.bytes_read;
                if (p.valid && (!best.valid || p.deadline < best.deadline)) {
                    best = std::move(p);
                    best_plot = mineable_plots[i];
                }
            }
            rep.finish();

            if (!best.valid || best.deadline <= 0) {
                log_info("[#" + std::to_string(height) + "] No valid proof  ch=" + ch_id.substr(0,12) + "...");
                sleep(interval);
                continue;
            }
            {
                std::string brs = best.bytes_read >= 1024 ? std::to_string(best.bytes_read/1024) + "KB"
                                                          : std::to_string(best.bytes_read) + "B";
                std::string bn = best_plot;
                auto sl = bn.find_last_of('/'); if (sl != std::string::npos) bn = bn.substr(sl + 1);
                const char* dlc = best.deadline <= 3600 ? GREEN : (best.deadline <= 21600 ? YELLOW : "");
                log_info("[#" + std::to_string(height) + "] deadline " + dlc + std::to_string(best.deadline) + "s" + RESET +
                         "  plot=" + bn + "  ch=" + ch_id.substr(0,12) + "...  read=" + brs);
            }
            PlotMeta meta = get_plot_meta(best_plot);
            std::string plot_id = meta.valid ? meta.plot_id : "";
            std::string proof_sig;
            if (key) {
                try { proof_sig = sign_proof_message(proof_message(ch_id, miner_addr, best.deadline, plot_id), key); }
                catch (const std::exception& e) { log_warn(std::string("Failed to sign proof: ") + e.what()); }
            }
            Json pp = Json::object();
            pp.obj["proof_version"] = Json::i(1);
            pp.obj["scoop_num"] = Json::i(best.scoop_num);
            pp.obj["deadline"] = Json::i(best.deadline);
            pp.obj["proof_digest"] = Json::s(best.proof_digest);
            pp.obj["read_count"] = Json::i(best.read_count);
            pp.obj["scoop_data"] = Json::s(best.scoop_data_hex);
            Json mp = Json::array();
            for (auto& h : best.merkle_proof_hex) mp.arr.push_back(Json::s(h));
            pp.obj["merkle_proof"] = mp;
            pp.obj["scoop_index"] = Json::i(best.scoop_index);
            pp.obj["total_scoops"] = Json::i(best.total_scoops);
            pp.obj["merkle_root"] = Json::s(meta.merkle_root);
            pp.obj["challenge_seed"] = Json::s(gen_sig);
            pp.obj["base_target"] = Json::s(std::to_string(bt));
            pp.obj["public_key"] = Json::s(key ? pub_compressed_hex(key) : "");
            Json samples = Json::array();
            for (const auto& sample : best.capacity_samples) {
                Json item = Json::object();
                item.obj["index"] = Json::i((long long)sample.index);
                item.obj["leaf"] = Json::s(sample.leaf);
                Json path = Json::array();
                for (const auto& node : sample.proof) path.arr.push_back(Json::s(node));
                item.obj["merkle_proof"] = std::move(path);
                samples.arr.push_back(std::move(item));
            }
            pp.obj["capacity_samples"] = std::move(samples);

            Json payload = Json::object();
            payload.obj["challenge_id"] = Json::s(ch_id);
            payload.obj["miner"] = Json::s(miner_addr);
            payload.obj["plot_id"] = Json::s(plot_id);
            payload.obj["deadline"] = Json::i(best.deadline);
            payload.obj["proof_packet"] = pp;
            payload.obj["proof_signature"] = Json::s(proof_sig);
            payload.obj["reward_recipient"] = Json::s(miner_addr);

            bool submitted = false;
            if (!pool_url.empty()) {
                submitted = submit_payload_to(pool_url, payload, ch_id, height);
            } else {
                for (auto& s : seeds)
                    if (submit_payload_to(s, payload, ch_id, height)) { submitted = true; break; }
            }
            if (!submitted) log_warn("Proof submission failed on all seed nodes");

            long long elapsed = (long long)(mono_sec() - start_time);
            double bps = (double)total_bytes_read / std::max(1LL, elapsed);
            char spd[64];
            if (bps > 1e6) snprintf(spd, sizeof spd, "%.2f MB/s", bps/1e6);
            else snprintf(spd, sizeof spd, "%.2f KB/s", bps/1024);
            char rd[64];
            if (total_bytes_read > 1000000000LL) snprintf(rd, sizeof rd, "%.2f GB", total_bytes_read/1e9);
            else snprintf(rd, sizeof rd, "%.2f MB", total_bytes_read/1e6);
            log_info(std::string("[stats] scans=") + std::to_string(scans) + " accepted=" + std::to_string(accepted) +
                     " uptime=" + fmt_dur(elapsed) + " read=" + rd + " speed=" + spd);
            csv_stats(height, best.deadline, best.deadline, bps/1e6, elapsed, plot_files.size());
            sleep(interval);
        } catch (const std::exception& e) {
            log_error(std::string("Mining loop error: ") + e.what());
            sleep(interval);
        }
    }
}

static std::string ask(const std::string& prompt, const std::string& def = "") {
    if (!isatty(0)) return def;
    printf("%s [%s]: ", prompt.c_str(), def.c_str());
    fflush(stdout);
    std::string line;
    if (!std::getline(std::cin, line)) { printf("\n"); return def; }
    line = str_trim(line);
    return line.empty() ? def : line;
}
static double to_float(const std::string& s, double d = 0) {
    try {
        std::string t = s;
        std::replace(t.begin(), t.end(), ',', '.');
        size_t used = 0;
        const double value = std::stod(t, &used);
        return used == t.size() && std::isfinite(value) ? value : d;
    } catch (...) { return d; }
}

static std::vector<PlotResult> create_plots(const std::string& outdir, const std::vector<double>& sizes,
                                            const std::string& miner_addr, const std::string& chain_id) {
    make_dirs(outdir);
    std::vector<PlotResult> created;
    for (size_t i = 0; i < sizes.size(); i++) {
        std::string plot_id = random_hex(32);
        std::string path = outdir + "/" + plot_id + ".plot";
        log_info("[" + std::to_string(i+1) + "/" + std::to_string(sizes.size()) + "] Creating " +
                 std::to_string(sizes[i]) + " GiB v4 plot " + plot_id + "...");
        PlotResult r = create_plot_file(path, plot_id, str_tolower(miner_addr), chain_id, sizes[i], true);
        if (r.ok) {
            created.push_back(r);
            log_info("Genesis registration (use this plot only after adding it to the shared v4 genesis config):");
            printf("{\"miner\":\"%s\",\"plot_id\":\"%s\",\"merkle_root\":\"%s\",\"capacity_bytes\":\"%lld\"}\n",
                   str_tolower(miner_addr).c_str(), r.plot_id.c_str(), r.merkle_root.c_str(), r.total_scoops * SCOOP_SIZE);
        } else {
            log_error("Failed to create plot " + std::to_string(i+1));
        }
    }
    return created;
}

static std::vector<std::string> scan_plot_files(const std::string& dir) {
    std::vector<std::string> out;
    DIR* d = opendir(dir.c_str());
    if (!d) return out;
    std::vector<std::string> names;
    struct dirent* e;
    while ((e = readdir(d))) names.push_back(e->d_name);
    closedir(d);
    std::sort(names.begin(), names.end());
    for (auto& nm : names) {
        if (nm.size() < 5 || nm.substr(nm.size() - 5) != ".plot") continue;
        std::string full = dir + "/" + nm;
        PlotMeta m = get_plot_meta(full);
        if (!m.valid) { log_warn("Skipping invalid plot: " + nm); continue; }
        log_info("Plot: " + m.plot_id + " scoops=" + std::to_string(m.total_scoops) +
                 " root=" + m.merkle_root.substr(0,16) + "...");
        out.push_back(full);
    }
    return out;
}

static std::string make_banner() { return std::string(MAGENTA) + BOLD + R"(
 _____ _                     _           _
/  __ \ |                   | |         | |
| /  \/ |__   ___   ___ ___ | |__  _   _| |__
| |   | '_ \ / _ \ / __/ _ \| '_ \| | | | '_ \
| \__/\ | | | (_) | (_| (_) | | | | |_| | |_) |
 \____/_| |_|\___/ \___\___/|_| |_|\__,_|_.__/


___  ____       _  ___  ____
|  \/  (_)     (_) |  \/  (_)
| .  . |_ _ __  _  | .  . |_ _ __   ___ _ __
| |\/| | | '_ \| | | |\/| | | '_ \ / _ \ '__|
| |  | | | | | | | | |  | | | | | |  __/ |
\_|  |_/_|_| |_|_| \_|  |_/_|_| |_|\___|_|

CCPoC v4 canonical plot miner!
)" + RESET;
}

static const char* CCPOC_VERSION = "4.0.0";

static void print_help(const char* prog) {
    printf("ChocoHub Unified Miner v%s - Plot Generation + PoC Mining (C++)\n\n"
           "Usage:\n"
           "  %s                          # mine (asks for whatever is missing)\n"
           "  %s generate 1               # generate a 1 GiB v4 plot\n"
           "  %s generate 1 3             # generate two plots: 1 GiB and 3 GiB\n"
           "  %s status                   # show wallet, plots and effective capacity\n"
           "  %s --miner 0x... --rpc http://localhost:3000\n"
           "  %s --generate-key\n\n"
           "Options:\n"
           "  --miner ADDR          Wallet address\n"
           "  --wallet PATH         Wallet JSON path (default: $HOME/wallet.json)\n"
           "  --rpc URL[,URL]       RPC seed URL(s)\n"
           "  --chain-id ID         v4 chain ID (must match the node; default 19971971)\n"
           "  --pool URL            Pool URL for submitting proofs\n"
           "  --genplot N           Generate N v4 plots before mining\n"
           "  --genplot-size GiB    v4 capacity in GiB (must be a multiple of 256 KiB)\n"
           "  --genplot-outdir DIR  Plot output directory\n"
           "  --plots-dir DIR       Directory with existing plots\n"
           "  --interval S          Mining poll interval (default 20)\n"
           "  --threads N           Scan threads (default 4)\n"
           "  --generate-key        Generate secp256k1 keypair and exit\n"
           "  --no-mine             Only generate plots\n"
           "  --stop-deadline S     Submit as soon as deadline <= S is found\n"
           "  --version             Print version and exit\n",
           CCPOC_VERSION, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char** argv) {
    curl_global_init(CURL_GLOBAL_ALL);
    g_log_fp = fopen("miner.log", "a");
    log_info(make_banner());

    std::string miner_addr, rpc, pool_url, plots_dir, genplot_outdir, wallet_file;
    std::string chain_id = "19971971";
    int genplot = 0;
    double genplot_size = 1.0;
    int interval = 20, threads = 4;
    bool verify_ssl = true, gen_key = false, no_mine = false;
    long long stop_deadline = -1;
    std::vector<double> sizes;
    std::string mode = "mine";

    int i = 1;
    if (i < argc) {
        std::string a0 = argv[i];
        if (a0 == "generate" || a0 == "gen" || a0 == "plot") { mode = "generate"; i++; }
        else if (a0 == "status") { mode = "status"; i++; }
    }
    for (; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--miner") miner_addr = next();
        else if (a == "--wallet") wallet_file = next();
        else if (a == "--rpc") rpc = next();
        else if (a == "--chain-id") chain_id = next();
        else if (a == "--pool") pool_url = next();
        else if (a == "--genplot") genplot = atoi(next().c_str());
        else if (a == "--genplot-size") genplot_size = to_float(next(), 1.0);
        else if (a == "--genplot-outdir") genplot_outdir = next();
        else if (a == "--plots-dir") plots_dir = next();
        else if (a == "--interval") interval = atoi(next().c_str());
        else if (a == "--threads") threads = atoi(next().c_str());
        else if (a == "--generate-key") gen_key = true;
        else if (a == "--no-mine") no_mine = true;
        else if (a == "--stop-deadline") stop_deadline = atoll(next().c_str());
        else if (a == "-h" || a == "--help") { print_help(argv[0]); return 0; }
        else if (a == "--version") { printf("ccpoc-miner %s\n", CCPOC_VERSION); return 0; }
        else if (!a.empty() && a[0] != '-') sizes.push_back(to_float(a));
        else { log_error("Unknown argument: " + a); print_help(argv[0]); return 1; }
    }

    if (!wallet_file.empty()) g_wallet_path_override = wallet_file;

    if (gen_key) {
        std::string priv, pub;
        if (!generate_keypair(priv, pub)) { log_error("Key generation failed"); return 1; }
        std::vector<uint8_t> pb;
        hex_decode(pub, pb);
        Wallet w;
        w.address = derive_address_from_pubbytes(pb);
        w.public_key = pub;
        w.private_key = priv;
        w.valid = true;
        write_wallet_file(wallet_path(), w);
        printf("Wallet saved to: %s\n", wallet_path().c_str());
        printf("Address: %s\n", w.address.c_str());
        printf("Private key (hex):\n  %s\n", priv.c_str());
        printf("Public key (hex):\n  %s\n", pub.c_str());
        printf("Public key (base64) -> user registration on the node:\n  %s\n",
               base64_encode(pb.data(), pb.size()).c_str());
        return 0;
    }

    if (chain_id.empty() || (chain_id.size() > 1 && chain_id[0] == '0') || chain_id.size() > 255 ||
        !std::all_of(chain_id.begin(), chain_id.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        log_error("--chain-id must be a canonical unsigned decimal value with at most 255 bytes");
        return 1;
    }

    std::vector<std::string> seeds;
    {
        std::string src = rpc.empty() ? "https://seed2.chocohub.org" : rpc;
        size_t pos = 0;
        while (pos < src.size()) {
            size_t c = src.find(',', pos);
            std::string u = str_trim(src.substr(pos, c == std::string::npos ? std::string::npos : c - pos));
            if (!u.empty()) seeds.push_back(u);
            if (c == std::string::npos) break;
            pos = c + 1;
        }
    }
    if (!pool_url.empty() &&
        pool_url.rfind("http://", 0) != 0 && pool_url.rfind("https://", 0) != 0)
        pool_url = "http://" + pool_url;

    Wallet wallet = load_wallet_file(wallet_path());
    if (!wallet.valid) {
        std::string priv, pub;
        if (generate_keypair(priv, pub)) {
            std::vector<uint8_t> pb; hex_decode(pub, pb);
            wallet.address = derive_address_from_pubbytes(pb);
            wallet.public_key = pub;
            wallet.private_key = priv;
            wallet.valid = true;
            write_wallet_file(wallet_path(), wallet);
            log_info("Generated new wallet.json at " + wallet_path());
        } else {
            log_warn("Could not auto-generate wallet.json");
        }
    }
    if (wallet.valid && !wallet.public_key.empty()) {
        std::vector<uint8_t> pb;
        if (hex_decode(wallet.public_key, pb)) {
            std::string want = derive_address_from_pubbytes(pb);
            if (!want.empty() && str_tolower(wallet.address) != want) {
                log_warn("Wallet address updated to node scheme: " + wallet.address + " -> " + want);
                wallet.address = want;
                write_wallet_file(wallet_path(), wallet);
            }
        }
    }
    if (miner_addr.empty()) {
        if (wallet.valid) miner_addr = str_tolower(wallet.address);
        if (miner_addr.empty()) miner_addr = str_tolower(ask("Wallet address (0x...)"));
    }
    if (miner_addr.empty()) {
        log_error("Wallet address required: use --miner, provide wallet.json, or answer the prompt");
        return 1;
    }
    std::vector<uint8_t> miner_bytes;
    miner_addr = str_tolower(miner_addr);
    if (!hex_decode(miner_addr, miner_bytes) || miner_bytes.size() != 20 || miner_addr.rfind("0x", 0) != 0) {
        log_error("Miner address must be a 20-byte 0x-prefixed hex address");
        return 1;
    }

    if (mode == "status") {
        Wallet w = load_wallet_file(wallet_path());
        if (w.valid) {
            printf("%sWallet%s  %s\n", BOLD, RESET, w.address.c_str());
            if (!w.public_key.empty()) printf("  pubkey %s...\n", w.public_key.substr(0, 24).c_str());
        } else printf("%sWallet%s  nenhum wallet.json\n", BOLD, RESET);
        std::string dir = plots_dir.empty() ? "./plots" : plots_dir;
        auto plots = scan_plot_files(dir);
        double total_gb = 0, eff_total = 0;
        printf("%sPlots%s   %zu em %s\n", BOLD, RESET, plots.size(), dir.c_str());
        for (auto& p : plots) {
            PlotMeta m = get_plot_meta(p);
            if (!m.valid) continue;
            double gb = m.total_scoops * SCOOP_SIZE / (1024.0*1024*1024);
            double eff = compute_effective_capacity_gb(gb);
            total_gb += gb; eff_total += eff;
            const char* tid = "tier_1"; double mult = 1.0;
            for (auto& t : TIERS) if (t.lo <= gb && gb < t.hi) { tid = t.id; mult = t.mult; }
            std::string bn = p;
            auto sl = bn.find_last_of('/'); if (sl != std::string::npos) bn = bn.substr(sl + 1);
            printf("  %s%-14s%s %8.3f GB  eff %8.3f GB  x%.1f %s\n", CYAN, bn.c_str(), RESET, gb, eff, mult, tid);
        }
        printf("%sTotal%s   %.3f GB  (effective %.3f GB)\n", BOLD, RESET, total_gb, eff_total);
        if (!seeds.empty()) {
            double bal;
            if (w.valid && fetch_balance(seeds[0], str_tolower(w.address), verify_ssl, bal))
                printf("%sSaldo%s   %.4f CC\n", BOLD, RESET, bal);
            else
                printf("%sSaldo%s   (seed inacessivel)\n", BOLD, RESET);
        }
        return 0;
    }

    MinerKey* key = nullptr;
    if (wallet.valid && !wallet.private_key.empty()) key = load_private_key(wallet.private_key);
    if (key) log_info("Proof signing: ENABLED");
    else log_warn("Proof signing: DISABLED (no valid privateKey in wallet.json)");

    std::string script_dir = ".";
    std::string default_outdir = !genplot_outdir.empty() ? genplot_outdir
                                 : (!plots_dir.empty() ? plots_dir : script_dir + "/plots");
    if (plots_dir.empty()) plots_dir = default_outdir;

    if (mode == "generate") {
        std::vector<double> ss;
        for (double s : sizes) if (s > 0) ss.push_back(s);
        while (ss.empty()) {
            double v = to_float(ask("Plot size in GB", "1"));
            if (v > 0) ss.push_back(v);
        }
        std::string outdir = !genplot_outdir.empty() ? genplot_outdir : ask("Plot output directory", default_outdir);
        auto created = create_plots(outdir, ss, miner_addr, chain_id);
        log_info(std::to_string(created.size()) + "/" + std::to_string(ss.size()) + " plot(s) created in " + outdir);
        if (no_mine) { delete key; return 0; }
        std::string a = str_tolower(ask("Start mining now? (Y/n)", "y"));
        if (a == "n" || a == "no") { delete key; return 0; }
        plots_dir = outdir;
    } else if (genplot > 0) {
        std::string outdir = !genplot_outdir.empty() ? genplot_outdir : plots_dir;
        std::vector<double> ss(genplot, genplot_size);
        create_plots(outdir, ss, miner_addr, chain_id);
        if (no_mine) { delete key; return 0; }
        plots_dir = outdir;
    }

    std::vector<std::string> plot_files = scan_plot_files(plots_dir);
    while (plot_files.empty()) {
        if (!file_exists(plots_dir)) log_warn("Directory not found: " + plots_dir);
        else log_warn("No valid plots in " + plots_dir);
        std::string raw = ask("Plots directory OR size in GB to generate", "scan");
        double sz = to_float(raw);
        if (sz > 0) {
            auto created = create_plots(plots_dir, {sz}, miner_addr, chain_id);
            if (created.empty()) continue;
        } else if (!raw.empty() && raw != "scan") {
            plots_dir = raw;
            make_dirs(plots_dir);
        }
        plot_files = scan_plot_files(plots_dir);
    }

    {
        std::string sl;
        for (auto& s : seeds) sl += (sl.empty() ? "" : ", ") + s;
        log_info("Seed URLs: " + sl);
    }
    log_info("Address: " + miner_addr);
    log_info("Plots: " + std::to_string(plot_files.size()) + " in " + plots_dir);
    log_info("Threads: " + std::to_string(threads) + ", Interval: " + std::to_string(interval) + "s");
    log_info(std::string("SSL verify: ") + (verify_ssl ? "true" : "false"));
    if (stop_deadline > 0)
        log_info("Stop-deadline: " + std::to_string(stop_deadline) + "s");

    g_csv = fopen("stats.csv", "a");
    if (g_csv && ftell(g_csv) == 0)
        fprintf(g_csv, "ts,height,deadline,best_deadline,mbps,uptime_s,plots\n");

    run_mining(miner_addr, chain_id, seeds, plot_files, key, verify_ssl, interval, threads, stop_deadline, pool_url);
    if (g_csv) fclose(g_csv);
    delete key;
    curl_global_cleanup();
    if (g_log_fp) fclose(g_log_fp);
    return 0;
}
