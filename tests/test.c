#include "../src/pcap_triage.h"
#include <stdlib.h>
#include <string.h>

static int n, failed;
#define CHECK(name, cond) do { n++; if (!(cond)) { failed++; printf("FAIL: %s\n", name); } } while (0)

static uint8_t cap[1 << 20]; static size_t cl;

static void w16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void le32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

static void start(int big) {
    memset(cap, 0, 24);
    if (big) { be32(cap, 0xa1b2c3d4u); cap[5] = 2; cap[7] = 4; be32(cap + 16, 65535); be32(cap + 20, 1); }
    else { le32(cap, 0xa1b2c3d4u); cap[4] = 2; cap[6] = 4; le32(cap + 16, 65535); le32(cap + 20, 1); }
    cl = 24;
}

/* append one Ethernet/IPv4/TCP packet (flags, payload) */
static void pkt(int big, int vlan, uint32_t src, uint32_t dst, int sport, int dport, int flags, const char *pl) {
    uint8_t f[1600]; size_t o = 0, pn = pl ? strlen(pl) : 0;
    memset(f, 0, 14); f[5] = 1; f[11] = 2; o = 12;
    if (vlan) { w16(f + o, 0x8100); w16(f + o + 2, 5); o += 4; }
    w16(f + o, 0x0800); o += 2;
    uint8_t *ip = f + o; memset(ip, 0, 20); ip[0] = 0x45; w16(ip + 2, (unsigned)(40 + pn)); ip[8] = 64; ip[9] = 6;
    be32(ip + 12, src); be32(ip + 16, dst);
    uint8_t *t = ip + 20; memset(t, 0, 20); w16(t, (unsigned)sport); w16(t + 2, (unsigned)dport); t[12] = 5 << 4; t[13] = (uint8_t)flags;
    memcpy(t + 20, pl ? pl : "", pn);
    size_t total = o + 40 + pn;
    uint8_t *r = cap + cl;
    if (big) { be32(r, 1700000000u + (uint32_t)(cl / 100)); be32(r + 4, 0); be32(r + 8, (uint32_t)total); be32(r + 12, (uint32_t)total); }
    else { le32(r, 1700000000u + (uint32_t)(cl / 100)); le32(r + 4, 0); le32(r + 8, (uint32_t)total); le32(r + 12, (uint32_t)total); }
    memcpy(r + 16, f, total); cl += 16 + total;
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static char *render(const pt_report *r, int html) {
    static char buf[1 << 16];
    FILE *f = tmpfile(); if (html) pt_render_html(f, r); else pt_render_text(f, r);
    size_t k = (size_t)ftell(f); rewind(f); k = fread(buf, 1, sizeof buf - 1, f); buf[k] = 0; fclose(f); return buf;
}

int main(void) {
    pt_report r;
    CHECK("too short", pt_analyze(cap, 10, 20, &r) == -1);
    memset(cap, 0, 64); CHECK("bad magic", pt_analyze(cap, 64, 20, &r) == -2);
    start(0); le32(cap + 20, 113); CHECK("linux sll unsupported", pt_analyze(cap, cl, 20, &r) == -3);

    start(0); pkt(0, 0, IP(1,1,1,1), IP(2,2,2,2), 1000, 80, 0x02, NULL);
    CHECK("one packet parses", pt_analyze(cap, cl, 20, &r) == 0 && r.packets == 1 && r.tcp == 1 && r.flows == 1);

    start(0); for (int i = 0; i < 30; i++) pkt(0, 0, IP(9,9,9,9), IP(10,0,0,5), 4000 + i, 20 + i, 0x02, NULL);
    pt_analyze(cap, cl, 20, &r);
    CHECK("port scan found", r.n_scanners == 1 && r.scanners[0].targets == 30 && r.scanners[0].dsts == 1 && !strcmp(r.scanners[0].kind, "port scan"));
    pt_analyze(cap, cl, 31, &r); CHECK("threshold respected", r.n_scanners == 0);

    start(0); for (int i = 0; i < 25; i++) pkt(0, 0, IP(9,9,9,9), IP(10,0,1,i + 1), 4000 + i, 445, 0x02, NULL);
    pt_analyze(cap, cl, 20, &r);
    CHECK("host sweep found", r.n_scanners == 1 && !strcmp(r.scanners[0].kind, "host sweep") && r.scanners[0].dsts == 25);

    start(0); for (int i = 0; i < 40; i++) pkt(0, 0, IP(9,9,9,9), IP(10,0,0,5), 4000 + i, 20 + i, 0x12, NULL);
    pt_analyze(cap, cl, 20, &r); CHECK("SYN-ACK replies are not a scan", r.n_scanners == 0);

    start(0); for (int i = 0; i < 40; i++) { pkt(0, 0, IP(9,9,9,9), IP(10,0,0,5), 4000, 80, 0x02, NULL); }
    pt_analyze(cap, cl, 20, &r); CHECK("repeated SYNs to one port are not a scan", r.n_scanners == 0);

    start(0); pkt(0, 0, IP(10,0,0,2), IP(10,0,0,3), 5000, 21, 0x18, "USER alice\r\n"); pkt(0, 0, IP(10,0,0,2), IP(10,0,0,3), 5000, 21, 0x18, "PASS s3cr3tpw\r\n");
    pt_analyze(cap, cl, 20, &r);
    CHECK("ftp credential", r.n_creds == 1 && !strcmp(r.creds[0].user, "alice") && r.creds[0].pwlen == 8 && !strcmp(r.creds[0].proto, "ftp"));
    CHECK("password never rendered (text)", !strstr(render(&r, 0), "s3cr3tpw"));
    CHECK("password never rendered (html)", !strstr(render(&r, 1), "s3cr3tpw"));

    start(0); pkt(0, 0, IP(10,0,0,2), IP(10,0,0,3), 5000, 110, 0x18, "USER bob\r\nPASS pw\r\n");
    pt_analyze(cap, cl, 20, &r); CHECK("pop3 user and pass in one packet", r.n_creds == 1 && !strcmp(r.creds[0].user, "bob") && !strcmp(r.creds[0].proto, "pop3"));

    start(0); pkt(0, 0, IP(10,0,0,2), IP(10,0,0,3), 5000, 8080, 0x18, "GET / HTTP/1.1\r\nauthorization: BASIC YWxpY2U6aHVudGVyMg==\r\n\r\n");
    pt_analyze(cap, cl, 20, &r);
    CHECK("http basic, any port, case-insensitive", r.n_creds == 1 && !strcmp(r.creds[0].user, "alice") && r.creds[0].pwlen == 7);

    start(0); pkt(0, 0, IP(10,0,0,2), IP(10,0,0,3), 5000, 21, 0x18, "USER <script>alert(1)</script>\r\n"); pkt(0, 0, IP(10,0,0,2), IP(10,0,0,3), 5000, 21, 0x18, "PASS x\r\n");
    pt_analyze(cap, cl, 20, &r);
    CHECK("html escapes attacker-controlled usernames", !strstr(render(&r, 1), "<script>") && strstr(render(&r, 1), "&lt;script&gt;"));

    start(1); pkt(1, 0, IP(1,1,1,1), IP(2,2,2,2), 1, 2, 0x02, NULL);
    CHECK("big-endian pcap", pt_analyze(cap, cl, 20, &r) == 0 && r.packets == 1 && r.tcp == 1);
    start(0); pkt(0, 1, IP(1,1,1,1), IP(2,2,2,2), 1, 2, 0x02, NULL);
    CHECK("vlan tagged frame", pt_analyze(cap, cl, 20, &r) == 0 && r.tcp == 1);

    start(0); pkt(0, 0, IP(1,1,1,1), IP(2,2,2,2), 1, 2, 0x02, NULL); pkt(0, 0, IP(1,1,1,1), IP(2,2,2,2), 1, 2, 0x02, NULL);
    CHECK("truncated capture flagged", pt_analyze(cap, cl - 5, 20, &r) == 0 && r.truncated && r.packets == 1);

    FILE *f = fopen("examples/sample.pcap", "rb");
    if (f) {
        static uint8_t s[1 << 20]; size_t k = fread(s, 1, sizeof s, f); fclose(f);
        CHECK("sample: parses", pt_analyze(s, k, 20, &r) == 0);
        CHECK("sample: 145 packets", r.packets == 145);
        CHECK("sample: two scanners", r.n_scanners == 2);
        CHECK("sample: two credentials", r.n_creds == 2 && !strcmp(r.creds[0].user, "backup-svc"));
        CHECK("sample: 12 dns queries", r.dns_queries == 12);
        CHECK("sample: top flow is the download", r.talkers[0].bytes > 70000 && r.talkers[0].dport == 443);
        /* fuzz: flipping bytes must never crash (run under AddressSanitizer in CI) */
        uint32_t seed = 12345; int ok = 1;
        for (int it = 0; it < 3000; it++) {
            static uint8_t m[1 << 20]; memcpy(m, s, k);
            for (int j = 0; j < 8; j++) { seed = seed * 1664525u + 1013904223u; m[(seed >> 8) % k] = (uint8_t)(seed >> 3); }
            size_t len = k; seed = seed * 1664525u + 1013904223u; if (it % 3 == 0) len = 24 + (seed >> 4) % (k - 24);
            int rc = pt_analyze(m, len, 20, &r); if (rc != 0 && rc != -2 && rc != -3) ok = 0;
        }
        CHECK("fuzz: 3000 mutated captures, no crash", ok);
    } else { printf("skipped sample tests (run from repo root)\n"); }

    printf(failed ? "%d of %d failed\n" : "all %d passed\n", failed ? failed : n, n);
    return failed ? 1 : 0;
}
