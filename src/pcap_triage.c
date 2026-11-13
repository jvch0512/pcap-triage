#include "pcap_triage.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define FLOW_CAP (1u << 16)
#define SET_CAP (1u << 17)
#define SRC_CAP 256
#define PEND_CAP 64

typedef struct { pt_flow f; uint8_t used; } flow_slot;
typedef struct { uint32_t a, b, c; uint8_t used; } set_slot;
typedef struct { uint32_t src; unsigned targets, dsts, syns; } src_stat;
typedef struct { uint32_t src, dst; uint16_t dport; char user[48]; uint8_t used; } pending;

static uint32_t rd32(const uint8_t *p, int be) {
    return be ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]
              : ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0];
}
static uint16_t rd16n(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32n(const uint8_t *p) { return rd32(p, 1); }

static uint32_t mix(uint32_t h, uint32_t v) { h ^= v; h *= 16777619u; h ^= h >> 15; return h; }

static flow_slot *flow_get(flow_slot *t, uint32_t s, uint32_t d, uint16_t sp, uint16_t dp, uint8_t pr, uint32_t *count, uint32_t *dropped) {
    uint32_t h = mix(mix(mix(mix(2166136261u, s), d), ((uint32_t)sp << 16) | dp), pr) & (FLOW_CAP - 1);
    for (uint32_t i = 0; i < 64; i++) {
        flow_slot *e = &t[(h + i) & (FLOW_CAP - 1)];
        if (!e->used) {
            if (*count >= FLOW_CAP * 3 / 4) { (*dropped)++; return NULL; }
            e->used = 1; e->f.src = s; e->f.dst = d; e->f.sport = sp; e->f.dport = dp; e->f.proto = pr; (*count)++;
            return e;
        }
        if (e->f.src == s && e->f.dst == d && e->f.sport == sp && e->f.dport == dp && e->f.proto == pr) return e;
    }
    (*dropped)++;
    return NULL;
}

/* returns 1 when the triple was new */
static int set_add(set_slot *t, uint32_t a, uint32_t b, uint32_t c, uint32_t *count) {
    uint32_t h = mix(mix(mix(2166136261u, a), b), c) & (SET_CAP - 1);
    for (uint32_t i = 0; i < 64; i++) {
        set_slot *e = &t[(h + i) & (SET_CAP - 1)];
        if (!e->used) {
            if (*count >= SET_CAP * 3 / 4) return 0;
            e->used = 1; e->a = a; e->b = b; e->c = c; (*count)++;
            return 1;
        }
        if (e->a == a && e->b == b && e->c == c) return 0;
    }
    return 0;
}

static src_stat *src_get(src_stat *t, int *n, uint32_t src) {
    for (int i = 0; i < *n; i++) if (t[i].src == src) return &t[i];
    if (*n >= SRC_CAP) return NULL;
    t[*n].src = src; return &t[(*n)++];
}

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64decode(const char *in, size_t n, char *out, size_t cap) {
    size_t o = 0; uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '=') break;
        int v = b64val((unsigned char)in[i]);
        if (v < 0) break;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if (bits >= 8) { bits -= 8; if (o + 1 < cap) out[o++] = (char)((acc >> bits) & 0xff); }
    }
    out[o] = 0;
    return o;
}

static void copy_clean(char *dst, size_t cap, const char *src, size_t n) {
    size_t o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[o++] = (c >= 32 && c < 127) ? (char)c : '?';
    }
    dst[o] = 0;
}

static void add_cred(pt_report *r, const char *proto, uint32_t s, uint32_t d, uint16_t dp, const char *user, size_t pwlen) {
    if (r->n_creds >= PT_MAX_CREDS) return;
    pt_cred *c = &r->creds[r->n_creds++];
    memset(c, 0, sizeof *c);
    strncpy(c->proto, proto, sizeof c->proto - 1);
    c->src = s; c->dst = d; c->dport = dp; c->pwlen = pwlen;
    strncpy(c->user, user, sizeof c->user - 1);
}

static int starts_ci(const char *p, size_t n, const char *lit) {
    size_t l = strlen(lit);
    return n >= l && strncasecmp(p, lit, l) == 0;
}

static void look_for_creds(pt_report *r, pending *pend, uint32_t s, uint32_t d, uint16_t dp, const uint8_t *pl, size_t n) {
    const char *p = (const char *)pl;
    if (dp == 21 || dp == 110) {
        const char *proto = dp == 21 ? "ftp" : "pop3";
        size_t i = 0;
        while (i < n) {
            size_t e = i;
            while (e < n && p[e] != '\n' && p[e] != '\r') e++;
            size_t len = e - i;
            if (starts_ci(p + i, len, "USER ")) {
                int slot = -1;
                for (int k = 0; k < PEND_CAP; k++) if (pend[k].used && pend[k].src == s && pend[k].dst == d && pend[k].dport == dp) { slot = k; break; }
                if (slot < 0) for (int k = 0; k < PEND_CAP; k++) if (!pend[k].used) { slot = k; break; }
                if (slot < 0) slot = 0;
                pend[slot].used = 1; pend[slot].src = s; pend[slot].dst = d; pend[slot].dport = dp;
                copy_clean(pend[slot].user, sizeof pend[slot].user, p + i + 5, len - 5);
            } else if (starts_ci(p + i, len, "PASS ")) {
                const char *user = "?";
                for (int k = 0; k < PEND_CAP; k++) if (pend[k].used && pend[k].src == s && pend[k].dst == d && pend[k].dport == dp) { user = pend[k].user; pend[k].used = 0; break; }
                add_cred(r, proto, s, d, dp, user, len - 5);
            }
            while (e < n && (p[e] == '\n' || p[e] == '\r')) e++;
            i = e;
        }
    }
    /* HTTP basic authentication on any port */
    static const char needle[] = "authorization: basic ";
    size_t nl = sizeof needle - 1;
    for (size_t i = 0; i + nl < n; i++) {
        if (strncasecmp(p + i, needle, nl) != 0) continue;
        size_t b = i + nl, e = b;
        while (e < n && p[e] != '\r' && p[e] != '\n' && p[e] != ' ') e++;
        char dec[96];
        size_t dl = b64decode(p + b, e - b, dec, sizeof dec);
        char *colon = memchr(dec, ':', dl);
        char user[48];
        if (colon) { copy_clean(user, sizeof user, dec, (size_t)(colon - dec)); add_cred(r, "http", s, d, dp, user, dl - (size_t)(colon - dec) - 1); }
        i = e;
    }
}

static int cmp_flow(const void *a, const void *b) {
    const pt_flow *x = a, *y = b;
    if (x->bytes != y->bytes) return x->bytes < y->bytes ? 1 : -1;
    if (x->src != y->src) return x->src < y->src ? -1 : 1;
    return x->dst < y->dst ? -1 : (x->dst > y->dst);
}

int pt_analyze(const uint8_t *buf, size_t len, unsigned thr, pt_report *r) {
    memset(r, 0, sizeof *r);
    if (len < 24) return -1;
    uint32_t m = rd32(buf, 0);
    int be = 0, nano = 0;
    if (m == 0xa1b2c3d4u) { be = 0; }
    else if (m == 0xa1b23c4du) { be = 0; nano = 1; }
    else if (m == 0xd4c3b2a1u) { be = 1; }
    else if (m == 0x4d3cb2a1u) { be = 1; nano = 1; }
    else return -2;
    uint32_t link = rd32(buf + 20, be);
    if (link != 1 && link != 101) return -3;

    flow_slot *flows = calloc(FLOW_CAP, sizeof *flows);
    set_slot *sets = calloc(SET_CAP, sizeof *sets);
    src_stat *srcs = calloc(SRC_CAP, sizeof *srcs);
    pending *pend = calloc(PEND_CAP, sizeof *pend);
    if (!flows || !sets || !srcs || !pend) { free(flows); free(sets); free(srcs); free(pend); return -4; }
    int nsrc = 0; uint32_t set_count = 0;
    double t0 = -1, t1 = 0;

    size_t off = 24;
    while (off < len) {
        if (len - off < 16) { r->truncated = 1; break; }
        uint32_t sec = rd32(buf + off, be), frac = rd32(buf + off + 4, be), incl = rd32(buf + off + 8, be);
        off += 16;
        if (incl > len - off) { r->truncated = 1; break; }
        const uint8_t *pk = buf + off; size_t pl = incl; off += incl;
        r->packets++; r->bytes += incl;
        double ts = (double)sec + (double)frac / (nano ? 1e9 : 1e6);
        if (t0 < 0) t0 = ts;
        t1 = ts;

        size_t o = 0;
        if (link == 1) {
            if (pl < 14) continue;
            uint16_t et = rd16n(pk + 12); o = 14;
            while ((et == 0x8100 || et == 0x88a8) && pl >= o + 4) { et = rd16n(pk + o + 2); o += 4; }
            if (et != 0x0800) continue;
        }
        if (pl < o + 20 || (pk[o] >> 4) != 4) continue;
        size_t ihl = (size_t)(pk[o] & 15) * 4;
        if (ihl < 20 || pl < o + ihl) continue;
        uint16_t frag = rd16n(pk + o + 6);
        if (frag & 0x1fff) continue;
        uint8_t proto = pk[o + 9];
        uint32_t s = rd32n(pk + o + 12), d = rd32n(pk + o + 16);
        r->ip_packets++;
        const uint8_t *l4 = pk + o + ihl; size_t l4n = pl - o - ihl;
        uint16_t sp = 0, dp = 0; const uint8_t *payload = NULL; size_t pn = 0; uint8_t flags = 0;
        if (proto == 6 && l4n >= 20) {
            sp = rd16n(l4); dp = rd16n(l4 + 2); flags = l4[13];
            size_t th = (size_t)(l4[12] >> 4) * 4;
            if (th < 20 || th > l4n) continue;
            payload = l4 + th; pn = l4n - th; r->tcp++;
        } else if (proto == 17 && l4n >= 8) {
            sp = rd16n(l4); dp = rd16n(l4 + 2); payload = l4 + 8; pn = l4n - 8; r->udp++;
            if (dp == 53) r->dns_queries++;
        } else continue;

        flow_slot *fs = flow_get(flows, s, d, sp, dp, proto, &r->flows, &r->flows_dropped);
        if (fs) { fs->f.bytes += incl; fs->f.packets++; }

        if (proto == 6 && (flags & 0x12) == 0x02) {   /* SYN without ACK */
            src_stat *st = src_get(srcs, &nsrc, s);
            if (st) {
                st->syns++;
                if (set_add(sets, s, d, dp, &set_count)) st->targets++;
                if (set_add(sets, s, d, 0xffffffffu, &set_count)) st->dsts++;
            }
        }
        if (proto == 6 && pn > 0) look_for_creds(r, pend, s, d, dp, payload, pn);
    }
    r->duration = t0 < 0 ? 0 : t1 - t0;

    for (int i = 0; i < nsrc && r->n_scanners < PT_MAX_SCANNERS; i++) {
        if (srcs[i].targets >= thr) {
            pt_scanner *sc = &r->scanners[r->n_scanners++];
            sc->src = srcs[i].src; sc->targets = srcs[i].targets; sc->dsts = srcs[i].dsts; sc->syns = srcs[i].syns;
            sc->kind = srcs[i].dsts >= thr ? "host sweep" : "port scan";
        }
    }
    /* top talkers */
    pt_flow *all = malloc(sizeof *all * (r->flows ? r->flows : 1));
    if (all) {
        uint32_t n = 0;
        for (uint32_t i = 0; i < FLOW_CAP; i++) if (flows[i].used) all[n++] = flows[i].f;
        qsort(all, n, sizeof *all, cmp_flow);
        for (uint32_t i = 0; i < n && i < PT_MAX_TALKERS; i++) r->talkers[r->n_talkers++] = all[i];
        free(all);
    }
    free(flows); free(sets); free(srcs); free(pend);
    return 0;
}

static void ip(char *b, size_t cap, uint32_t a) { snprintf(b, cap, "%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255); }

void pt_render_text(FILE *f, const pt_report *r) {
    char a[20], b[20];
    fprintf(f, "pcap-triage: %llu packets, %u flows, %llu bytes, %.1fs%s\n", (unsigned long long)r->packets, r->flows, (unsigned long long)r->bytes, r->duration, r->truncated ? " (capture truncated)" : "");
    fprintf(f, "tcp %llu, udp %llu, dns queries %llu\n\n", (unsigned long long)r->tcp, (unsigned long long)r->udp, (unsigned long long)r->dns_queries);
    fprintf(f, "SCANNERS (%d)\n", r->n_scanners);
    for (int i = 0; i < r->n_scanners; i++) {
        const pt_scanner *s = &r->scanners[i]; ip(a, sizeof a, s->src);
        fprintf(f, "  %-15s %s: %u distinct targets on %u hosts, %u SYNs\n", a, s->kind, s->targets, s->dsts, s->syns);
    }
    fprintf(f, "\nCLEARTEXT CREDENTIALS (%d), passwords are never printed\n", r->n_creds);
    for (int i = 0; i < r->n_creds; i++) {
        const pt_cred *c = &r->creds[i]; ip(a, sizeof a, c->src); ip(b, sizeof b, c->dst);
        fprintf(f, "  %-5s %s -> %s:%u  user=%s  password=%zu chars\n", c->proto, a, b, c->dport, c->user, c->pwlen);
    }
    fprintf(f, "\nTOP FLOWS BY BYTES\n");
    for (int i = 0; i < r->n_talkers; i++) {
        const pt_flow *t = &r->talkers[i]; ip(a, sizeof a, t->src); ip(b, sizeof b, t->dst);
        fprintf(f, "  %s:%u -> %s:%u  %s  %llu bytes, %u packets\n", a, t->sport, b, t->dport, t->proto == 6 ? "tcp" : "udp", (unsigned long long)t->bytes, t->packets);
    }
}

static void hesc(FILE *f, const char *s) {
    for (; *s; s++) {
        switch (*s) { case '&': fputs("&amp;", f); break; case '<': fputs("&lt;", f); break; case '>': fputs("&gt;", f); break; case '"': fputs("&quot;", f); break; default: fputc(*s, f); }
    }
}

void pt_render_html(FILE *f, const pt_report *r) {
    char a[20], b[20];
    fputs("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
          "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>pcap-triage</title>"
          "<style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}h2{margin:26px 0 6px;font-size:16px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #2a3441}th{color:#8b98a8}.bad{color:#f85149;font-weight:700}code{color:#7ee787}</style></head><body>", f);
    fprintf(f, "<h1>pcap-triage</h1><p class=\"sub\">Packet capture triage in C, no dependencies. Synthetic capture: %llu packets, %u flows, %.1fs. Passwords are never shown.</p>", (unsigned long long)r->packets, r->flows, r->duration);
    fprintf(f, "<h2>Scanners (%d)</h2><table><tr><th>Source</th><th>Kind</th><th>Targets</th><th>Hosts</th><th>SYNs</th></tr>", r->n_scanners);
    for (int i = 0; i < r->n_scanners; i++) { const pt_scanner *s = &r->scanners[i]; ip(a, sizeof a, s->src); fprintf(f, "<tr><td class=\"bad\">%s</td><td>%s</td><td>%u</td><td>%u</td><td>%u</td></tr>", a, s->kind, s->targets, s->dsts, s->syns); }
    fprintf(f, "</table><h2>Cleartext credentials (%d)</h2><table><tr><th>Protocol</th><th>From</th><th>To</th><th>User</th><th>Password</th></tr>", r->n_creds);
    for (int i = 0; i < r->n_creds; i++) {
        const pt_cred *c = &r->creds[i]; ip(a, sizeof a, c->src); ip(b, sizeof b, c->dst);
        fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s:%u</td><td class=\"bad\">", c->proto, a, b, c->dport); hesc(f, c->user); fprintf(f, "</td><td>%zu chars</td></tr>", c->pwlen);
    }
    fputs("</table><h2>Top flows by bytes</h2><table><tr><th>Flow</th><th>Bytes</th><th>Packets</th></tr>", f);
    for (int i = 0; i < r->n_talkers; i++) {
        const pt_flow *t = &r->talkers[i]; ip(a, sizeof a, t->src); ip(b, sizeof b, t->dst);
        fprintf(f, "<tr><td>%s:%u &rarr; %s:%u %s</td><td>%llu</td><td>%u</td></tr>", a, t->sport, b, t->dport, t->proto == 6 ? "tcp" : "udp", (unsigned long long)t->bytes, t->packets);
    }
    fputs("</table><p class=\"sub\">Triage, not forensics: it reads Ethernet and raw IPv4 captures (classic pcap), TCP and UDP only.</p></body></html>\n", f);
}
