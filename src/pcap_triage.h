#ifndef PCAP_TRIAGE_H
#define PCAP_TRIAGE_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PT_MAX_SCANNERS 16
#define PT_MAX_CREDS 32
#define PT_MAX_TALKERS 5

typedef struct { uint32_t src; unsigned targets, dsts, syns; const char *kind; } pt_scanner;
typedef struct { char proto[8]; uint32_t src, dst; uint16_t dport; char user[48]; size_t pwlen; } pt_cred;
typedef struct { uint32_t src, dst; uint16_t sport, dport; uint8_t proto; uint64_t bytes; uint32_t packets; } pt_flow;

typedef struct {
    uint64_t packets, bytes, ip_packets, tcp, udp, dns_queries;
    uint32_t flows, flows_dropped;
    double duration;
    int truncated;
    pt_scanner scanners[PT_MAX_SCANNERS]; int n_scanners;
    pt_cred creds[PT_MAX_CREDS]; int n_creds;
    pt_flow talkers[PT_MAX_TALKERS]; int n_talkers;
} pt_report;

/* 0 ok, -1 too short, -2 bad magic, -3 unsupported link type, -4 out of memory */
int pt_analyze(const uint8_t *buf, size_t len, unsigned scan_threshold, pt_report *out);
void pt_render_text(FILE *f, const pt_report *r);
void pt_render_html(FILE *f, const pt_report *r);
#endif
