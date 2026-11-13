#include "pcap_triage.h"
#include <stdlib.h>
#include <string.h>

static const char *USAGE = "usage: pcap-triage <capture.pcap> [--html] [--threshold N] [--fail-on-find]\n"
    "Reads classic pcap files (Ethernet or raw IPv4). Exit: 0 ok, 1 findings with --fail-on-find, 2 bad input.\n";

int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] == '-') { fputs(USAGE, stderr); return 2; }
    int html = 0, fail = 0; unsigned thr = 20;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--html")) html = 1;
        else if (!strcmp(argv[i], "--fail-on-find")) fail = 1;
        else if (!strcmp(argv[i], "--threshold") && i + 1 < argc) { long v = strtol(argv[++i], NULL, 10); if (v < 1 || v > 100000) { fputs("error: --threshold must be 1..100000\n", stderr); return 2; } thr = (unsigned)v; }
        else { fprintf(stderr, "error: unknown option %s\n%s", argv[i], USAGE); return 2; }
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > (512L << 20)) { fputs("error: file too large (limit 512 MB)\n", stderr); fclose(f); return 2; }
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fputs("error: read failed\n", stderr); free(buf); fclose(f); return 2; }
    fclose(f);
    static pt_report rep;
    int rc = pt_analyze(buf, (size_t)sz, thr, &rep);
    free(buf);
    if (rc != 0) { fprintf(stderr, "error: %s\n", rc == -1 ? "file too short for a pcap" : rc == -2 ? "not a classic pcap file (bad magic)" : rc == -3 ? "unsupported link type (need Ethernet or raw IP)" : "out of memory"); return 2; }
    if (html) pt_render_html(stdout, &rep); else pt_render_text(stdout, &rep);
    return (fail && (rep.n_scanners || rep.n_creds)) ? 1 : 0;
}
