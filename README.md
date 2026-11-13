# pcap-triage

Someone hands you a packet capture and says "is anything wrong in here?". pcap-triage answers the first five minutes of that question: who is scanning, which logins crossed the wire in cleartext, and where the bytes went.

**Live demo:** https://jvch0512.github.io/pcap-triage/ (a report on the synthetic capture in `examples/`)

C11, no dependencies, one binary. Reads classic pcap files (Ethernet or raw IPv4; VLAN tags handled).

## Use

```bash
make
./pcap-triage capture.pcap
./pcap-triage capture.pcap --html > report.html
./pcap-triage capture.pcap --threshold 50 --fail-on-find    # exit 1 if anything is found
```

What it finds:

- **Port scans and host sweeps**: a source that sends SYN-only packets to many distinct host:port targets. One host with many ports is a `port scan`, many hosts is a `host sweep`.
- **Cleartext credentials**: FTP and POP3 `USER`/`PASS`, and HTTP Basic authentication on any port. Usernames are shown, **passwords are never printed**, only their length. Attacker-controlled strings are HTML-escaped.
- **Top flows by bytes**, DNS query count, capture duration.

See [examples/sample.pcap](examples/sample.pcap) (built by [examples/make_sample.py](examples/make_sample.py), all addresses documentation or private ranges) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- Classic pcap only. pcapng files need converting first (`editcap -F pcap in.pcapng out.pcap`).
- IPv4, TCP and UDP. No IPv6, no TCP stream reassembly: a credential split across packets in unusual ways can be missed.
- Scan detection counts SYN-only packets, so it will not see UDP or stealth scans that avoid SYN.
- Triage, not forensics: it tells you where to look in Wireshark, it does not replace it.

## Where it fits

First-pass incident response, SOC runbooks, network assessments and pentest reporting ("cleartext credentials observed on the wire"), and as a pre-sales demo of why legacy protocols still matter.

## Tests

```bash
make test    # 25 checks, AddressSanitizer + UBSan, including a 3000-case fuzz of mutated captures
```

MIT.
