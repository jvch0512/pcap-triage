CFLAGS ?= -std=c11 -Wall -Wextra -O2

pcap-triage: src/pcap_triage.c src/main.c src/pcap_triage.h
	$(CC) $(CFLAGS) -o $@ src/pcap_triage.c src/main.c

test: tests/test.c src/pcap_triage.c src/pcap_triage.h
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined -o tests/run tests/test.c src/pcap_triage.c
	./tests/run

sample: pcap-triage
	python3 examples/make_sample.py
	./pcap-triage examples/sample.pcap > docs/sample-output.txt
	./pcap-triage examples/sample.pcap --html > site/index.html

clean:
	rm -f pcap-triage tests/run
