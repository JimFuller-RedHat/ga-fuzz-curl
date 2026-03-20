#!/bin/bash
#
# Fuzzer Finding Report
#
# Fitness Score: 10
# Exit Code: 0
# Notes: Fitness components: {"exit_code": 10.0}
#

curl --compressed-ssh --create-dirs --data-ascii {"key":"value"} --data-urlencode name=foo bar --dump-header - --ftp-account key=value --globoff --http2-prior-knowledge --ip-tos cs4 --max-time 285 --parallel-immediate --post302 --proxy-ntlm --proxy-pass ../../../etc/passwd --proxy-pinnedpubkey 0000000000000000000000000000000000000000000000000000000000000000 --retry-max-time 165 --service-name HTTP --socks5-basic --stderr - --tls-max 2 --trace-ascii /dev/null --trace-time --upload-flags test --verbose http://localhost:8080
