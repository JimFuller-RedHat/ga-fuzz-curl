#!/bin/bash
#
# Fuzzer Finding Report
#
# Fitness Score: 8
# Exit Code: 0
# Notes: Fitness components: {"http_anomaly": 2.0, "stderr": 3.0, "exit_code": 3.0}
#

curl --cookie-jar /tmp/curl-fuzz-out --oauth2-bearer test-token-12345 --pubkey /dev/null --sslv2 http://localhost:8080
