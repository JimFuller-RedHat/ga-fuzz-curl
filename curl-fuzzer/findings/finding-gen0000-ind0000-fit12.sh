#!/bin/bash
#
# Fuzzer Finding Report
#
# Fitness Score: 12
# Exit Code: 0
# Notes: Fitness components: {"http_anomaly": 2.0, "exit_code": 10.0}
#

curl --socks4 localhost:8080 --proto-redir =https --request-target /tmp --http2-prior-knowledge --tlsv1 --output-dir /dev/null --proxy-ciphers ALL http://localhost:8080
