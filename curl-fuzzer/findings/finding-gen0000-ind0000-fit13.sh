#!/bin/bash
#
# Fuzzer Finding Report
#
# Fitness Score: 13
# Exit Code: 0
# Notes: Fitness components: {"exit_code": 10.0, "stderr": 3.0}
#

curl --abstract-unix-socket /dev/null --cert /dev/null --crlfile /tmp/curl-fuzz-out --false-start --ftp-account %00%01%02 --header X-Custom: 
Injected: true --hostpubmd5 0000000000000000000000000000000000000000000000000000000000000000 --hostpubsha256 0000000000000000000000000000000000000000000000000000000000000000 --http1.0 --keepalive-cnt 635 --mail-rcpt-allowfails --post303 --random-file /dev/null --remote-name-all --request TRACE --retry-max-time 101 --show-error --socks5 127.0.0.1:1080 --ssl-reqd --time-cond Mon, 01 Jan 2024 00:00:00 GMT --user-agent  http://localhost:8080
