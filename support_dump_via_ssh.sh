# 1. Collect UniFi Core logs
tar -zcvf unifi-core-logs.tar.gz /data/unifi-core/logs/

# 2. Collect ULP-Go logs
tar -zcvf ulp-go-logs.tar.gz /data/ulp-go/log/

# 3. Generate system support dump, then tar it
ubnt-systool support /tmp/system
tar -zcvf system.tar.gz /tmp/system

# 4. Bundle everything into a single timestamped archive
tar -zcvf "$(date +%Y%m%d-%H%M%S)-support.tar.gz" \
  unifi-core-logs.tar.gz \
  ulp-go-logs.tar.gz \
  system.tar.gz

# 5. Cleanup intermediary files (optional)
rm -f unifi-core-logs.tar.gz ulp-go-logs.tar.gz system.tar.gz

# 6. to download from admin machine: scp root@<console-ip>:/tmp/*-support.tar.gz .
