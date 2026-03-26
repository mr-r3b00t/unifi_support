ssh root@<console-ip> 'tar -zcvf /tmp/$(date +%Y%m%d-%H%M%S)-backups.tar.gz /data/unifi/data/backup/ /data/unifi-core/backups/' && scp root@<console-ip>:/tmp/*-backups.tar.gz .
