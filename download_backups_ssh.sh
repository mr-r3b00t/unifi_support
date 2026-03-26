CONSOLE=root@192.168.0.1

ssh "$CONSOLE" 'tar -zcvf /tmp/$(date +%Y%m%d-%H%M%S)-backups.tar.gz /data/unifi/data/backup/ /data/unifi-core/backups/' && scp "$CONSOLE":"/tmp/*-backups.tar.gz" .
