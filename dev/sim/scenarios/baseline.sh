# Baseline scenario — healthy system
# Provides fake output for commands not natively available in the sim container
# (docker, systemctl) and realistic defaults for others.

sim_free() {
    cat <<'EOF'
               total        used        free      shared  buff/cache   available
Mem:            8000        3200        2400         128        2400        4600
Swap:           2048           0        2048
EOF
}

sim_df() {
    cat <<'EOF'
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   18G   30G  38% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
/dev/sdb1       200G   95G   95G  50% /data
EOF
}

sim_uptime() {
    echo " 12:00:00 up 45 days,  3:22,  1 user,  load average: 0.45, 0.38, 0.32"
}

sim_docker() {
    # Only respond to `docker ps --format json`
    if [[ "$*" == *"ps --format json"* ]]; then
        cat <<'EOF'
{"ID":"a1b2c3d4e5f6","Names":"api","Image":"myapp/api:latest","Status":"Up 3 hours","Ports":"0.0.0.0:3000->3000/tcp","RunningFor":"3 hours"}
{"ID":"b2c3d4e5f6a1","Names":"worker","Image":"myapp/worker:latest","Status":"Up 3 hours","Ports":"","RunningFor":"3 hours"}
{"ID":"c3d4e5f6a1b2","Names":"redis","Image":"redis:7-alpine","Status":"Up 2 days","Ports":"6379/tcp","RunningFor":"2 days"}
{"ID":"d4e5f6a1b2c3","Names":"postgres","Image":"postgres:16","Status":"Up 2 days","Ports":"5432/tcp","RunningFor":"2 days"}
EOF
    else
        echo ""
        exit 1
    fi
}

sim_ss() {
    cat <<'EOF'
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1,fd=3))
LISTEN 0      128          0.0.0.0:3000       0.0.0.0:*    users:(("nginx",pid=100,fd=6))
LISTEN 0      128          0.0.0.0:3001       0.0.0.0:*    users:(("myapp",pid=200,fd=4))
LISTEN 0      128        127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=300,fd=5))
LISTEN 0      128        127.0.0.1:6379       0.0.0.0:*    users:(("redis",pid=400,fd=6))
EOF
}

sim_systemctl() {
    cat <<'EOF'
UNIT                     LOAD   ACTIVE SUB     DESCRIPTION
nginx.service            loaded active running A high performance web server
postgresql.service       loaded active running PostgreSQL RDBMS
redis-server.service     loaded active running Advanced key-value store
ssh.service              loaded active running OpenBSD Secure Shell server
cron.service             loaded active running Regular background program processing

5 loaded units listed.
EOF
}
