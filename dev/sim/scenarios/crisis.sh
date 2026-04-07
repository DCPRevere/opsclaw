# Combined crisis — memory pressure + disk full + api container down
# Triggers: HighMemory (Warning), DiskSpaceLow (Critical), ContainerDown (Critical)

source /sim/scenarios/baseline.sh

sim_free() {
    cat <<'EOF'
               total        used        free      shared  buff/cache   available
Mem:            8000        7600          80         128         320         280
Swap:           2048        1200         848
EOF
}

sim_df() {
    cat <<'EOF'
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   18G   30G  38% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
/dev/sdb1       200G  184G   16G  92% /data
EOF
}

sim_docker() {
    if [[ "$*" == *"ps --format json"* ]]; then
        cat <<'EOF'
{"ID":"b2c3d4e5f6a1","Names":"worker","Image":"myapp/worker:latest","Status":"Up 3 hours","Ports":"","RunningFor":"3 hours"}
{"ID":"c3d4e5f6a1b2","Names":"redis","Image":"redis:7-alpine","Status":"Up 2 days","Ports":"6379/tcp","RunningFor":"2 days"}
{"ID":"d4e5f6a1b2c3","Names":"postgres","Image":"postgres:16","Status":"Up 2 days","Ports":"5432/tcp","RunningFor":"2 days"}
EOF
    else
        echo ""
        exit 1
    fi
}
