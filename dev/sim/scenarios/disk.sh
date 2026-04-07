# Disk full — /data at 92% usage
# Triggers: DiskSpaceLow (Critical)

source /sim/scenarios/baseline.sh

sim_df() {
    cat <<'EOF'
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   18G   30G  38% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
/dev/sdb1       200G  184G   16G  92% /data
EOF
}
