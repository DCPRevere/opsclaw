# Memory pressure — 95% memory usage
# Triggers: HighMemory (Warning)

source /sim/scenarios/baseline.sh

sim_free() {
    cat <<'EOF'
               total        used        free      shared  buff/cache   available
Mem:            8000        7600          80         128         320         280
Swap:           2048        1200         848
EOF
}
