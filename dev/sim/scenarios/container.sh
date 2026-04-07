# Container down — api container missing from docker ps
# Triggers: ContainerDown (Critical)

source /sim/scenarios/baseline.sh

sim_docker() {
    if [[ "$*" == *"ps --format json"* ]]; then
        # api container is gone
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
