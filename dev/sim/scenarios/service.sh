# Service stopped — nginx.service missing from systemctl
# Triggers: ServiceStopped (Critical)

source /sim/scenarios/baseline.sh

sim_systemctl() {
    cat <<'EOF'
UNIT                     LOAD   ACTIVE SUB     DESCRIPTION
postgresql.service       loaded active running PostgreSQL RDBMS
redis-server.service     loaded active running Advanced key-value store
ssh.service              loaded active running OpenBSD Secure Shell server
cron.service             loaded active running Regular background program processing

4 loaded units listed.
EOF
}
