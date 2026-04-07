# Port gone — port 3000 (nginx) no longer listening
# Triggers: PortGone (Warning)

source /sim/scenarios/baseline.sh

sim_ss() {
    cat <<'EOF'
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1,fd=3))
LISTEN 0      128          0.0.0.0:3001       0.0.0.0:*    users:(("myapp",pid=200,fd=4))
LISTEN 0      128        127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=300,fd=5))
LISTEN 0      128        127.0.0.1:6379       0.0.0.0:*    users:(("redis",pid=400,fd=6))
EOF
}
