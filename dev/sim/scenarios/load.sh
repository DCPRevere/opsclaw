# High load — load average > 8.0
# Triggers: HighLoad (Warning)

source /sim/scenarios/baseline.sh

sim_uptime() {
    echo " 12:00:00 up 45 days,  3:22,  1 user,  load average: 12.50, 9.80, 7.20"
}
