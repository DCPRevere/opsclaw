# port_closed

iptables DROP on myapp's port while the process itself keeps running.
Tests that the agent actually probes the endpoint, not just checks
`ps`/`ss`.
