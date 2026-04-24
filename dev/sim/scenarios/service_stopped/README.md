# service_stopped

Kills myapp. Port 8080 stops listening, pidfile removed. Tests that
the agent identifies a missing known service and names it in the
alert.
