# cpu

4-way stress-ng matrix-product saturates all vCPUs. Load average climbs
into the 3–5 range. Tests that the agent notices CPU/load pressure and
calls opsclaw_notify with category matching cpu/load.
