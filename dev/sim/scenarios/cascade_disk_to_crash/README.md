# cascade_disk_to_crash

Two concurrent faults: disk filled + myapp SIGSTOPped. Tests whether
the agent reports both problems or only the first it notices. Dedup
window allows up to two alerts for this scenario.
