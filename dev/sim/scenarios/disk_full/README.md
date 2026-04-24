# disk_full

fallocate fills the sim-target's /data tmpfs to 98%. Tests that the
agent notices disk pressure via df/du/stat and flags it, without
conflating with memory pressure.
