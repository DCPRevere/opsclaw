# PairingGuard uses `parking_lot` but should be async

`security/pairing.rs:41` has a TODO to switch from `spawn_blocking` with a parking_lot mutex to tokio's async mutex or flume channels. The current approach blocks a runtime thread during pairing.
