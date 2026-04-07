# Doctor doesn't check data source connectivity

`ops/doctor.rs` checks SSH, disk, LLM, and notifications but never tests that configured Prometheus/Seq/Jaeger endpoints are reachable. Add a `check_data_sources` diagnostic.
