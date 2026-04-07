# Local JWKS token validation not implemented (Nevis)

`security/nevis.rs:242-255` returns an explicit error for `token_validation = "local"`. Implement local JWT/JWKS validation so deployments can avoid the remote introspection round-trip.
