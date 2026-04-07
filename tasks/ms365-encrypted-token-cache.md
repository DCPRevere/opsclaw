# Microsoft 365 encrypted token cache

`tools/microsoft365/auth.rs:43` bails with "encryption is not yet implemented". Implement encrypted-at-rest token storage so the `token_cache_encrypted = true` config path works.
