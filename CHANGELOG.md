# Changelog

## 0.1.0

- The pure core: compact serialization, the ECDSA signature conversions, and JSON read by `lean-json` behind a length and a nesting limit.
- JWK and JWK Set reading, RFC 7638 thumbprints, and key selection.
- Verification behind a `Backend`, with a pure one covering HS, RS and PS.
- JWT claim decoding and validation against an instant the caller supplies.
- HMAC signing, enough for `client_secret_jwt` client authentication.
