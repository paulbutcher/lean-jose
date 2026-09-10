# Changelog

## 0.2.1

- The Wycheproof vectors carry a key's `alg` as an `Option`, so the four groups whose key declares none are run again rather than skipped.
- The vector generator stops on a case member it cannot read, rather than standing a placeholder in for it.

## 0.2.0

- The Wycheproof vectors are a package of their own, `vectors`, which another library's suite can require.

## 0.1.1

- Updated to `leancrypto` 0.4.1.

## 0.1.0

- The pure core: compact serialization, the ECDSA signature conversions, and JSON read by `lean-json` behind a length and a nesting limit.
- JWK and JWK Set reading, RFC 7638 thumbprints, and key selection.
- Verification behind a `Backend`, with a pure one covering HS, RS and PS.
- JWT claim decoding and validation against an instant the caller supplies.
- HMAC signing, enough for `client_secret_jwt` client authentication.
