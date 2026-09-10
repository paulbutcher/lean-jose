# jose

JSON Web Signature, JSON Web Key, and JSON Web Token in pure Lean 4: RFCs 7515, 7517, 7518, 7519, 7638 and 8037.

Given a string somebody handed you, it returns either a set of verified claims or a specific reason for rejecting it.

| Algorithms | Verify | Sign |
| --- | --- | --- |
| `HS256` `HS384` `HS512` | yes | yes |
| `RS256` `RS384` `RS512` | yes | no |
| `PS256` `PS384` `PS512` | yes | no |
| `ES256` `ES384` `ES512` | no | no |
| `EdDSA` | no | no |

A client that needs something this table does not offer can use [`jose-libcrypto`](https://github.com/paulbutcher/jose-libcrypto), which supplies the same interface over libcrypto.

**The algorithm never comes from the token.** A `Policy` names the algorithms you accept. The token's `alg` is compared against that list and refused if it is absent from it.

## Usage

```lean
require jose from git "https://github.com/paulbutcher/lean-jose"
```

```lean
import Jose
open Jose

def policy : Policy :=
  { algs := #[.rs256],
    issuer := "https://accounts.google.com",
    audience := #["my-client-id"] }

/-- The JWKS document is bytes the caller fetched. -/
def check (jwks token : String) : IO (Except Error Claims) := do
  match Jwks.parse {} jwks with
  | .error reason => return .error reason
  | .ok published => Jwt.verifyNow Backend.pure policy (Pure.keySet published) token
```

`Jwt.verifyNow` is the only thing in the library that reads a clock. Everything under it is pure:

```lean
def checkAt (published : Jwks) (token : String) (now : Std.Time.Timestamp) : Except Error Claims :=
  Pure.jwt policy (Pure.keySet published) token now
```

Signing is enough for `client_secret_jwt` client authentication and no more:

```lean
def assertion (secret : Jwk) (claims : String) : Except Error String :=
  Pure.token .hs256 (Pure.prepare secret) "{\"alg\":\"HS256\",\"typ\":\"JWT\"}" claims
```

## Where it is strict

Each of the following refuses something another library might accept.

- A `kid` in the header that matches no key selects nothing, rather than falling back to the rest of the set.
- A key is held to the `alg` it declares, so a key published for `PS256` will not verify a `PS384` signature.
- `exp` is required.
- An HMAC key shorter than its digest is refused, as RFC 7518 §3.2 requires.
- A key set is refused if two keys share a `kid`, or if it holds a shared secret beside a public key.
- A member name written twice is refused, in a header, a payload or a key set.
- A `crit` header is always refused.
- Whitespace anywhere in a token is refused rather than trimmed.

## What is verified

Proved as theorems, for all inputs, in `test`:

- A token the parser accepts is exactly its signing input, a separator, and its signature, so the bytes whose signature is checked are bytes of the token as it arrived. A second theorem puts no separator inside any part, which makes that signing input the prefix ending at the second separator and no other.
- Every algorithm name is read back as the algorithm that wrote it, over the whole enumeration, and each `ES` algorithm names the curve RFC 7518 §3.4 pairs it with, at that curve's width. `none` is not a value of the algorithm type, and neither is any of the near misses a lenient parser might take for one.
- On any token this library accepted, the member it reads under a name is the member a reader resolving a repeated name by taking the last would read, so no other implementation can read a different header out of the bytes whose signature was checked. This is built on `lean-json`'s `Json.Parser.uniqueKeys_parse`, which says a parse told to refuse a repeated name returns no object carrying one, read through its `Json.distinctNames_iff`.
- A thumbprint is taken over a text that denotes exactly the members RFC 7638 §3.2 requires for the key's type, in the order it requires them, for all four types rather than only the two a published vector covers. That the text denotes them is built on `lean-json`'s `Json.parse_compress`, which says compact output is read back as the value it was printed from; which members and in what order is proved here.
- An ECDSA coordinate survives the trip through the integer DER writes it as, at any width and leading zeros included, and a coordinate of a curve's width never denotes a value that width cannot hold.

Checked against published vectors, not proved:

- RFC 7515 A.1 and A.2 verify under the keys those appendices publish, and A.1 is reproduced from its header, its payload and its key rather than only verified.
- RFC 7520 §4.2 verifies under the RSA key that RFC gives in §3.4, which carries no algorithm of its own.
- RFC 7638 §3.1 and RFC 8037 §2 have the thumbprints those sections publish, and RFC 7638 §3.1 the canonical form it prints, member for member.
- Project Wycheproof's JSON Web Signature suite, 354 of its 401 cases, and its JSON Web Key suite, 25 of 26. The 41 others in the first are its `ES*` groups, which this backend cannot perform and the suite skips; the remaining six, and the one key case, are left out of the vectors themselves, with the reason recorded there.

Checked against constructed inputs:

- A bit flipped in the signature, the payload or the header refuses the token, at A.1 and at A.2.
- A key is used only for the algorithm it declares, an algorithm outside the policy is refused before any key is read, and a token offering an RSA key for HMAC is refused for the kind of key and never for its tag.
- An unsecured token, an absent `alg`, a `crit`, a header member spelled twice, whitespace, a fourth part and an over-long token are each refused, and the error names what decided it.
- Every claim boundary is exact to the second in both directions, with leeway and without, and a token carrying no `exp` is refused rather than read as one that never expires.
- A key set refuses a duplicate `kid`, a shared secret beside a public key, a private component, a coordinate of the wrong width for its curve, and an RSA exponent that could not have signed anything, while setting aside the keys it merely cannot read.
- The DER reader refuses a coordinate written behind a needless zero octet, a value too wide for the curve, a third integer, a missing one, a wrong tag, and bytes after the sequence.

Checked over drawn values, not proved:

- An ECDSA signature written as `R‖S` reads back as itself through DER at all three curves, over coordinates nobody here chose. This is the half of that round trip the proof does not close, and the obstacle is recorded where the property is.

The cases above are also run against [`jose-libcrypto`](https://github.com/paulbutcher/jose-libcrypto), so this backend is cross-checked against the implementations in libcrypto.

## Building

`lake build` builds the library; `lake test` runs the suite, which lives in a subproject of its own so that nothing it needs reaches a downstream consumer. The properties above are run with [Plausible](https://github.com/leanprover-community/plausible), which that subproject requires and a consumer of this library does not.

The Wycheproof vectors are a package of their own, `vectors`, which requires nothing at all, so another JOSE library's suite can run the same cases:

```lean
require wycheproof from git "https://github.com/paulbutcher/lean-jose" / "vectors"
```
