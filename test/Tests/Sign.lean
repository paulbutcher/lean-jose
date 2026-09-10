/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Pure

/-!
Signing, which here is HMAC and nothing else: enough for the `client_secret_jwt` of OpenID Connect,
where the secret is shared and the assertion is small. Anything with a private key is refused by
name.

The published token is reproduced from its published header, payload and key, so what is pinned is
not only that a signature verifies against itself but that these bytes are the ones RFC 7515 says
they are.
-/

namespace Tests.Sign
open Jose

/-- RFC 7515 A.1, the header and payload as octets, with the line breaks the appendix prints. The
base64url of each was checked against OpenSSL before being written here. -/
private def a1Header : String := "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"

private def a1Payload : String :=
  "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"

private def a1Token : String :=
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." ++
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0" ++
  "cnVlfQ." ++
  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

private def a1Jwk : String :=
  "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4h" ++
  "cgUuTwjAzZr1Z9CAow\"}"

/-- A second secret, as long as the widest digest here, since RFC 7518 §3.2 requires a key at least
as long as the digest and this one is signed with at each size. -/
private def otherJwk : String :=
  "{\"kty\":\"oct\",\"k\":\"c2Vjb25kLXNlY3JldC1mb3ItdGhlLXNpZ25pbmctdGVzdHMtbG9uZy1lbm91" ++
  "Z2gtZm9yLWhzNTEyLTY0Ynl0ZQ\"}"

private def rsaJwk : String :=
  "{\"kty\":\"RSA\",\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw" ++
  "-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0" ++
  "LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5Zw" ++
  "Kh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"" ++
  ",\"e\":\"AQAB\"}"

private def jwks (text : String) : Jwks :=
  match Jwks.parse {} ("{\"keys\":[" ++ text ++ "]}") with
  | .ok set => set
  | .error _ => Jwks.empty

private def keyOf (text : String) : Pure.Key :=
  match (jwks text).keys[0]? with
  | some key => Pure.prepare key
  | none => .unusable .oct

private def policy (algs : Array Alg) : Policy :=
  (Policy.mk? algs "joe" #["everyone"]).getD
    { algs := #[.hs256], issuer := "joe", audience := #["everyone"] }

private def header (alg : Alg) : String := "{\"alg\":\"" ++ alg.name ++ "\"}"

private def signed (alg : Alg) (key : String) : Option String :=
  (Pure.token alg (keyOf key) (header alg) a1Payload).toOption

private def roundTrips (alg : Alg) : Bool :=
  match signed alg a1Jwk with
  | none => false
  | some token => (Pure.verify (policy #[alg]) (Pure.keySet (jwks a1Jwk)) token).isOk

private def refusesToSign (alg : Alg) (key : String) (expected : Error) : Bool :=
  match Pure.token alg (keyOf key) (header alg) a1Payload with
  | .error actual => actual == expected
  | .ok _ => false

public def checks : List (String × Bool) :=
  [ ("a token signed at each HMAC size verifies again",
      [Alg.hs256, .hs384, .hs512].all roundTrips),
    ("the three sizes produce three different tokens",
      signed .hs256 a1Jwk != signed .hs384 a1Jwk
        && signed .hs384 a1Jwk != signed .hs512 a1Jwk),
    ("the RFC 7515 A.1 token is reproduced from its header, its payload and its key",
      (Pure.token .hs256 (keyOf a1Jwk) a1Header a1Payload).toOption == some a1Token),
    ("a token signed under another secret does not verify",
      match signed .hs256 otherJwk with
      | none => false
      | some token =>
        match Pure.verify (policy #[.hs256]) (Pure.keySet (jwks a1Jwk)) token with
        | .error reason => reason == .signatureInvalid
        | .ok _ => false),
    ("a token signed at one size does not verify under a policy that allows another",
      match signed .hs256 a1Jwk with
      | none => false
      | some token =>
        match Pure.verify (policy #[.hs384]) (Pure.keySet (jwks a1Jwk)) token with
        | .error reason => reason == .algRejected .hs256
        | .ok _ => false),
    ("signing with an algorithm that needs a private key is refused by name",
      [Alg.rs256, .rs384, .rs512, .ps256, .ps384, .ps512, .es256, .eddsa].all fun alg =>
        refusesToSign alg a1Jwk (.algUnsupported alg "pure")),
    ("signing HMAC with a key that is not symmetric is refused as the wrong kind of key",
      refusesToSign .hs256 rsaJwk (.keyKindMismatch .hs256 .rsa)) ]

end Tests.Sign
