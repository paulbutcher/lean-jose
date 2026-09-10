/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Jwt

/-!
Claim validation, at every instant that decides an answer. Nothing here reads a clock: the instant
is an argument, so the boundary cases are reachable and stay reachable.
-/

namespace Tests.Jwt
open Jose Std.Time

private def expiry : Int := 1300819380

private def notBefore : Int := 1300819300

private def moment (seconds : Int) : Timestamp :=
  Timestamp.ofSecondsSinceUnixEpoch (Second.Offset.ofInt seconds)

private def policy (leeway : Second.Offset := 0) : Policy :=
  (Policy.mk? #[.hs256] "joe" #["everyone"] (leeway := leeway)).getD
    { algs := #[.hs256], issuer := "joe", audience := #["everyone"] }

private def payload (members : String) : ByteArray := members.toUTF8

private def full : String :=
  "{\"iss\":\"joe\",\"aud\":\"everyone\",\"sub\":\"user\",\"jti\":\"id-1\"," ++
  "\"iat\":1300819300,\"nbf\":1300819300,\"exp\":1300819380}"

private def accepts (text : String) (seconds : Int) (leeway : Second.Offset := 0) : Bool :=
  (Jwt.check (policy leeway) (moment seconds) (payload text)).isOk

private def refuses (text : String) (seconds : Int) (expected : Error)
    (leeway : Second.Offset := 0) : Bool :=
  match Jwt.check (policy leeway) (moment seconds) (payload text) with
  | .error actual => actual == expected
  | .ok _ => false

/-- The claims of `full`, as a token signed HS256 with the RFC 7515 A.1 key. Generated with
OpenSSL, so what it exercises is the whole path rather than the claims alone. -/
private def token : String :=
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." ++
  "eyJpc3MiOiJqb2UiLCJhdWQiOiJldmVyeW9uZSIsInN1YiI6InVzZXIiLCJqdGkiOiJpZC0xIiwiaWF0IjoxMzAwODE5" ++
  "MzAwLCJuYmYiOjEzMDA4MTkzMDAsImV4cCI6MTMwMDgxOTM4MH0." ++
  "NSIGNJdLDGZ1gRy2GbLNk1NuCb_5MvZCKsKlADAJj6E"

private def a1Key : String :=
  "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4h" ++
  "cgUuTwjAzZr1Z9CAow\"}"

private def keys : KeySet Backend.pure :=
  match Jwks.parse {} ("{\"keys\":[" ++ a1Key ++ "]}") with
  | .ok set => Pure.keySet set
  | .error _ => Pure.keySet Jwks.empty

private def claimsOf (text : String) : Option Claims := (Jwt.decode {} (payload text)).toOption

public def checks : List (String × Bool) :=
  [ ("a token is valid one second before it expires",
      accepts full (expiry - 1)),
    ("a token expiring at the instant compared against has expired",
      refuses full expiry (.expired expiry expiry)),
    ("a token is expired one second after it expires",
      refuses full (expiry + 1) (.expired expiry (expiry + 1))),
    ("leeway moves the expiry boundary and no more",
      accepts full (expiry + 59) (leeway := 60)
        && refuses full (expiry + 60) (.expired expiry (expiry + 60)) (leeway := 60)
        && refuses full (expiry + 61) (.expired expiry (expiry + 61)) (leeway := 60)),
    ("a token is valid at the instant it becomes valid",
      accepts full notBefore),
    ("a token is not yet valid one second before that",
      refuses full (notBefore - 1) (.notYetValid notBefore (notBefore - 1))),
    ("leeway moves the not-before boundary and no more",
      accepts full (notBefore - 60) (leeway := 60)
        && refuses full (notBefore - 61) (.notYetValid notBefore (notBefore - 61))
          (leeway := 60)),
    ("a token with no expiry is refused rather than treated as one that never expires",
      refuses "{\"iss\":\"joe\",\"aud\":\"everyone\"}" 0 (.claimMissing "exp")),
    ("the issuer must be the policy's",
      refuses "{\"iss\":\"eve\",\"aud\":\"everyone\",\"exp\":1300819380}" (expiry - 1)
        (.wrongIssuer "joe" "eve")
        && refuses "{\"aud\":\"everyone\",\"exp\":1300819380}" (expiry - 1) (.claimMissing "iss")),
    ("an audience is met by any one of its members",
      accepts "{\"iss\":\"joe\",\"aud\":[\"other\",\"everyone\"],\"exp\":1300819380}" (expiry - 1)
        && refuses "{\"iss\":\"joe\",\"aud\":[\"other\"],\"exp\":1300819380}" (expiry - 1)
          (.wrongAudience #["everyone"] #["other"])
        && refuses "{\"iss\":\"joe\",\"exp\":1300819380}" (expiry - 1) (.claimMissing "aud")),
    ("a claim of the wrong type is refused rather than read as absent",
      refuses "{\"iss\":\"joe\",\"aud\":\"everyone\",\"exp\":\"1300819380\"}" 0
          (.claimMalformed "exp")
        && refuses "{\"iss\":1,\"aud\":\"everyone\",\"exp\":1300819380}" 0 (.claimMalformed "iss")
        && refuses "{\"iss\":\"joe\",\"aud\":[1],\"exp\":1300819380}" 0 (.claimMalformed "aud")),
    ("the seven registered claims are read, and the object is kept for the rest",
      match claimsOf ((full.dropEnd 1).toString ++ ",\"scope\":\"read\"}") with
      | some claims =>
        claims.issuer == some "joe" && claims.subject == some "user"
          && claims.audience == some #["everyone"] && claims.expiry == some expiry
          && claims.notBefore == some notBefore && claims.issuedAt == some notBefore
          && claims.id == some "id-1"
          && Read.stringMember? claims.value "scope" == some "read"
      | none => false),
    ("a payload that is not an object is refused",
      match Jwt.decode {} (payload "[1,2]") with
      | .error reason => reason == .notAnObject .payload
      | .ok _ => false),
    ("a signed token is verified and its claims checked in one pass",
      (Pure.jwt (policy) keys token (moment (expiry - 1))).isOk
        && match Pure.jwt (policy) keys token (moment expiry) with
           | .error reason => reason == .expired expiry expiry
           | .ok _ => false),
    ("a tampered payload is refused for its signature, before its claims are read",
      match Pure.jwt (policy) keys
          ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJldmUifQ." ++
            "NSIGNJdLDGZ1gRy2GbLNk1NuCb_5MvZCKsKlADAJj6E") (moment (expiry - 1)) with
      | .error reason => reason == .signatureInvalid
      | .ok _ => false) ]

end Tests.Jwt
