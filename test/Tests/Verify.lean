/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Pure
import Leancrypto.Codec.Base64Url

/-!
Verification, against the published tokens of RFC 7515 and against tokens built to break it.

The first check is the one the rest exists for. A verifier that chose its algorithm from the token's
own header would take an RSA public key, which is not secret, as an HMAC secret, and anyone holding
that key could then mint tokens. The token below is a real HMAC over a real signing input, which the
second check demonstrates by verifying it against the same bytes offered as a symmetric key; the
first says that a key set holding it as an RSA key refuses it.
-/

namespace Tests.Verify
open Jose Leancrypto

/-- RFC 7515 A.1, the HS256 example, and A.2, the RS256 one. Both were checked against OpenSSL
before being written down here: the A.1 tag is the HMAC of its signing input under the A.1 key, and
the A.2 signature verifies under the A.2 modulus. -/
private def payload : String :=
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

private def a1Header : String := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"

private def a1Signature : String := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

private def a1Key : String :=
  "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4h" ++
  "cgUuTwjAzZr1Z9CAow\"}"

private def a2Header : String := "eyJhbGciOiJSUzI1NiJ9"

private def a2Signature : String :=
  "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5" ++
  "jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb" ++
  "1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QO" ++
  "YEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

private def a2Modulus : String :=
  "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4" ++
  "d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5re" ++
  "xMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxX" ++
  "FvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"

private def a2Key : String :=
  "{\"kty\":\"RSA\",\"n\":\"" ++ a2Modulus ++ "\",\"e\":\"AQAB\"}"

/-- The A.2 public key in the PEM an issuer publishes, offered as a symmetric key. This is the
attacker's half of the confusion: the same bytes, called something else. -/
private def a2KeyAsSecret : String :=
  "{\"kty\":\"oct\",\"k\":\"" ++
  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FR" ++
  "RUFvZmdXQ3VManliUmx6bzB0WldKagpOaXVTZmI0cDRmQWtkL3dXSmN5UW9UYmppOWswbDhXMjZtUGRkeEhtZkhRcCtW" ++
  "YXcrNHFQQ0pyY1MybUpQTUV6ClAxUHQwQm00ZDRRbEwreVJUK1NGZDJsWlMrcENnTk1zRDFXL1lwUlBFd09Xdkc2YjMy" ++
  "NjkwcjJqWjQ3c29NWm8KOXdHempiLzdPTWcwTE9MK2JTZjYza3BhU0hTWG5kUzV6NXJleE1kYkJZVXNMQTllK0tYQmRR" ++
  "T1MrVVRvN1dUQgpFTWEyUjJDYXBIZzY2NXhzbXRkVk1UQlFZNHVEWmx4dmIzcUNvNVp3S2g5a0c0TFQ2L0k1SWhsSkg3" ++
  "YUdoeXhYCkZ2VUsrRFdObW91ZEY4TkFjbzkvaDlpYUdOajhxMmV0aEZrTUxzOTFremsyUEFjRFRXOWdiNTRoNEZSV3l1" ++
  "WHAKb1FJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg\"}"

/-- HS256 over the A.1 payload, keyed with the bytes of the A.2 public key. Generated with OpenSSL,
so the tag is a genuine HMAC and a verifier that accepted it would be doing so for the reason the
attack relies on rather than by accident. -/
private def confusionToken : String :=
  "eyJhbGciOiJIUzI1NiJ9." ++ payload ++ ".c8Tg3ipPrf5_HrYg61gCx0plq6GU74R-LeYmADiLgfs"

private def token (header signature : String) : String :=
  header ++ "." ++ payload ++ "." ++ signature

private def keys (jwks : List String) : KeySet Backend.pure :=
  match Jwks.parse {} ("{\"keys\":[" ++ String.intercalate "," jwks ++ "]}") with
  | .ok set => Pure.keySet set
  | .error _ => Pure.keySet Jwks.empty

private def policy (algs : Array Alg) : Policy :=
  (Policy.mk? algs "joe" #["everyone"]).getD
    { algs := #[.rs256], issuer := "joe", audience := #["everyone"] }

private def isError {α : Type} (result : Except Error α) (expected : Error) : Bool :=
  match result with
  | .error actual => actual == expected
  | .ok _ => false

private def verifies (algs : Array Alg) (jwks : List String) (token : String) : Bool :=
  (Pure.verify (policy algs) (keys jwks) token).isOk

private def refuses (algs : Array Alg) (jwks : List String) (token : String) (expected : Error) :
    Bool :=
  isError (Pure.verify (policy algs) (keys jwks) token) expected

/-- One bit of the decoded part, flipped, and the part written back out. Flipping a base64url
character instead would risk changing nothing, since several characters can encode the same bits at
the end of a part. -/
private def tamper (text : String) (index : Nat) : String :=
  match Codec.Base64Url.decodeString text with
  | none => text
  | some bytes => Codec.Base64Url.encodeString ⟨bytes.data.modify index (· ^^^ 1)⟩

/-- The `T` of `"typ":"JWT"` in the A.1 header, and the `j` of `"iss":"joe"` in the payload. Both
stay inside a string, so the tampered part is still the JSON it was, and what fails is the
signature rather than the parse. -/
private def headerByte : Nat := 10

private def payloadByte : Nat := 8

/-- The `R` of `"alg":"RS256"` in the A.2 header, which carries nothing else. A bit flipped anywhere
in that header changes the algorithm it names, so what refuses the token is the name rather than the
signature; the A.1 header, which has a `typ` to disturb instead, is where the signature covering the
header is what shows. -/
private def algByte : Nat := 8

/-- RFC 7520 §4.2, the PS384 example, signed with the RSA key that RFC gives in §3.4. The signature
was verified against that modulus with OpenSSL before being written here.

This pair is what settles a disagreement with Project Wycheproof, whose copy of the key carries an
`alg` of PS256 that RFC 7520 does not put there. Both checks below are this library's rule that a
key is used only for the algorithm it declares: with the key as the RFC publishes it, declaring
nothing, the token verifies; with an `alg` added, it does not. -/
private def figure20 : String :=
  "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2V" ++
  "yb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5" ++
  "kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJ" ++
  "lIHN3ZXB0IG9mZiB0by4.cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6" ++
  "VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyP" ++
  "EgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6u" ++
  "iP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw"

private def bilboModulus : String :=
  "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmS" ++
  "CpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-Of" ++
  "VfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKw" ++
  "uCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw"

/-- The key as RFC 7520 §3.4 publishes it: `kty`, `kid`, `use`, and the two components. It declares
no algorithm, which is the whole of the difference. -/
private def bilboKey : String :=
  "{\"kty\":\"RSA\",\"kid\":\"bilbo.baggins@hobbiton.example\",\"use\":\"sig\",\"n\":\"" ++
  bilboModulus ++ "\",\"e\":\"AQAB\"}"

private def bilboKeyDeclaring (alg : String) : String :=
  "{\"kty\":\"RSA\",\"kid\":\"bilbo.baggins@hobbiton.example\",\"use\":\"sig\",\"alg\":\"" ++ alg ++
  "\",\"n\":\"" ++ bilboModulus ++ "\",\"e\":\"AQAB\"}"

private def es256Token : String :=
  "eyJhbGciOiJFUzI1NiJ9." ++ payload ++ "." ++
  "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

private def es256Key : String :=
  "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," ++
  "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}"

public def checks : List (String × Bool) :=
  [ ("a token signed HS256 with the bytes of an RSA public key is refused",
      refuses #[.rs256, .hs256] [a2Key] confusionToken (.noKeyMatched none)),
    ("that token is a real HMAC over those bytes, so the refusal is the key type and not the tag",
      verifies #[.hs256] [a2KeyAsSecret] confusionToken),
    ("an RSA key offered for HMAC is refused by the backend as well as by selection",
      match Jwks.parse {} ("{\"keys\":[" ++ a2Key ++ "]}") with
      | .ok set =>
        match set.keys[0]? with
        | some key =>
          isError (Pure.verifySignature .hs256 (Pure.prepare key) "x".toUTF8 "y".toUTF8)
            (.keyKindMismatch .hs256 .rsa)
        | none => false
      | .error _ => false),
    ("the RFC 7515 A.1 token verifies under the A.1 key",
      verifies #[.hs256] [a1Key] (token a1Header a1Signature)),
    ("the RFC 7515 A.2 token verifies under the A.2 key",
      verifies #[.rs256] [a2Key] (token a2Header a2Signature)),
    ("a bit flipped in the A.1 signature refuses it",
      refuses #[.hs256] [a1Key] (token a1Header (tamper a1Signature 0)) .signatureInvalid),
    ("a bit flipped in the A.1 payload refuses it",
      refuses #[.hs256] [a1Key]
        (a1Header ++ "." ++ tamper payload payloadByte ++ "." ++ a1Signature) .signatureInvalid),
    ("a bit flipped in the A.1 header refuses it",
      refuses #[.hs256] [a1Key] (token (tamper a1Header headerByte) a1Signature) .signatureInvalid),
    ("a bit flipped in the A.2 signature refuses it",
      refuses #[.rs256] [a2Key] (token a2Header (tamper a2Signature 0)) .signatureInvalid),
    ("a bit flipped in the A.2 payload refuses it",
      refuses #[.rs256] [a2Key]
        (a2Header ++ "." ++ tamper payload payloadByte ++ "." ++ a2Signature) .signatureInvalid),
    ("a bit flipped in the A.2 header refuses it, as an algorithm nobody named",
      refuses #[.rs256] [a2Key] (token (tamper a2Header algByte) a2Signature)
        (.algUnknown "SS256")),
    ("the RFC 7520 §4.2 token verifies under the key that RFC publishes for it",
      verifies #[.ps384] [bilboKey] figure20),
    ("a key declaring one algorithm does not verify a signature made with another",
      refuses #[.ps384] [bilboKeyDeclaring "PS256"] figure20 (.noKeyMatched (some
        "bilbo.baggins@hobbiton.example"))
        && verifies #[.ps384] [bilboKeyDeclaring "PS384"] figure20),
    ("an ES256 token names the algorithm this backend lacks, and never says the signature is bad",
      refuses #[.es256] [es256Key] es256Token (.algUnsupported .es256 "pure")),
    ("an algorithm outside the policy is refused before any key is looked at",
      refuses #[.rs256] [a1Key] (token a1Header a1Signature) (.algRejected .hs256)),
    ("a header with no alg is refused",
      refuses #[.hs256] [a1Key] (token "eyJ0eXAiOiJKV1QifQ" a1Signature) .algMissing),
    ("an alg of none is refused as a name this library does not know",
      refuses #[.hs256] [a1Key] (token "eyJhbGciOiJub25lIn0" a1Signature) (.algUnknown "none")),
    ("an unsecured token is refused for its shape before its header is read",
      refuses #[.hs256] [a1Key] ("eyJhbGciOiJub25lIn0." ++ payload ++ ".") .emptySignature),
    ("a kid that no key carries is refused as a key set that has grown stale",
      refuses #[.hs256] [a1Key] (token "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0" a1Signature)
        (.noKeyMatched (some "k1"))),
    ("a crit naming a registered header parameter is refused",
      refuses #[.hs256] [a1Key] (token "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsia2lkIl19" a1Signature)
        (.critRegistered "kid")),
    ("a crit naming an extension this library does not implement is refused",
      refuses #[.hs256] [a1Key] (token "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYjY0Il19" a1Signature)
        (.critUnsupported "b64")),
    ("an empty crit is refused",
      refuses #[.hs256] [a1Key] (token "eyJhbGciOiJIUzI1NiIsImNyaXQiOltdfQ" a1Signature)
        .critEmpty),
    ("a header naming alg twice is refused",
      refuses #[.hs256] [a1Key]
        (token "eyJhbGciOiJIUzI1NiIsImFsZyI6Im5vbmUifQ" a1Signature)
        (.duplicateMember .header "alg")),
    ("a policy demanding a typ refuses a token without one",
      match Policy.mk? #[.hs256] "joe" #["everyone"] (typ := some "JWT") with
      | some policy =>
        isError (Pure.verify policy (keys [a1Key]) (token "eyJhbGciOiJIUzI1NiJ9" a1Signature))
          (.wrongTyp "JWT" none)
      | none => false),
    ("a typ is compared without regard to case or to the media type prefix",
      match Policy.mk? #[.hs256] "joe" #["everyone"] (typ := some "application/jwt") with
      | some policy => (Pure.verify policy (keys [a1Key]) (token a1Header a1Signature)).isOk
      | none => false) ]

end Tests.Verify
