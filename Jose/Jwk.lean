/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Read
public import Leancrypto.Codec.Base64Url
public import Leancrypto.Rsa
public import Leancrypto.Sha2

public section

namespace Jose

open Leancrypto

/-- The components of a key, as RFC 7517 spells them. No prepared key and no algorithm
implementation: turning these into something a signature can be checked against is the backend's
job, and happens once per key rather than once per token. -/
inductive KeyMaterial where
  | oct (key : ByteArray)
  | rsa (modulus exponent : Nat)
  | ec (crv : Crv) (x y : ByteArray)
  | okp (crv : OkpCrv) (x : ByteArray)
  deriving DecidableEq

def KeyMaterial.kind : KeyMaterial → KeyKind
  | .oct _ => .oct
  | .rsa _ _ => .rsa
  | .ec _ _ _ => .ec
  | .okp _ _ => .okp

/-- A key this library could use, with the two members that decide whether it is the right one for a
token: `kid`, which a header may name, and `alg`, which restricts the key to one algorithm.

`use` and `key_ops` are not carried, because they are spent: a key they exclude from verification
never becomes one of these. -/
structure Jwk where
  material : KeyMaterial
  kid : Option String
  alg : Option Alg
  deriving DecidableEq

namespace Jwk

private def decode (name : String) (value : Read.Value) : Except Error ByteArray := do
  match Read.asString? value with
  | none => .error (.jwkBadMember name)
  | some text =>
    match Codec.Base64Url.decodeString text with
    | none => .error (.jwkBadMember name)
    | some bytes => .ok bytes

private def required (value : Read.Value) (name : String) : Except Error ByteArray := do
  match Read.member? value name with
  | none => .error (.jwkMissingMember name)
  | some member => decode name member

/-- The members RFC 7518 §6 and RFC 7638 §3.2 mark private, refused rather than dropped. A key set
that publishes one is broken in a way that matters more than the token in hand, and a parser that
quietly kept the public half would leave nothing to notice it by. -/
private def publicOnly (value : Read.Value) (names : List String) : Except Error Unit := do
  match names.find? (fun name => (Read.member? value name).isSome) with
  | some name => .error (.jwkPrivateComponent name)
  | none => .ok ()

private def coordinate (value : Read.Value) (name : String) (width : Nat) :
    Except Error ByteArray := do
  let bytes ← required value name
  if bytes.size = width then .ok bytes else .error (.jwkBadMember name)

private def curve (value : Read.Value) : Except Error Crv := do
  match Read.stringMember? value "crv" with
  | none => .error (.jwkMissingMember "crv")
  | some name =>
    match Crv.ofString name with
    | none => .error (.jwkUnknownCurve name)
    | some crv => .ok crv

private def materialOf (value : Read.Value) (kind : KeyKind) : Except Error KeyMaterial := do
  match kind with
  | .oct => .ok (.oct (← required value "k"))
  | .rsa =>
    publicOnly value ["d", "p", "q", "dp", "dq", "qi", "oth"]
    let modulus := Rsa.natOfBytes (← required value "n")
    let exponent := Rsa.natOfBytes (← required value "e")
    -- An exponent of 1 leaves the signature equal to the block it should have been derived from,
    -- so anyone can produce one; an even exponent is not invertible modulo a product of two odd
    -- primes, so no signature could have been made with it. Neither is a key.
    if exponent < 3 || exponent % 2 = 0 then .error (.jwkBadMember "e")
    else if modulus = 0 then .error (.jwkBadMember "n")
    else .ok (.rsa modulus exponent)
  | .ec =>
    publicOnly value ["d"]
    let crv ← curve value
    let width := crv.coordinateSize
    let x ← coordinate value "x" width
    let y ← coordinate value "y" width
    .ok (.ec crv x y)
  | .okp =>
    publicOnly value ["d"]
    match Read.stringMember? value "crv" with
    | none => .error (.jwkMissingMember "crv")
    | some name =>
      match OkpCrv.ofString name with
      | none => .error (.jwkUnknownCurve name)
      | some crv =>
        let x ← coordinate value "x" crv.keySize
        .ok (.okp crv x)

/-- A JWK, strictly: every check that could change which key a token is verified against is an
error here, including the ones a key set will go on to treat as ordinary. Which of those are
ordinary is `Jwks.ignorable`, and it is stated there because it is a property of reading a set
rather than of reading a key. -/
def parse (value : Read.Value) : Except Error Jwk := do
  let kty ← match Read.member? value "kty" with
    | none => .error (.jwkMissingMember "kty")
    | some member =>
      match Read.asString? member with
      | none => .error (.jwkBadMember "kty")
      | some kty => .ok kty
  let kind ← match KeyKind.ofString kty with
    | none => .error (.jwkUnknownKeyType kty)
    | some kind => .ok kind
  match Read.member? value "use" with
  | none => .ok ()
  | some use =>
    match Read.asString? use with
    | none => .error (.jwkBadMember "use")
    | some "sig" => .ok ()
    | some other => .error (.jwkUse other)
  -- `key_ops` is read for `verify` alone, since nothing here does anything else with a public key,
  -- and a key that does not list it is one its publisher meant for something else.
  match Read.member? value "key_ops" with
  | some ops =>
    match Read.asStringArray? ops with
    | none => .error (.jwkBadMember "key_ops")
    | some operations => if operations.contains "verify" then .ok () else .error .jwkKeyOps
  | none => .ok ()
  let alg ← match Read.member? value "alg" with
    | none => .ok none
    | some member =>
      match Read.asString? member with
      | none => .error (.jwkBadMember "alg")
      | some name =>
        match Alg.ofString name with
        | none => .error (.algUnknown name)
        | some alg =>
          if alg.keyKind = kind then .ok (some alg) else .error (.keyKindMismatch alg kind)
  let kid ← match Read.member? value "kid" with
    | none => .ok none
    | some member =>
      match Read.asString? member with
      | none => .error (.jwkBadMember "kid")
      | some kid => .ok (some kid)
  .ok { material := ← materialOf value kind, kid := kid, alg := alg }

/-- The members RFC 7638 §3.2 keeps, in the order it sorts them. Written out per key type rather
than assembled from the parsed object, so that a member this library does not read cannot reach the
digest, and the ordering is the constant it has to be rather than something a sort might get wrong.

The components are written back from their values, which is minimal big-endian as RFC 7518 §6.3
requires them to have been written. A key that arrived with a leading zero octet it was not
entitled to therefore has the thumbprint its conforming spelling would have. -/
@[expose] def canonicalValue (jwk : Jwk) : Read.Value :=
  let encode := Codec.Base64Url.encodeString
  let integer (n : Nat) := encode (Rsa.bytesOfNat (Rsa.byteLength n) n)
  match jwk.material with
  | .oct key => .obj #[("k", .str (encode key)), ("kty", .str "oct")]
  | .rsa modulus exponent =>
    .obj #[("e", .str (integer exponent)), ("kty", .str "RSA"), ("n", .str (integer modulus))]
  | .ec crv x y =>
    .obj #[("crv", .str crv.name), ("kty", .str "EC"), ("x", .str (encode x)),
      ("y", .str (encode y))]
  | .okp crv x => .obj #[("crv", .str crv.name), ("kty", .str "OKP"), ("x", .str (encode x))]

/-- The text RFC 7638 §3.2 hashes: no whitespace, and each value written as JSON rather than pasted
between quotes, so that the encoding is the printer's business and this module's only business is
which members go in and in what order. -/
@[expose] def canonical (jwk : Jwk) : String := Json.compress (canonicalValue jwk)

/-- Whether this key may be tried for a token: it carries the `kid` the header named, if the header
named one, and its type and its own `alg` admit one of the algorithms the policy allows. -/
def admits (key : Jwk) (kid : Option String) (algs : Array Alg) : Bool :=
  (match kid with | none => true | some wanted => key.kid == some wanted)
    && algs.any fun alg => alg.keyKind == key.material.kind && key.alg.all (· == alg)

/-- The RFC 7638 thumbprint: SHA-256 over the canonical members, base64url. -/
def thumbprint (jwk : Jwk) : String :=
  Codec.Base64Url.encodeString (Sha256.hashUtf8 (canonical jwk))

end Jwk
end Jose
