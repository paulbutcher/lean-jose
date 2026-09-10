/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Jwks

/-!
Reading a JWK, and the thumbprint of one. The published thumbprints are the backbone: a canonical
form that sorted its members differently, or wrote a component to a different width, would still
round-trip through this library and still be wrong, and only a constant from outside it says so.
-/

namespace Tests.Jwk
open Jose

/-- The modulus of the RFC 7638 §3.1 worked example. -/
private def modulus : String :=
  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP" ++
  "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY" ++
  "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f" ++
  "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

/-- RFC 7638 §3.1, member for member as that section prints it. -/
private def rfc7638Key : String :=
  "{\"kty\":\"RSA\",\"n\":\"" ++ modulus ++ "\",\"e\":\"AQAB\",\"alg\":\"RS256\"," ++
  "\"kid\":\"2011-04-29\"}"

/-- The canonical form RFC 7638 §3.1 prints for that key. -/
private def rfc7638Canonical : String :=
  "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"" ++ modulus ++ "\"}"

private def rfc7638Thumbprint : String := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

private def rsaKeyWith (exponent : String) : String :=
  "{\"kty\":\"RSA\",\"n\":\"" ++ modulus ++ "\",\"e\":\"" ++ exponent ++ "\"}"

/-- The same key with nothing but its required members, so that a check adding one member differs
from this in that member alone. -/
private def rsaKey : String := rsaKeyWith "AQAB"

/-- RFC 8037 §2, the Ed25519 example, whose thumbprint that RFC prints. -/
private def rfc8037Key : String :=
  "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"

private def rfc8037Thumbprint : String := "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

private def parseOne (text : String) : Except Error Jose.Jwk := do
  Jwk.parse (← Read.parse {} .keySet text.toUTF8)

private def usable (text : String) : Option Jose.Jwk := (parseOne text).toOption

private def refuses (text : String) (expected : Error) : Bool :=
  match parseOne text with
  | .error actual => actual == expected
  | .ok _ => false

/-- Refused when read alone, and set aside rather than refused when read as part of a set. -/
private def setAside (text : String) : Bool :=
  match parseOne text with
  | .error reason =>
    Jwks.ignorable reason
      && (match Jwks.parse {} ("{\"keys\":[" ++ text ++ "]}") with
          | .ok set => set.keys.isEmpty && set.skipped.size == 1
          | .error _ => false)
  | .ok _ => false

private def thumbprintOf (text : String) : Option String := (usable text).map Jwk.thumbprint

private def canonicalOf (text : String) : Option String := (usable text).map Jwk.canonical

/-- A key with one more member in front of the ones it has, so that a check differs from the key it
is built from in exactly that member. -/
private def withMember (member : String) (text : String) : String :=
  "{" ++ member ++ "," ++ (text.drop 1).toString

private def withPrivate (name : String) (text : String) : String :=
  withMember ("\"" ++ name ++ "\":\"AQAB\"") text

private def p256X : String := "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"

private def p256Y : String := "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

private def ecKey (x y : String) : String :=
  "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" ++ x ++ "\",\"y\":\"" ++ y ++ "\"}"

private def keySet : String :=
  "{\"keys\":[" ++ rfc7638Key ++ "," ++ rfc8037Key ++ ",{\"kty\":\"unknown\"}]}"

private def selected (kid : Option String) (algs : Array Alg) : Array Jose.Jwk :=
  match Jwks.parse {} keySet with
  | .ok set => set.select kid algs
  | .error _ => #[]

/--
An object whose names are a list without repeats, and whose values hold no repeats of their own,
repeats no name. This is the shape every canonical form below has, and it is separated out because
the names are a constant while the values are whatever key arrived.

`hfields` names the list, so that `hnames` can be a claim about literal text rather than about the
key; `Nodup` of that list is `distinctNames` of the object by `distinctNames_iff`. `hvalues` is the
same question asked of what the members hold, which for a canonical form is a string apiece and so
holds by computation. `UniqueKeys` is the conjunction of the two, at this object and below it.
-/
private theorem uniqueKeys_of_names (fields : Array (String × _root_.Json)) (names : List String)
    (hfields : _root_.Json.fieldNames fields = names) (hnames : names.Nodup)
    (hvalues : _root_.Json.uniqueKeysFields fields.toList = true) :
    _root_.Json.UniqueKeys (.obj fields) := by
  rw [_root_.Json.UniqueKeys, _root_.Json.uniqueKeys, Bool.and_eq_true]
  exact ⟨(_root_.Json.distinctNames_iff fields).mpr (hfields ▸ hnames), hvalues⟩

/--
The text a thumbprint is taken over denotes exactly the members this library put into it. RFC 7638
fixes the digest input as a JSON object, so what is hashed has to be an encoding of that object and
not merely a string that resembles one; this says the printer's output is read back as the value it
was printed from, which is what makes the hash a hash of the key rather than of some text about it.

`Jwk.canonical` is `compress` of `Jwk.canonicalValue`, and the equation puts that text through the
parser and recovers the value itself. The configuration turns off both limits, so the claim is
about the encoding rather than about any policy: nothing is refused for its size or its nesting.
What it stands on is `lean-json`'s `Json.parse_compress`, whose hypotheses are discharged for every
key: the names distinct by `uniqueKeys_of_names`, which is `Json.distinctNames_iff` at this shape of
object, and the numbers vacuously canonical because a canonical form holds only strings.
-/
theorem canonical_denotes (key : Jose.Jwk) :
    _root_.Json.parse (Jose.Jwk.canonical key) { maxNumberDigits := none, maxDepth := none }
      = .ok (Jose.Jwk.canonicalValue key) := by
  obtain ⟨material, kid, alg⟩ := key
  have hkeys : _root_.Json.UniqueKeys (Jose.Jwk.canonicalValue ⟨material, kid, alg⟩) := by
    cases material
    · exact uniqueKeys_of_names _ ["k", "kty"] rfl (by decide) rfl
    · exact uniqueKeys_of_names _ ["e", "kty", "n"] rfl (by decide) rfl
    · exact uniqueKeys_of_names _ ["crv", "kty", "x", "y"] rfl (by decide) rfl
    · exact uniqueKeys_of_names _ ["crv", "kty", "x"] rfl (by decide) rfl
  exact _root_.Json.parse_compress rfl (Or.inr hkeys) nofun (by cases material <;> rfl)

/--
A thumbprint is taken over the members RFC 7638 §3.2 requires for the key's type, in the order it
requires them, and over nothing else. Two of the four are pinned by a published thumbprint below;
this covers all four, including the EC and `oct` forms that no RFC here prints a vector for.

The existential says the canonical form is an object and names its members in order. RFC 7638 §3.2
requires the members registered as required for the key type, sorted by name as JSON strings, which
for these names is ascending ASCII: `k` before `kty`, `e` before `kty` before `n`, and `crv` before
`kty` before `x` before `y`. A member this library does not read cannot appear, since the list is
the whole of what is written.
-/
theorem canonical_names (key : Jose.Jwk) :
    ∃ fields, Jose.Jwk.canonicalValue key = .obj fields ∧ _root_.Json.fieldNames fields =
      match key.material with
      | .oct _ => ["k", "kty"]
      | .rsa _ _ => ["e", "kty", "n"]
      | .ec _ _ _ => ["crv", "kty", "x", "y"]
      | .okp _ _ => ["crv", "kty", "x"] := by
  obtain ⟨material, kid, alg⟩ := key
  cases material <;> exact ⟨_, rfl, rfl⟩

public def checks : List (String × Bool) :=
  [ ("the RFC 7638 §3.1 key has the canonical form that RFC prints",
      canonicalOf rfc7638Key == some rfc7638Canonical),
    ("the RFC 7638 §3.1 key has the thumbprint that RFC publishes",
      thumbprintOf rfc7638Key == some rfc7638Thumbprint),
    ("the RFC 8037 §2 key has the thumbprint that RFC publishes",
      thumbprintOf rfc8037Key == some rfc8037Thumbprint),
    ("the thumbprint is over the required members alone",
      thumbprintOf rfc7638Key == thumbprintOf (withMember "\"kid\":\"another\"" rsaKey)),
    ("a private component is refused rather than dropped",
      ["d", "p", "q", "dp", "dq", "qi", "oth"].all fun name =>
        refuses (withPrivate name rfc7638Key) (.jwkPrivateComponent name)),
    ("an EC key with a private component is refused",
      refuses (withPrivate "d" (ecKey p256X p256Y)) (.jwkPrivateComponent "d")),
    ("an OKP key with a private component is refused",
      refuses (withPrivate "d" rfc8037Key) (.jwkPrivateComponent "d")),
    ("a coordinate of the wrong width for its curve is refused",
      refuses (ecKey (p256X.take 40).toString p256Y) (.jwkBadMember "x")
        && refuses (ecKey p256X (p256Y ++ "AA")) (.jwkBadMember "y")),
    ("a missing component is named",
      refuses "{\"kty\":\"RSA\",\"e\":\"AQAB\"}" (.jwkMissingMember "n")
        && refuses "{\"kty\":\"EC\",\"crv\":\"P-256\"}" (.jwkMissingMember "x")
        && refuses "{\"n\":\"AQAB\"}" (.jwkMissingMember "kty")),
    ("a component that is not base64url is refused",
      refuses "{\"kty\":\"oct\",\"k\":\"not base64url!\"}" (.jwkBadMember "k")),
    ("a key type this library does not read is set aside",
      setAside "{\"kty\":\"unknown\"}"),
    ("a curve this library does not read is set aside",
      setAside "{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"x\":\"AA\",\"y\":\"AA\"}"),
    ("a key published for encryption is set aside",
      setAside (withMember "\"use\":\"enc\"" rsaKey)),
    ("a key whose operations exclude verification is set aside",
      setAside (withMember "\"key_ops\":[\"encrypt\"]" rsaKey)
        && (usable (withMember "\"key_ops\":[\"verify\"]" rsaKey)).isSome),
    ("a key naming an algorithm this library does not name is set aside",
      setAside (withMember "\"alg\":\"RSA-OAEP\"" rsaKey)),
    ("a key naming an algorithm its type cannot take is refused, not set aside",
      refuses (withMember "\"alg\":\"HS256\"" rsaKey) (.keyKindMismatch .hs256 .rsa)
        && !Jwks.ignorable (.keyKindMismatch .hs256 .rsa)),
    ("a broken key fails the whole set rather than being passed over",
      (Jwks.parse {} ("{\"keys\":[" ++ withPrivate "d" rfc7638Key ++ "]}")).isOk == false),
    ("an RSA key whose exponent could not have signed anything is refused",
      refuses (rsaKeyWith "AQ") (.jwkBadMember "e")
        && refuses (rsaKeyWith "Ag") (.jwkBadMember "e")
        && (usable (rsaKeyWith "Aw")).isSome),
    ("two keys carrying the same kid make a set with two answers, so the set is refused",
      match Jwks.parse {} ("{\"keys\":[" ++ rfc7638Key ++ "," ++ rfc7638Key ++ "]}") with
      | .error reason => reason == .duplicateKid "2011-04-29"
      | .ok _ => false),
    ("a set holding a shared secret beside a public key is refused",
      match Jwks.parse {} ("{\"keys\":[" ++ rsaKey ++ ",{\"kty\":\"oct\",\"k\":\"AQAB\"}]}") with
      | .error reason => reason == .mixedKeySet
      | .ok _ => false),
    ("a key set keeps the keys it reads and sets aside the rest",
      match Jwks.parse {} keySet with
      | .ok set => set.keys.size == 2 && set.skipped.size == 1
      | .error _ => false),
    ("a kid selects one key and an unknown kid selects none",
      (selected (some "2011-04-29") #[.rs256]).size == 1
        && (selected (some "absent") #[.rs256]).size == 0),
    ("without a kid every key the policy's algorithms admit is selected",
      (selected none #[.rs256]).size == 1
        && (selected none #[.eddsa]).size == 1
        && (selected none #[.rs256, .eddsa]).size == 2
        && (selected none #[.es256]).size == 0),
    ("a key restricted to one algorithm is not selected for another",
      (selected none #[.ps256]).size == 0) ]

end Tests.Jwk
