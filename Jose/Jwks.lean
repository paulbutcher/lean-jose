/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Jwk

public section

namespace Jose

/-- A JWK Set as it was published, with the entries this library will not use kept beside the ones
it will. The skipped reasons are not an error: a set that mixes a signing key with an encryption key
is ordinary, and it is only a set with nothing usable in it that is worth reporting, which the
reasons then explain.

This is a parsed document and not a prepared key set. Preparation belongs to a backend, and a
`KeySet` is what it produces. -/
structure Jwks where
  keys : Array Jwk
  skipped : Array Error

namespace Jwks

def empty : Jwks := { keys := #[], skipped := #[] }

def ofKeys (keys : Array Jwk) : Jwks := { keys := keys, skipped := #[] }

/-- The failures that are ordinary in a published set rather than a fault in it. RFC 7517 §5 says to
ignore a key whose `kty` is not understood, and the rest are the same thing said by another member:
the key is for an algorithm, a curve, or a purpose that is not this one. A set that mixes a signing
key with an encryption key is what a real issuer publishes.

Everything else stays an error, including a key whose `alg` contradicts its `kty`. That one is not a
key for something else; it is a key that does not say what it is. -/
def ignorable : Error → Bool
  | .jwkUnknownKeyType _ | .jwkUnknownCurve _ | .algUnknown _ | .jwkUse _ | .jwkKeyOps => true
  | _ => false

/-- A JWK Set from bytes. Fetching one over HTTPS, and deciding how long to trust it, is the
caller's; nothing here goes near a network. -/
def parse (limits : Limits) (text : String) : Except Error Jwks := do
  let document ← Read.parseObject limits .keySet text.toUTF8
  let set ← readEntries document
  -- A published set holding a shared secret beside a public key is one of two mistakes: a secret
  -- that has been published, or a public key handed to something that expected a secret. Neither
  -- is a set to go looking for a verification key in.
  if set.keys.any (·.material.kind == .oct) && set.keys.any (·.material.kind != .oct) then
    .error .mixedKeySet
  else .ok set
where
  readEntries (document : Read.Value) : Except Error Jwks :=
    match Read.member? document "keys" with
    | none => .error (.jwkMissingMember "keys")
    | some (.arr entries) =>
      entries.foldlM (init := empty) fun set entry =>
        match Jwk.parse entry with
        | .ok key =>
          -- RFC 7517 §4.5 leaves a repeated `kid` to the reader. A set with one is refused rather
          -- than resolved, because the header names a key by it and two answers is not one.
          match key.kid with
          | some kid =>
            if set.keys.any (fun existing => existing.kid == some kid) then
              .error (.duplicateKid kid)
            else .ok { set with keys := set.keys.push key }
          | none => .ok { set with keys := set.keys.push key }
        | .error reason =>
          if ignorable reason then .ok { set with skipped := set.skipped.push reason }
          else .error reason
    | some _ => .error (.jwkBadMember "keys")

/-- The keys of the set that carry the `kid` given, if one is given, and whose type and declared
`alg` admit one of the algorithms given.

A `kid` that names nothing selects nothing, rather than falling back to the rest of the set. The
fallback would turn a rotated-out key into an attempt against every other key the issuer publishes,
and the empty result is what tells a caller its key set is stale. -/
def select (set : Jwks) (kid : Option String) (algs : Array Alg) : Array Jwk :=
  set.keys.filter (Jwk.admits · kid algs)

end Jwks
end Jose
