/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Jwks

public section

namespace Jose

/-- The whole of the boundary with cryptography. Everything else in this package is pure and knows
nothing of how a signature is checked, which is what lets a sibling package supply the algorithms
this one cannot reach without either of them changing.

The record is `IO`-shaped although the backend shipped here is pure, so that nothing above it has to
be parametric in a monad; that parameter would otherwise reach every consumer. `Except Error Bool`
is two answers rather than one: an `Error` is this backend being unable to check that signature, and
`false` is the signature being wrong. -/
structure Backend where
  PreparedKey : Type
  prepare : Jwk → IO (Except Error PreparedKey)
  verify : Alg → PreparedKey → (signingInput signature : ByteArray) → IO (Except Error Bool)
  sign : Alg → PreparedKey → (signingInput : ByteArray) → IO (Except Error ByteArray)

/-- A key converted once, with the components it was converted from kept beside it. The components
are what selection reads, so a key set is searched without asking the backend anything. -/
structure Prepared (backend : Backend) where
  jwk : Jwk
  key : backend.PreparedKey

/-- Keys prepared for one backend. A token is checked against this rather than against a `Jwks`, so
that a key is converted when the set is read and not once per token. -/
structure KeySet (backend : Backend) where
  keys : Array (Prepared backend)
  skipped : Array Error

namespace KeySet

def ofJwks (backend : Backend) (set : Jwks) : IO (Except Error (KeySet backend)) := do
  let mut prepared : Array (Prepared backend) := #[]
  for key in set.keys do
    match ← backend.prepare key with
    | .error reason => return .error reason
    | .ok converted => prepared := prepared.push { jwk := key, key := converted }
  return .ok { keys := prepared, skipped := set.skipped }

def select {backend : Backend} (set : KeySet backend) (kid : Option String) (algs : Array Alg) :
    Array (Prepared backend) :=
  set.keys.filter fun prepared => prepared.jwk.admits kid algs

end KeySet
end Jose
