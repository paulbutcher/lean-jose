/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Pure
import Tests.WycheproofKeyVectors

/-!
Project Wycheproof's JSON Web Key suite, run against this backend. The vectors are in
`Tests.WycheproofKeyVectors`, generated from the suite's own JSON.

Each case is a key set and a token, and what it asks is whether reading that set and checking that
token should succeed. A set this library refuses outright and one it reads but finds no usable key
in are the same answer here, which is what the suite is asking about.
-/

namespace Tests.WycheproofKeys
open Jose

private def algs : Array Alg :=
  #[.hs256, .hs384, .hs512, .rs256, .rs384, .rs512, .ps256, .ps384, .ps512]

private def policy : Policy :=
  (Policy.mk? algs "joe" #["everyone"]).getD
    { algs := #[.hs256], issuer := "joe", audience := #["everyone"] }

private def accepts (group : Group) (jws : String) : Bool :=
  match Jwks.parse {} group.keys with
  | .error _ => false
  | .ok set => (Pure.verify policy (Pure.keySet set) jws).isOk

private def run (group : Group) : List (String × Bool) :=
  group.cases.map fun vector =>
    (s!"wycheproof key {group.comment} {vector.id}", accepts group vector.jws == vector.valid)

public def checks : List (String × Bool) := groups.flatMap run

end Tests.WycheproofKeys
