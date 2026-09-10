/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Pure
import Tests.WycheproofVectors

/-!
Project Wycheproof's JSON Web Signature suite, run against this backend. The vectors are in
`Tests.WycheproofVectors`, generated from the suite's own JSON rather than copied out of it.

Each case says whether a library should accept the token; what is checked is that this one agrees,
so a case is a failure both when a forgery is accepted and when a sound token is refused.
-/

namespace Tests.Wycheproof
open Jose

/-- Every algorithm this backend performs. The suite's cases are about verification rather than
about policy, so the policy is as wide as the backend; a case is then refused by the check it was
written to exercise rather than by an algorithm this test pinned. -/
private def algs : Array Alg :=
  #[.hs256, .hs384, .hs512, .rs256, .rs384, .rs512, .ps256, .ps384, .ps512]

private def policy : Policy :=
  (Policy.mk? algs "joe" #["everyone"]).getD
    { algs := #[.hs256], issuer := "joe", audience := #["everyone"] }

/-- A key the suite publishes for encryption, or one this library will not read, leaves the set
empty rather than failing it, and every token then has no key to be checked against. That is the
answer those groups are testing for. -/
private def keysOf (group : Group) : KeySet Backend.pure :=
  match Jwks.parse {} ("{\"keys\":[" ++ group.key ++ "]}") with
  | .ok set => Pure.keySet set
  | .error _ => Pure.keySet Jwks.empty

private def run (group : Group) : List (String × Bool) :=
  let keys := keysOf group
  group.cases.map fun vector =>
    (s!"wycheproof {group.comment} {group.alg} {vector.id}",
      (Pure.verify policy keys vector.jws).isOk == vector.valid)

public def checks : List (String × Bool) := groups.flatMap run

end Tests.Wycheproof
