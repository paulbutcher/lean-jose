/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Pure
import Wycheproof.Signatures

/-!
Project Wycheproof's JSON Web Signature suite, run against this backend. The vectors are in
`Wycheproof.Signatures`, a package of their own, generated from the suite's own JSON rather than
copied out of it.

Each case says whether a library should accept the token; what is checked is that this one agrees,
so a case is a failure both when a forgery is accepted and when a sound token is refused.
-/

namespace Tests.Wycheproof
open Jose Wycheproof.Signatures

/-- Every algorithm this backend performs. The suite's cases are about verification rather than
about policy, so the policy is as wide as the backend; a case is then refused by the check it was
written to exercise rather than by an algorithm this test pinned. -/
private def algs : Array Alg :=
  #[.hs256, .hs384, .hs512, .rs256, .rs384, .rs512, .ps256, .ps384, .ps512]

private def policy : Policy :=
  (Policy.mk? algs "joe" #["everyone"]).getD
    { algs := #[.hs256], issuer := "joe", audience := #["everyone"] }

/-- Groups this backend has an answer for. The vectors carry every group the suite publishes, so one
whose key names something `Alg.ofString` does not read, or an algorithm this backend cannot perform,
is dropped here: every case in it would be refused for that rather than for what it was written to
test. A key naming no algorithm is kept, because what those groups test is the key itself. -/
private def answerable (group : Group) : Bool :=
  match group.alg with
  | none => true
  | some name =>
    match Alg.ofString name with
    | none => false
    | some alg => algs.contains alg

/-- A key the suite publishes for encryption, or one this library will not read, leaves the set
empty rather than failing it, and every token then has no key to be checked against. That is the
answer those groups are testing for. -/
private def keysOf (group : Group) : KeySet Backend.pure :=
  match Jwks.parse {} ("{\"keys\":[" ++ group.key ++ "]}") with
  | .ok set => Pure.keySet set
  | .error _ => Pure.keySet Jwks.empty

private def run (group : Group) : List (String × Bool) :=
  let keys := keysOf group
  let alg := group.alg.getD "no alg"
  group.cases.map fun vector =>
    (s!"wycheproof {group.comment} {alg} {vector.id}",
      (Pure.verify policy keys vector.jws).isOk == vector.valid)

public def checks : List (String × Bool) := (groups.filter answerable).flatMap run

end Tests.Wycheproof
