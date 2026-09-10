/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Alg

namespace Tests.Alg
open Jose

/--
Every algorithm this library names is read back from the name it writes. The two directions are
written out as separate tables, so a name mistyped in one of them would be a name no policy could
ever match, or worse, one that read back as a different algorithm.

`Alg.name` is the `alg` value RFC 7518 §3.1 registers and `Alg.ofString` is the parser a header goes
through. The equation quantifies over `Alg`, so the case analysis is the whole of the enumeration
and no constructor is exempt.
-/
theorem ofString_name (alg : Alg) : Alg.ofString alg.name = some alg := by
  cases alg <;> rfl

/--
The curves are likewise read back from the names they write, and each ECDSA algorithm names the one
curve RFC 7518 §3.4 pairs it with. This is what makes a coordinate width a property of the token
rather than a choice: the algorithm fixes the curve, and the curve fixes the width.

The first conjunct is the round trip over the enumeration of curves. The second reads the pairing
back: `Alg.curve` of each `ES` algorithm is the curve whose name the JWK must carry, and the widths
are the ones RFC 7518 gives, 66 rather than 64 for P-521.
-/
theorem curves_pair_with_algorithms :
    (∀ crv : Crv, Crv.ofString crv.name = some crv)
      ∧ Alg.curve .es256 = some .p256 ∧ Alg.curve .es384 = some .p384
      ∧ Alg.curve .es512 = some .p521
      ∧ Crv.coordinateSize .p256 = 32 ∧ Crv.coordinateSize .p384 = 48
      ∧ Crv.coordinateSize .p521 = 66 := by
  refine ⟨fun crv => by cases crv <;> rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/--
`none` is not an algorithm here. RFC 7515 §6 defines an unsecured JWS whose `alg` is the string
`none`, and a library that reads it as a value of its algorithm type has to remember to refuse it
everywhere; this one cannot represent it, so there is nowhere to forget.

The first conjunct is that string, refused. The rest are the near misses a lenient parser would
accept: another spelling of a real algorithm's case, one with the whitespace a JSON writer might
leave, and the empty string an absent member would decode to if it were read as text.
-/
theorem no_algorithm_named_none :
    Alg.ofString "none" = none ∧ Alg.ofString "None" = none ∧ Alg.ofString "hs256" = none
      ∧ Alg.ofString "HS256 " = none ∧ Alg.ofString "" = none := by
  refine ⟨rfl, rfl, rfl, rfl, rfl⟩

end Tests.Alg
