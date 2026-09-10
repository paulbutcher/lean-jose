/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Plausible

/-!
Running a property over generated values, where a theorem is out of reach.

The `plausible` tactic is not used, and cannot be: it reports its result as a warning, and this
build treats a warning as an error. What is used is the same library underneath it, which hands
back a result a runner can read.
-/

namespace Tests.Property
open Plausible Plausible.Decorations

/-- The seed is fixed, so that a property either fails for everyone or fails for nobody. A suite
that passes at one hour and fails at the next teaches its readers to run it again rather than to
read it, and a counter-example nobody else can reproduce is not evidence.

The values are drawn up to a size that covers the widest thing any property here quantifies over,
which is the pair of 66-byte coordinates of a P-521 signature. -/
def configuration : Configuration :=
  { numInst := 200, maxSize := 140, randomSeed := some 20260909, quiet := true }

/-- Whether a property survives every value drawn. Giving up counts as failing: it means the values
generated never met the property's preconditions, so nothing was tested and saying so is the only
honest answer. -/
public def holds (p : Prop) (p' : DecorationsOf p := by mk_decorations) [Testable p'] :
    IO Bool := do
  match ← Testable.checkIO p' configuration with
  | .success _ => return true
  | .gaveUp _ => return false
  | .failure _ _ _ => return false

end Tests.Property
