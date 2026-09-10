/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests

/-!
Much of the suite is theorems, which pass by compiling. What remains is here: the published vectors,
whose value is agreement with a constant no proof could establish, and the properties, which draw
their own values and so have to be run.
-/

public def main : IO UInt32 := do
  let checks := Tests.Compact.checks ++ Tests.Ecdsa.checks ++ Tests.Read.checks
    ++ Tests.Jwk.checks ++ Tests.Verify.checks ++ Tests.Jwt.checks ++ Tests.Sign.checks
    ++ Tests.Wycheproof.checks ++ Tests.WycheproofKeys.checks
  let properties := Tests.Ecdsa.properties
  let mut failed := (checks.filter fun (_, passed) => !passed).map Prod.fst
  for (name, property) in properties do
    if !(← property) then failed := failed ++ [name]
  for name in failed do
    IO.eprintln s!"FAILED: {name}"
  let total := checks.length + properties.length
  if failed.isEmpty then
    IO.println s!"{checks.length} checks and {properties.length} properties passed"
    return 0
  else
    IO.eprintln s!"{failed.length} of {total} failed"
    return 1
