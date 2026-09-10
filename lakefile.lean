/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lake
open Lake DSL

require leancrypto from git "https://github.com/paulbutcher/leancrypto" @ "v0.4.1"

require json from git "https://github.com/paulbutcher/lean-json" @ "v0.3.0"

package jose where
  version := v!"0.1.1"
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

@[default_target]
lean_lib Jose

/-- The suite is a package of its own, so that nothing it requires reaches a consumer of this one.
The environment entries are cleared because Lake exports them to a child process, and a nested
`lake` that inherits them builds the outer package's module tree instead of the suite's. -/
@[test_driver]
script tests (args) do
  let lake ← IO.appPath
  let suite ← IO.Process.spawn {
    cmd := lake.toString
    args := #["test"] ++ args.toArray
    cwd := some "test"
    env := #[("LEAN_PATH", none), ("LEAN_SRC_PATH", none), ("LAKE", none), ("LAKE_HOME", none),
      ("LAKE_PKG_URL_MAP", none), ("ELAN_TOOLCHAIN", none)]
  }
  suite.wait
