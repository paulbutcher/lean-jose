/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lake
open Lake DSL

package wycheproof where
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

/-- The vectors are data and nothing else, so this package requires nothing and any suite in any
repository can take it, by path or by git subdirectory, without taking a backend with it. -/
@[default_target]
lean_lib Wycheproof
