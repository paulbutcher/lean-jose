/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lean.Data.Json
open Lean

/-!
Writes `Tests/WycheproofVectors.lean` and `Tests/WycheproofKeyVectors.lean` from Project
Wycheproof's own JSON, so that the suite is regenerated rather than kept by hand.

Run it from the `test` directory with the checkout to read from:

    lake env lean --run tools/Wycheproof.lean path/to/wycheproof/testvectors_v1

It reads `Lean.Data.Json`, which the library itself does not: this is a program run by hand over a
trusted file, and it is elaborated by the frontend either way.

This is not part of any target. Nothing in the suite imports it, and it is here so that the two
generated files can be made again when Wycheproof publishes a new version.
-/

def q : String := "\""

def lines (ls : List String) : String := String.intercalate "\n" ls

def escapeChar (c : Char) : List Char :=
  if c == '"' then ['\\', '"'] else if c == '\\' then ['\\', '\\'] else [c]

def escape (s : String) : String := String.ofList (s.toList.flatMap escapeChar)

/-- Splits at the width the escaped text occupies rather than the width of the text, since a quote
takes two columns once it is written into a Lean literal, and never inside an escape. -/
def chunk (width : Nat) : Nat → List Char → List Char → Nat → List String
  | 0, _, current, _ => [String.ofList current.reverse]
  | _ + 1, [], current, _ => [String.ofList current.reverse]
  | fuel + 1, c :: rest, current, taken =>
    let written := escapeChar c
    if taken + written.length > width then
      String.ofList current.reverse :: chunk width fuel rest written.reverse written.length
    else
      chunk width fuel rest (written.reverse ++ current) (taken + written.length)

/-- A Lean expression for a string, split so that no emitted line runs long. The width leaves room
for the widest indent a value is written at, the quotes, and the operator that joins the pieces. -/
def literal (indent : String) (s : String) : String :=
  if s.isEmpty then q ++ q
  else
    let pieces := chunk 80 (s.length + 1) s.toList [] 0
    String.intercalate (" ++\n" ++ indent) (pieces.map fun p => q ++ p ++ q)

def preamble (namespace_ : String) (documentation : List String) (fields : List String) : String :=
  lines
    ([ "/-",
       "Copyright (c) 2026 Paul Butcher. All rights reserved.",
       "Released under Apache 2.0 license as described in the file LICENSE.",
       "-/",
       "module",
       "",
       "/-!" ] ++ documentation ++
     [ "-/",
       "",
       "public section",
       "",
       "namespace " ++ namespace_,
       "",
       "structure Case where",
       "  id : Nat",
       "  valid : Bool",
       "  jws : String",
       "",
       "structure Group where" ] ++ fields ++
     [ "  cases : List Case",
       "",
       "def groups : List Group := [" ])

def caseLiteral (id : Nat) (valid : Bool) (jws : String) : String :=
  "      { id := " ++ toString id ++ ", valid := " ++ toString valid ++
    ", jws :=\n          " ++ literal "            " jws ++ " }"

def field (value : Json) (name : String) : String :=
  (value.getObjValAs? String name).toOption.getD "?"

def tests (group : Json) : Array Json := (group.getObjValAs? (Array Json) "tests").toOption.getD #[]

def keyOf (group : Json) : Json :=
  (group.getObjVal? "public").toOption.getD ((group.getObjVal? "private").toOption.getD Json.null)

/-- Algorithms no backend in this package performs. Their groups are left out rather than expected
to fail, since every case in them would be refused for the algorithm rather than for what it was
written to test. -/
def unsupported : String → Bool
  | "ES256" | "ES384" | "ES512" | "ES521" | "EdDSA" => true
  | _ => false

/-- Signature cases whose stated result contradicts the token printed beside it. -/
def contradictory : List Nat := [367, 370, 372, 373]

/-- Signature cases the suite decides against its own other groups. -/
def disagreements : List Nat := [346, 350]

/-- The key case that asks for a ROCA-vulnerable modulus to be recognised. -/
def excludedKeys : List Nat := [7]

def signatures (json : Json) : String := Id.run do
  let mut emitted : Array String := #[]
  let mut kept := 0
  let mut skipped : Array String := #[]
  for group in (json.getObjValAs? (Array Json) "testGroups").toOption.getD #[] do
    let comment := field group "comment"
    let key := keyOf group
    let alg := field key "alg"
    if unsupported alg then
      skipped := skipped.push ("  " ++ comment ++ " (" ++ alg ++ ")")
    else
      let mut cases : Array String := #[]
      for test in tests group do
        let id := (test.getObjValAs? Nat "tcId").toOption.getD 0
        if contradictory.contains id || disagreements.contains id then continue
        cases := cases.push (caseLiteral id (field test "result" == "valid") (field test "jws"))
        kept := kept + 1
      emitted := emitted.push ("  { comment := " ++ q ++ comment ++ q ++ ", alg := " ++
        q ++ alg ++ q ++ ",\n    key := " ++ literal "      " key.compress ++
        ",\n    cases := [\n" ++ String.intercalate ",\n" cases.toList ++ "] }")
  preamble "Tests.Wycheproof"
    ([ "Project Wycheproof's JSON Web Signature vectors, from `json_web_signature_test.json`",
       "in `testvectors_v1`. Generated from that file rather than transcribed;",
       "`Tests.Wycheproof` runs them.",
       "",
       toString kept ++ " of the suite's cases are here. The rest are its groups for algorithms",
       "this backend cannot perform, every one of which would be refused for that reason",
       "rather than for the reason the case was written to test:" ] ++ skipped.toList ++
     [ "",
       "Four more are left out because no library can meet their stated results at once.",
       "372's token is 367's with one character inserted into the header, and the two carry",
       "the same tag; anything that accepts 372 has to ignore that character and check that",
       "tag over the bytes that remain, which are 367's, so it accepts 367 as well. 367 is",
       "marked invalid and 372 valid. 370 and 373 are the same pair with the character in",
       "the payload instead. The tag all four carry is the HMAC of 367's signing input under",
       "the group's key, which OpenSSL confirms, so the token 367 and 370 print is the",
       "group's untampered one and is sound. This library accepts 367 and 370 and refuses",
       "372 and 373.",
       "",
       "Two more, 346 and 350, are left out because the key they are checked against carries",
       "an `alg` that RFC 7520 does not put on it. That RFC gives the key in §3.4 with",
       "`kty`, `kid`, `use` and its components and no algorithm at all; the copy here adds",
       "PS256, while the token is the PS384 of §4.2. The added label is generated rather",
       "than published, as the group beside it shows by declaring `ES521`, which is not an",
       "algorithm any RFC names. This library uses a key only for the algorithm it declares,",
       "which is what RFC 7517 §4.4 says that member is for and what the `ps512` group of",
       "this same suite requires. `Tests.Verify` checks that same token against the key as",
       "RFC 7520 publishes it, where it verifies, and against one declaring PS256, where it",
       "does not." ])
    [ "  comment : String", "  alg : String", "  key : String" ] ++ "\n" ++
    String.intercalate ",\n" emitted.toList ++ "]\n\nend Tests.Wycheproof\n"

def keys (json : Json) : String := Id.run do
  let mut emitted : Array String := #[]
  let mut kept := 0
  for group in (json.getObjValAs? (Array Json) "testGroups").toOption.getD #[] do
    let mut cases : Array String := #[]
    for test in tests group do
      let id := (test.getObjValAs? Nat "tcId").toOption.getD 0
      if excludedKeys.contains id then continue
      cases := cases.push (caseLiteral id (field test "result" == "valid") (field test "jws"))
      kept := kept + 1
    if !cases.isEmpty then
      emitted := emitted.push ("  { comment := " ++ q ++ field group "comment" ++ q ++
        ",\n    keys := " ++ literal "      " (keyOf group).compress ++
        ",\n    cases := [\n" ++ String.intercalate ",\n" cases.toList ++ "] }")
  preamble "Tests.WycheproofKeys"
    [ "Project Wycheproof's JSON Web Key vectors, from `json_web_key_test.json` in",
      "`testvectors_v1`. Generated from that file rather than transcribed;",
      "`Tests.WycheproofKeys` runs them. Each case is a key set and a token, and what it",
      "says is whether the set should be read and the token accepted.",
      "",
      toString kept ++ " of the suite's 26 cases are here. The one left out is 7, which asks",
      "for a modulus with the ROCA weakness to be refused; recognising one is a fingerprint",
      "test on the key rather than anything JOSE defines, and belongs wherever keys are",
      "admitted." ]
    [ "  comment : String", "  keys : String" ] ++ "\n" ++
    String.intercalate ",\n" emitted.toList ++ "]\n\nend Tests.WycheproofKeys\n"

def main (args : List String) : IO UInt32 := do
  match args with
  | [directory] =>
    let read (name : String) : IO Json := do
      IO.ofExcept (Json.parse (← IO.FS.readFile (System.FilePath.mk directory / name)))
    IO.FS.writeFile "Tests/WycheproofVectors.lean"
      (signatures (← read "json_web_signature_test.json"))
    IO.FS.writeFile "Tests/WycheproofKeyVectors.lean"
      (keys (← read "json_web_key_test.json"))
    IO.println "wrote Tests/WycheproofVectors.lean and Tests/WycheproofKeyVectors.lean"
    return 0
  | _ =>
    IO.eprintln "usage: lake env lean --run tools/Wycheproof.lean <testvectors_v1 directory>"
    return 1
