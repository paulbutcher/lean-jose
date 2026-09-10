/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Read

/-!
The limits handed to the parser, the errors its refusals are turned into, and the accessors read
through afterwards. What is established here is this library's side of that frontier: that a limit
reaches the parser, that each way it can refuse arrives as an error naming the part the text came
from, and that a member found under a name is the member any reader would find there.
-/

namespace Tests.Read
open Jose Jose.Read

/--
A fold looking for one name passes over members that do not carry it. This is the step that makes
the last member of a name the only one a last-wins reader can return, and it is stated for an
arbitrary accumulator because that reader carries its answer forward from the left.

`l` is a list of members and `k` the name looked for; the hypothesis says no member of `l` is named
`k`, and the fold is the one `Json.findLast?` performs, replacing its accumulator whenever a name
matches. The conclusion is that the accumulator survives, so a match already found is not lost and
an absence is not filled in.
-/
private theorem foldl_keeps (k : String) (acc : Option Value) :
    ∀ l : List (String × Value), (∀ member ∈ l, member.1 ≠ k) →
      l.foldl (fun found member => if member.1 == k then some member.2 else found) acc = acc
  | [], _ => rfl
  | member :: rest, h => by
    have hb : (member.1 == k) = false := beq_eq_false_iff_ne.mpr (h member (by simp))
    simp only [List.foldl_cons, hb, Bool.false_eq_true, if_false]
    exact foldl_keeps k acc rest fun other hother => h other (by simp [hother])

/--
Where the names of a list of members are distinct, taking the first of a name and taking the last
give the same answer. This is the arithmetic of the guarantee below, separated from the parser so
that what the parser contributes is exactly the distinctness.

The hypothesis is `Nodup` of the names, which is what `distinctNames` amounts to. The left side is
the first member whose name is `k`, with its value taken; the right side is the fold
`Json.findLast?` performs, which keeps the last such member. Both are `Option`, so the equation also
covers the case where no member carries the name and neither side finds one.
-/
private theorem find?_eq_foldl (k : String) :
    ∀ l : List (String × Value), (l.map Prod.fst).Nodup →
      (l.find? (fun member => member.1 == k)).map Prod.snd
        = l.foldl (fun found member => if member.1 == k then some member.2 else found) none
  | [], _ => rfl
  | member :: rest, h => by
    simp only [List.map_cons, List.nodup_cons] at h
    cases hb : member.1 == k with
    | true =>
      have hmember : member.1 = k := by simpa using hb
      have hrest : ∀ other ∈ rest, other.1 ≠ k := by
        intro other hother hname
        exact h.1 (List.mem_map.mpr ⟨other, hother, by rw [hname, hmember]⟩)
      simp only [List.find?_cons, List.foldl_cons, hb, if_true]
      exact (foldl_keeps k (some member.2) rest hrest).symm
    | false =>
      simp only [List.find?_cons, List.foldl_cons, hb, Bool.false_eq_true, if_false]
      exact find?_eq_foldl k rest h.2

/--
A value this library accepted names no member twice, so the member it reads under a name is the one
any other reader would read there too. Nothing else in this library needs saying about the parser:
a token is signed over bytes rather than over a value, so two readers that resolve a repeated name
differently disagree about what was signed, and this says there is nothing left to disagree about.

`Read.parse limits part bytes = .ok value` is the parse having succeeded under this library's
configuration, which refuses a repeated name. That refusal is `lean-json`'s
`Json.Parser.uniqueKeys_parse`, whose hypothesis the configuration meets by `rfl`, and
`Json.distinctNames_iff` reads its conclusion as one object's names being distinct; the rest is the
two lemmas above. `Read.member?` takes the first member of a name and
`Json.getObjVal?` takes the last, ECMA-262's rule and the mainstream one; the equation says they
coincide, at every name rather than at the ones this library happens to read. `Except.toOption` is
there because the two report an absence differently, and both are `none` at a value that is not an
object, so no shape of value is exempt.
-/
theorem member?_eq_getObjVal? {limits : Limits} {part : Source} {bytes : ByteArray}
    {value : Value} (h : Read.parse limits part bytes = .ok value) (name : String) :
    Read.member? value name = (_root_.Json.getObjVal? value name).toOption := by
  have hunique : _root_.Json.UniqueKeys value := by
    unfold Read.parse at h
    split at h
    · rename_i parsed hparsed
      rw [show parsed = value by injection h] at hparsed
      unfold _root_.Json.parseBytes _root_.Json.Parser.parseBytes at hparsed
      split at hparsed
      · exact _root_.Json.Parser.uniqueKeys_parse rfl hparsed
      · exact absurd hparsed (by simp)
    · exact absurd h (by simp)
  match value with
  | .null | .bool _ | .num _ | .str _ | .arr _ => rfl
  | .obj fields =>
    have hnodup : (_root_.Json.fieldNames fields).Nodup := by
      rw [_root_.Json.UniqueKeys, _root_.Json.uniqueKeys, Bool.and_eq_true] at hunique
      exact (_root_.Json.distinctNames_iff fields).mp hunique.1
    show (fields.find? (fun member => member.1 == name)).map Prod.snd
      = (_root_.Json.getObjVal? (.obj fields) name).toOption
    rw [_root_.Json.getObjVal?, _root_.Json.findLast?, ← Array.find?_toList,
      ← Array.foldl_toList, find?_eq_foldl name fields.toList hnodup]
    cases fields.toList.foldl
      (fun found member => if member.1 == name then some member.2 else found) none <;> rfl

private def nested (depth : Nat) : String :=
  String.ofList (List.replicate depth '[') ++ "1" ++ String.ofList (List.replicate depth ']')

private def refuses (limits : Limits) (part : Source) (text : String) (expected : Error) : Bool :=
  match Read.parse limits part text.toUTF8 with
  | .error actual => actual == expected
  | .ok _ => false

private def accepts (limits : Limits) (text : String) : Bool :=
  (Read.parse limits .payload text.toUTF8).isOk

private def header (text : String) : Except Error Value := Read.parseObject {} .header text.toUTF8

private def refusesHeader (text : String) (expected : Error) : Bool :=
  match header text with
  | .error actual => actual == expected
  | .ok _ => false

private def audience (text : String) : Option (Array String) :=
  (Read.parse {} .payload text.toUTF8).toOption
    >>= (Read.member? · "aud") >>= Read.asStringOrArray?

private def seconds (text : String) : Option Int :=
  (Read.parse {} .payload text.toUTF8).toOption >>= (Read.member? · "exp") >>= Read.asSeconds?

public def checks : List (String × Bool) :=
  [ ("nesting at the limit is accepted and one deeper is refused",
      accepts { maxJsonDepth := 4 } (nested 4)
        && refuses { maxJsonDepth := 4 } .payload (nested 5) (.jsonTooDeep 4)),
    ("a header naming a member twice is refused, and the error names the member",
      refusesHeader "{\"alg\":\"HS256\",\"alg\":\"none\"}" (.duplicateMember .header "alg")),
    ("a member named twice anywhere is refused, and the error names where it was read",
      refuses {} .payload "{\"iss\":\"joe\",\"iss\":\"eve\"}" (.duplicateMember .payload "iss")
        && refuses {} .keySet "{\"keys\":[{\"kty\":\"oct\",\"kty\":\"RSA\"}]}"
          (.duplicateMember .keySet "kty")),
    ("a member name repeated in a nested object is not a duplicate at the top",
      (header "{\"alg\":\"HS256\",\"jwk\":{\"alg\":\"RS256\"}}").isOk),
    ("a value equal to a member name is not a duplicate",
      (header "{\"alg\":\"HS256\",\"kid\":\"alg\"}").isOk),
    ("a name written twice in two spellings is written twice",
      refusesHeader "{\"alg\":\"HS256\",\"\\u0061lg\":\"none\"}" (.duplicateMember .header "alg")),
    ("an escaped member name is the name it denotes",
      (header "{\"\\u0061lg\":\"HS256\"}").toOption
        >>= (Read.stringMember? · "alg") == some "HS256"),
    ("a header that is not an object is refused",
      refusesHeader "[\"HS256\"]" (.notAnObject .header)),
    ("text that is not JSON is refused as the part it came from",
      refuses {} .payload "{\"a\":" (.badJson .payload)
        && refuses {} .header "" (.badJson .header)),
    ("an audience is read whether it is a string or an array",
      audience "{\"aud\":\"one\"}" == some #["one"]
        && audience "{\"aud\":[\"one\",\"two\"]}" == some #["one", "two"]
        && audience "{\"aud\":[\"one\",2]}" == none
        && audience "{\"aud\":2}" == none),
    ("a NumericDate is the whole second at or below the value",
      seconds "{\"exp\":1300819380}" == some 1300819380
        && seconds "{\"exp\":1.30081938e9}" == some 1300819380
        && seconds "{\"exp\":1300819380.7}" == some 1300819380
        && seconds "{\"exp\":\"1300819380\"}" == none),
    ("an expiry no clock could name is refused rather than worked out",
      seconds "{\"exp\":1e1000000000}" == none) ]

end Tests.Read
