/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Compact

/-!
The compact serialization: that the parser takes a token apart the way the signing input puts it
back together, and the RFC 7515 A.1 token, accepted and then refused once for each way of breaking
its shape.
-/

namespace Tests.Compact
open Jose Jose.Compact

/-- The separators `splitDots` consumed, put back. This is the inverse the theorem below is stated
against, and it exists only to say what the parser's output means. -/
def dotJoin : List (List Char) → List Char
  | [] => []
  | segment :: rest => '.' :: (segment ++ dotJoin rest)

/--
Splitting a list of characters on the separator loses nothing: the first segment, followed by every
later segment with the separator it was taken from restored, is the input. This is what makes the
signing input safe to rebuild from the parsed parts rather than carried alongside them.

`(splitDots cs).1` is the text before the first separator and `(splitDots cs).2` is every segment
after it; `dotJoin` writes one separator in front of each of those, which is exactly the separator
`splitDots` dropped. The equation is over every list, so no shape of input is exempt: no separators,
only separators, and empty segments at either end all fall under it.
-/
theorem splitDots_join (cs : List Char) : (splitDots cs).1 ++ dotJoin (splitDots cs).2 = cs := by
  induction cs using Jose.Compact.splitDots.induct with
  | case1 => rfl
  | case2 rest first others heq ih =>
    rw [heq] at ih
    simp [splitDots, heq, dotJoin, ih]
  | case3 c rest hc first others heq ih =>
    rw [heq] at ih
    simp [splitDots, heq, ih]

/--
No segment the parser produces contains a separator. Without this the theorem below would still
hold of a parser that put the whole token in the header and nothing anywhere else, so this is what
makes the decomposition the only one: the header ends at the first separator and the payload at the
second.

The conjunction covers the two places a segment can appear: `.1`, the text before the first
separator, and every member of `.2`, the segments after it. `∉` is over the characters of the
segment, so it says the separator survives nowhere inside one.
-/
theorem splitDots_dotFree (cs : List Char) :
    '.' ∉ (splitDots cs).1 ∧ ∀ segment ∈ (splitDots cs).2, '.' ∉ segment := by
  induction cs using Jose.Compact.splitDots.induct with
  | case1 => simp [splitDots]
  | case2 rest first others heq ih =>
    rw [heq] at ih
    simp [splitDots, heq]
    exact ⟨ih.1, ih.2⟩
  | case3 c rest hc first others heq ih =>
    rw [heq] at ih
    simp [splitDots, heq]
    exact ⟨⟨fun h => hc h.symm, ih.1⟩, ih.2⟩

/--
A token the parser accepts is exactly its signing input, a separator, and its signature. This is
the property RFC 7515 §5.2 rests on: the bytes whose signature is checked are bytes of the token as
it arrived, so a verifier cannot be made to check a signature over anything it did not receive.

`Compact.parse limits token = .ok parts` is the parser having accepted, and `parts.signingInput` is
`parts.header ++ "." ++ parts.payload`, the value handed to the backend. The equation says appending
the remaining separator and `parts.signature` recovers `token` character for character, so the
signing input is a prefix of the token; with `splitDots_dotFree`, which puts no separator inside
either part, it is the prefix that ends at the second separator and no other.
-/
theorem signingInput_token (limits : Limits) (token : String) (parts : Parts)
    (h : Compact.parse limits token = .ok parts) :
    parts.signingInput ++ "." ++ parts.signature = token := by
  unfold Compact.parse at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · exact absurd h (by simp)
    · split at h
      · rename_i header payload signature heq
        split at h
        · exact absurd h (by simp)
        · have hparts : parts = {
              header := String.ofList header,
              payload := String.ofList payload,
              signature := String.ofList signature } := by
            injection h with h; exact h.symm
          have hjoin := splitDots_join token.toList
          rw [heq] at hjoin
          simp [dotJoin] at hjoin
          apply String.toList_inj.mp
          simp [hparts, Parts.signingInput, hjoin]
      · exact absurd h (by simp)

-- RFC 7515 A.1, the HS256 example, whose three parts the appendix prints separately.
private def header : String := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"

private def payload : String :=
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

private def signature : String := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

private def token : String := header ++ "." ++ payload ++ "." ++ signature

private def accepts (token : String) (expected : Parts) : Bool :=
  match Compact.parse ({} : Limits) token with
  | .ok actual => actual == expected
  | .error _ => false

private def rejects (limits : Limits) (token : String) (expected : Error) : Bool :=
  match Compact.parse limits token with
  | .error actual => actual == expected
  | .ok _ => false

public def checks : List (String × Bool) :=
  [ ("the RFC 7515 A.1 token splits into the three parts the appendix prints",
      accepts token { header := header, payload := payload, signature := signature }),
    ("a fourth part is refused",
      rejects {} (token ++ "." ++ signature) (.wrongPartCount 4)),
    ("a token with only two parts is refused",
      rejects {} (header ++ "." ++ payload) (.wrongPartCount 2)),
    ("leading whitespace is refused",
      rejects {} (" " ++ token) .whitespaceInToken),
    ("trailing whitespace is refused",
      rejects {} (token ++ "\n") .whitespaceInToken),
    ("whitespace inside a part is refused",
      rejects {} (header ++ "." ++ payload ++ ".dBjftJeZ4CVP -mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        .whitespaceInToken),
    ("an empty signature part is refused",
      rejects {} (header ++ "." ++ payload ++ ".") .emptySignature),
    ("a token longer than the limit is refused before it is looked at",
      rejects { maxTokenBytes := 32 } token (.tokenTooLong token.utf8ByteSize 32)) ]

end Tests.Compact
