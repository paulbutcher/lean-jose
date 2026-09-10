/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Error
public import Json

/-!
The frontier with untrusted input: the limits a parser is given, the errors its refusals become, and
the accessors the rest of the library reads values through. Nothing outside this module names the
JSON library, so replacing it is a change here and nowhere else.
-/

@[expose] public section

namespace Jose

/-- The two bounds RFC 7515 gives no help with, both of which a hostile sender chooses. The
defaults hold every token a real issuer produces: 8192 bytes is the header size a common proxy
allows, and a JOSE header or a claims set nests two or three deep, never sixteen. -/
structure Limits where
  maxTokenBytes : Nat := 8192
  maxJsonDepth : Nat := 16
  deriving Repr, DecidableEq

namespace Read

abbrev Value := _root_.Json

/-- Reading is strict, and the strictness that matters here is the default: a member name written
twice is refused rather than resolved, since two readers resolving it differently disagree about
what the signature covered. The depth is this library's, not the parser's, and it is policy rather
than protection: nesting costs the parser heap and never stack. -/
def config (limits : Limits) : _root_.Json.Config :=
  { maxDepth := some limits.maxJsonDepth }

/-- The parser's own error carries the offset it stopped at and, for a name written twice, the name.
The rest of it is discarded rather than carried into the error, since it quotes the text it failed
on and that text may be a payload.

Bytes that are not UTF-8 are refused as not being JSON, which is what they are: JSON is UTF-8, and
the base64url around them decoded cleanly. -/
def refusal (limits : Limits) (part : Source) (reason : _root_.Json.Error) : Error :=
  match reason.kind with
  | .depthExceeded => .jsonTooDeep limits.maxJsonDepth
  | .duplicateKey name => .duplicateMember part name
  | _ => .badJson part

/-- Text arrives here as the bytes a part decoded to, and it is the parser that decides whether they
are UTF-8, so nothing above this needs an opinion about encoding. -/
def parse (limits : Limits) (part : Source) (bytes : ByteArray) : Except Error Value :=
  match _root_.Json.parseBytes bytes (config limits) with
  | .ok value => .ok value
  | .error reason => .error (refusal limits part reason)

def parseObject (limits : Limits) (part : Source) (bytes : ByteArray) : Except Error Value := do
  match ← parse limits part bytes with
  | .obj members => .ok (.obj members)
  | _ => .error (.notAnObject part)

/-- A parse refuses a name written twice, so there is at most one member to find. -/
def member? (value : Value) (name : String) : Option Value :=
  match value with
  | .obj members => (members.find? (fun member => member.1 == name)).map Prod.snd
  | _ => none

def asString? : Value → Option String
  | .str s => some s
  | _ => none

def asStringArray? : Value → Option (Array String)
  | .arr items => items.mapM asString?
  | _ => none

/-- RFC 7519 §4.1.3 writes a single audience as a string and several as an array, and a verifier
has to take either. -/
def asStringOrArray? (value : Value) : Option (Array String) :=
  match value with
  | .str s => some #[s]
  | .arr _ => asStringArray? value
  | _ => none

/-- A `NumericDate`, which RFC 7519 §2 allows to carry a fraction. The whole second at or below the
value is taken, so a fractional expiry expires no later than it says.

A number is held as a mantissa and an exponent that is never evaluated, which is what makes
`1e1000000000` cost nothing to parse; evaluating one here would undo that, so an exponent past the
range of any clock is refused rather than raised. -/
def asSeconds? : Value → Option Int
  | .num n =>
    if n.exponent > 20 then none
    else if n.exponent ≥ 0 then some (n.mantissa * 10 ^ n.exponent.toNat)
    else some (Int.fdiv n.mantissa (10 ^ (-n.exponent).toNat))
  | _ => none

def stringMember? (value : Value) (name : String) : Option String :=
  member? value name >>= asString?

end Read

end Jose
