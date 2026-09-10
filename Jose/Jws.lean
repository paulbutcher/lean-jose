/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Backend
public import Jose.Compact
public import Std.Time

public section

namespace Jose

/-- What a token is checked against. The algorithms are the caller's, never the token's: the `alg`
in a header is compared with `algs` and refused if it is absent from it, and it selects nothing.

`algs` and `audience` cannot be empty. The proofs are discharged by `decide` for the literals a
policy is usually written from, so an empty one does not compile; `Policy.mk?` is for the case where
they are only known at run time. An empty audience that meant "accept anything" is how a library
stops checking without anyone noticing. -/
structure Policy where
  algs : Array Alg
  issuer : String
  audience : Array String
  typ : Option String := none
  leeway : Std.Time.Second.Offset := 0
  algsNonEmpty : algs.size > 0 := by decide
  audienceNonEmpty : audience.size > 0 := by decide

def Policy.mk? (algs : Array Alg) (issuer : String) (audience : Array String)
    (typ : Option String := none) (leeway : Std.Time.Second.Offset := 0) : Option Policy :=
  if halgs : algs.size > 0 then
    if haudience : audience.size > 0 then
      some {
        algs := algs, issuer := issuer, audience := audience, typ := typ, leeway := leeway,
        algsNonEmpty := halgs, audienceNonEmpty := haudience }
    else none
  else none

namespace Jws

/-- The header parameters RFC 7515 §4.1 and RFC 7518 register. RFC 7515 §4.1.11 forbids `crit` from
naming one of these, because a receiver already knows them and the sender learns nothing by
insisting. `b64` is absent on purpose: RFC 7797 defines it elsewhere, so a `crit` naming it is
well formed and simply asks for something this library does not implement. -/
def registeredHeaders : Array String :=
  #["alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"]

/-- What survives the checks that do not need a key: the parts as they arrived, the algorithm the
policy admitted, the `kid` to look up, and the signature. The payload is not here, because it is not
decoded until a signature has been checked. -/
structure Request where
  parts : Compact.Parts
  alg : Alg
  kid : Option String
  signature : ByteArray

/-- RFC 7515 §4.1.11: an extension every receiver must understand. This library implements none of
them, so any name is refused; what the name is decides which refusal, since a registered name is a
sender doing something forbidden while another name is a sender asking for something absent. -/
def checkCrit (header : Read.Value) : Except Error Unit := do
  match Read.member? header "crit" with
  | none => .ok ()
  | some member =>
    match Read.asStringArray? member with
    | none => .error (.headerBadMember "crit")
    | some names =>
      if names.isEmpty then .error .critEmpty
      else match names.find? (registeredHeaders.contains ·) with
        | some name => .error (.critRegistered name)
        | none => .error (.critUnsupported names[0]!)

/-- Media types are compared without regard to case, and RFC 7515 §4.1.9 lets a sender drop the
`application/` a media type would otherwise carry, so both spellings mean the same thing here. -/
def typMatches (expected actual : String) : Bool :=
  let normalise (value : String) :=
    let lowered := value.toLower
    if lowered.startsWith "application/" then (lowered.drop 12).toString else lowered
  normalise expected == normalise actual

/-- Everything that can be decided before a key is chosen, in the order that keeps the cheapest
refusals first and never looks at the payload.

The algorithm is read only to be compared against the policy. Nothing here dispatches on it, and
there is no path by which a token can choose what it is checked with. -/
def prepare (policy : Policy) (token : String) (limits : Limits := {}) : Except Error Request := do
  let parts ← Compact.parse limits token
  let header ← Read.parseObject limits .header (← Compact.decodePart .header parts.header)
  checkCrit header
  let alg ← match Read.stringMember? header "alg" with
    | none => .error .algMissing
    | some name =>
      match Alg.ofString name with
      | none => .error (.algUnknown name)
      | some alg => .ok alg
  if !policy.algs.contains alg then .error (.algRejected alg)
  match policy.typ with
  | none => .ok ()
  | some expected =>
    match Read.member? header "typ" with
    | none => .error (.wrongTyp expected none)
    | some member =>
      match Read.asString? member with
      | none => .error (.headerBadMember "typ")
      | some actual =>
        if typMatches expected actual then .ok () else .error (.wrongTyp expected (some actual))
  let kid ← match Read.member? header "kid" with
    | none => .ok none
    | some member =>
      match Read.asString? member with
      | none => .error (.headerBadMember "kid")
      | some kid => .ok (some kid)
  .ok {
    parts := parts,
    alg := alg,
    kid := kid,
    signature := ← Compact.decodePart .signature parts.signature }

/-- What a run of attempts against the selected keys amounts to. A backend that cannot perform the
algorithm is not a failed verification, so its reason is kept and returned in place of
`signatureInvalid`: a missing package and a forgery need different fixes, and a caller that saw the
same answer for both would look in the wrong place. -/
def outcome (verified : Bool) (reason : Option Error) (kid : Option String) (keys : Nat) :
    Except Error Unit :=
  if verified then .ok ()
  else match reason with
    | some reason => .error reason
    | none => if keys = 0 then .error (.noKeyMatched kid) else .error .signatureInvalid

/-- The payload, decoded only once a signature over it has been checked. Keeping this out of
`prepare` is what makes malformed-payload handling unreachable for an unverified token. -/
def payload (request : Request) : Except Error ByteArray :=
  Compact.decodePart .payload request.parts.payload

/-- A token, verified against a prepared key set, returning the payload it signed and nothing on any
other outcome.

Selection narrows to the algorithm the token names, which by this point has already been compared
against the policy and found in it. This is not the token choosing anything: it has no say in which
algorithms are acceptable, only in which of the acceptable ones it claims to have used, and the
narrowing is what holds a key to the `alg` RFC 7517 §4.4 says it is for. A key published for PS512
must not verify an RS256 signature, and would if the whole policy were used to select it.

The keys are tried in the order the set holds them, and the first that verifies ends it. -/
def verify (backend : Backend) (policy : Policy) (keys : KeySet backend) (token : String)
    (limits : Limits := {}) : IO (Except Error ByteArray) := do
  match prepare policy token limits with
  | .error reason => return .error reason
  | .ok request =>
    let selected := keys.select request.kid #[request.alg]
    let mut verified := false
    let mut reason : Option Error := none
    for prepared in selected do
      if !verified then
        match ← backend.verify request.alg prepared.key request.parts.signingInputBytes
            request.signature with
        | .error refusal => reason := reason.orElse fun _ => some refusal
        | .ok true => verified := true
        | .ok false => pure ()
    match outcome verified reason request.kid selected.size with
    | .error refusal => return .error refusal
    | .ok () => return payload request


/-- The signing input for a header and a payload that are about to be signed: each part base64url,
joined by the separator. Verification never uses this, because there the parts arrive already
encoded and re-encoding them is what puts a signature over bytes nobody sent. -/
def signingInput (header payload : String) : String :=
  Leancrypto.Codec.Base64Url.encodeString header.toUTF8 ++ "." ++
    Leancrypto.Codec.Base64Url.encodeString payload.toUTF8

/-- A signed token, through any backend. -/
def token (backend : Backend) (alg : Alg) (key : backend.PreparedKey) (header payload : String) :
    IO (Except Error String) := do
  let input := signingInput header payload
  match ← backend.sign alg key input.toUTF8 with
  | .error reason => return .error reason
  | .ok signature =>
    return .ok (input ++ "." ++ Leancrypto.Codec.Base64Url.encodeString signature)
end Jws
end Jose
