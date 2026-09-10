/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Alg

@[expose] public section

namespace Jose

/-- What a failure was reading, so that a decoding failure names it rather than an offset. -/
inductive Source where
  | header
  | payload
  | signature
  | keySet
  deriving Repr, DecidableEq

def Source.name : Source → String
  | .header => "header"
  | .payload => "payload"
  | .signature => "signature"
  | .keySet => "key set"

/-- One constructor per check, because the caller has to log which check refused the token and a
single `false` closes no investigation. Each carries the value that decided it where that value is
public: an algorithm, a `kid`, an expiry and the instant it was compared against. None carries key
material or signature bytes, and where a value does come from the token it is one the check itself
compared, or the name of the member at fault, never a claim this library does not read.

Times are seconds since the Unix epoch, as RFC 7519 §2 writes a `NumericDate`, rather than a
`Timestamp`, so that a log line reads as the token spells it. -/
inductive Error where
  | tokenTooLong (bytes limit : Nat)
  | wrongPartCount (parts : Nat)
  | whitespaceInToken
  | emptySignature
  | badBase64Url (part : Source)
  | badJson (part : Source)
  | notAnObject (part : Source)
  | jsonTooDeep (limit : Nat)
  | duplicateMember (part : Source) (name : String)
  | headerBadMember (name : String)
  | critEmpty
  | critRegistered (name : String)
  | critUnsupported (name : String)
  | algMissing
  | algUnknown (name : String)
  | algRejected (alg : Alg)
  | algUnsupported (alg : Alg) (backend : String)
  | jwkMissingMember (name : String)
  | jwkBadMember (name : String)
  | jwkUnknownKeyType (kty : String)
  | jwkUnknownCurve (crv : String)
  | jwkPrivateComponent (name : String)
  | jwkUse (use : String)
  | jwkKeyOps
  | jwkWrongCoordinateWidth (crv : Crv) (bytes : Nat)
  | duplicateKid (kid : String)
  | mixedKeySet
  | keyTooShort (bytes required : Nat)
  | keyKindMismatch (alg : Alg) (kind : KeyKind)
  | noKeyMatched (kid : Option String)
  | signatureInvalid
  | claimMissing (name : String)
  | claimMalformed (name : String)
  | expired (expiry compared : Int)
  | notYetValid (notBefore compared : Int)
  | wrongIssuer (expected actual : String)
  | wrongAudience (expected actual : Array String)
  | wrongTyp (expected : String) (actual : Option String)
  deriving Repr, DecidableEq

/-- The line to log. It names the check and the value that decided it; a caller wanting to branch
should match the constructor rather than read this. -/
def Error.message : Error → String
  | .tokenTooLong bytes limit => s!"token of {bytes} bytes exceeds the limit of {limit}"
  | .wrongPartCount parts => s!"compact form has {parts} parts, not 3"
  | .whitespaceInToken => "token contains whitespace"
  | .emptySignature => "signature part is empty"
  | .badBase64Url part => s!"{part.name} is not base64url"
  | .badJson part => s!"{part.name} is not JSON"
  | .notAnObject part => s!"{part.name} is not a JSON object"
  | .jsonTooDeep limit => s!"JSON nests deeper than the limit of {limit}"
  | .duplicateMember part name => s!"{part.name} names the member {name} more than once"
  | .headerBadMember name => s!"header member {name} is malformed"
  | .critEmpty => "crit is present and empty"
  | .critRegistered name => s!"crit names the registered header parameter {name}"
  | .critUnsupported name => s!"crit names {name}, which this library does not implement"
  | .algMissing => "header has no alg"
  | .algUnknown name => s!"alg {name} is not an algorithm this library names"
  | .algRejected alg => s!"alg {alg.name} is not in the policy"
  | .algUnsupported alg backend => s!"alg {alg.name} is not supported by the {backend} backend"
  | .jwkMissingMember name => s!"key has no {name}"
  | .jwkBadMember name => s!"key member {name} is malformed"
  | .jwkUnknownKeyType kty => s!"key type {kty} is not one this library reads"
  | .jwkUnknownCurve crv => s!"curve {crv} is not one this library reads"
  | .jwkPrivateComponent name => s!"key carries the private component {name}"
  | .jwkUse use => s!"key is published for use {use}, not sig"
  | .jwkKeyOps => "key operations do not include verify"
  | .jwkWrongCoordinateWidth crv bytes =>
      s!"coordinate of {bytes} bytes is not the {crv.coordinateSize} of {crv.name}"
  | .duplicateKid kid => s!"two keys in the set carry the kid {kid}"
  | .mixedKeySet => "key set holds both a symmetric key and an asymmetric one"
  | .keyTooShort bytes required =>
      s!"key of {bytes} bytes is shorter than the {required} this algorithm requires"
  | .keyKindMismatch alg kind => s!"alg {alg.name} does not take a {kind.name} key"
  | .noKeyMatched kid =>
      match kid with
      | some kid => s!"no key in the set has kid {kid}"
      | none => "no key in the set admits the policy's algorithms"
  | .signatureInvalid => "signature does not verify"
  | .claimMissing name => s!"claim {name} is absent"
  | .claimMalformed name => s!"claim {name} is malformed"
  | .expired expiry compared => s!"expired at {expiry}, compared against {compared}"
  | .notYetValid notBefore compared => s!"not valid before {notBefore}, compared against {compared}"
  | .wrongIssuer expected actual => s!"issuer is {actual}, not {expected}"
  | .wrongAudience expected actual => s!"audience {actual} meets none of {expected}"
  | .wrongTyp expected actual =>
      match actual with
      | some actual => s!"typ is {actual}, not {expected}"
      | none => s!"typ is absent, and {expected} was required"

instance : ToString Error := ⟨Error.message⟩

end Jose
