/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Pure

/-!
The claims of RFC 7519, decoded and checked. Validation takes the instant to compare against as an
argument and reads no clock, so a test can put a token at either side of its own expiry; the wrapper
that reads `Std.Time.Timestamp.now` is the only thing here that touches one.
-/

public section

namespace Jose

/-- The seven claims RFC 7519 §4.1 registers, with the object they were read from kept beside them
so that a caller can read a claim this library does not name without parsing the payload twice.

`aud` is `none` when absent and never an empty array standing in for it, because those are the
difference between a token addressed to nobody and one addressed to everybody. -/
structure Claims where
  issuer : Option String
  subject : Option String
  audience : Option (Array String)
  expiry : Option Int
  notBefore : Option Int
  issuedAt : Option Int
  id : Option String
  value : Read.Value

namespace Jwt

private def stringClaim (value : Read.Value) (name : String) : Except Error (Option String) :=
  match Read.member? value name with
  | none => .ok none
  | some member =>
    match Read.asString? member with
    | none => .error (.claimMalformed name)
    | some text => .ok (some text)

private def secondsClaim (value : Read.Value) (name : String) : Except Error (Option Int) :=
  match Read.member? value name with
  | none => .ok none
  | some member =>
    match Read.asSeconds? member with
    | none => .error (.claimMalformed name)
    | some seconds => .ok (some seconds)

private def audienceClaim (value : Read.Value) : Except Error (Option (Array String)) :=
  match Read.member? value "aud" with
  | none => .ok none
  | some member =>
    match Read.asStringOrArray? member with
    | none => .error (.claimMalformed "aud")
    | some audience => .ok (some audience)

/-- The claims of a payload that has already been verified. A member of the wrong type is an error
rather than an absence: a token whose `exp` is the string `"0"` is not a token without an expiry. -/
def decode (limits : Limits) (payload : ByteArray) : Except Error Claims := do
  let value ← Read.parseObject limits .payload payload
  .ok {
    issuer := ← stringClaim value "iss",
    subject := ← stringClaim value "sub",
    audience := ← audienceClaim value,
    expiry := ← secondsClaim value "exp",
    notBefore := ← secondsClaim value "nbf",
    issuedAt := ← secondsClaim value "iat",
    id := ← stringClaim value "jti",
    value := value }

/-- The claims checked against the policy, at an instant the caller supplies.

RFC 7519 §4.1.4 requires the current time to be strictly before `exp`, so a token whose expiry is
the instant compared against has expired; §4.1.5 requires it to be at or after `nbf`, so a token
whose `nbf` is that instant is valid. The leeway widens each of those by the same amount and does
not change which side of the boundary the instant itself falls on.

`exp` is required. Every use this library is for issues tokens that expire, and a JWT that never
does is one a caller has to decide about rather than one this can quietly accept. -/
def validate (policy : Policy) (now : Std.Time.Timestamp) (claims : Claims) :
    Except Error Unit := do
  let instant := now.toSecondsSinceUnixEpoch.toInt
  let leeway := policy.leeway.toInt
  match claims.issuer with
  | none => .error (.claimMissing "iss")
  | some issuer =>
    if issuer == policy.issuer then .ok () else .error (.wrongIssuer policy.issuer issuer)
  match claims.audience with
  | none => .error (.claimMissing "aud")
  | some audience =>
    if audience.any (policy.audience.contains ·) then .ok ()
    else .error (.wrongAudience policy.audience audience)
  match claims.expiry with
  | none => .error (.claimMissing "exp")
  | some expiry =>
    if instant < expiry + leeway then .ok () else .error (.expired expiry instant)
  match claims.notBefore with
  | none => .ok ()
  | some notBefore =>
    if instant + leeway ≥ notBefore then .ok () else .error (.notYetValid notBefore instant)

def check (policy : Policy) (now : Std.Time.Timestamp) (payload : ByteArray)
    (limits : Limits := {}) : Except Error Claims := do
  let claims ← decode limits payload
  validate policy now claims
  .ok claims

/-- A token verified and its claims checked, through any backend. -/
def verify (backend : Backend) (policy : Policy) (keys : KeySet backend) (token : String)
    (now : Std.Time.Timestamp) (limits : Limits := {}) : IO (Except Error Claims) := do
  match ← Jws.verify backend policy keys token limits with
  | .error reason => return .error reason
  | .ok payload => return check policy now payload limits

/-- The same, against the clock. This is the only place in the library that reads one. -/
def verifyNow (backend : Backend) (policy : Policy) (keys : KeySet backend) (token : String)
    (limits : Limits := {}) : IO (Except Error Claims) := do
  verify backend policy keys token (← Std.Time.Timestamp.now) limits

end Jwt

/-- A token verified and its claims checked, with no `IO` anywhere: the instant is the caller's, and
so is the decision about where it came from. -/
def Pure.jwt (policy : Policy) (keys : KeySet Backend.pure) (token : String)
    (now : Std.Time.Timestamp) (limits : Limits := {}) : Except Error Claims := do
  Jwt.check policy now (← Pure.verify policy keys token limits) limits

end Jose
