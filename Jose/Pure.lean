/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Jws
public import Leancrypto.Compare
public import Leancrypto.Hmac
public import Leancrypto.Rsa
public import Leancrypto.Rsa.Pss

/-!
The backend this package ships: HMAC and both RSA schemes, in Lean, with no native code anywhere
beneath it. ECDSA and EdDSA are refused by name, because `leancrypto` has no elliptic curve
arithmetic; `jose-libcrypto` supplies them.

Everything here is pure. `Backend.pure` is this lifted into `IO` and not a second implementation, so
there is one set of rules about what verifies and no way for the two entry points to disagree.
-/

public section

namespace Jose
namespace Pure

open Leancrypto

def name : String := "pure"

/-- A key converted for this backend. `unusable` is not a failure: an EC key in an otherwise usable
set has to survive preparation so that a token naming ES256 reaches `verifySignature` and is refused
by algorithm. A key set that dropped it would refuse the same token for having no key, which is a
different fault with a different fix. -/
inductive Key where
  | oct (secret : ByteArray)
  | rsa (key : Rsa.PublicKey)
  | unusable (kind : KeyKind)

def Key.kind : Key → KeyKind
  | .oct _ => .oct
  | .rsa _ => .rsa
  | .unusable kind => kind

def prepare (jwk : Jwk) : Key :=
  match jwk.material with
  | .oct secret => .oct secret
  | .rsa modulus exponent => .rsa { modulus := modulus, exponent := exponent }
  | .ec _ _ _ => .unusable .ec
  | .okp _ _ => .unusable .okp

/-- The tag is compared with `bytesEqual`, which reads both operands to the end. Comparing with
`==` would stop at the first difference, and the position of that difference is a fact about the
expected tag that the time taken to answer would carry out of the process. -/
def mac (digest : Sha2) (secret signingInput tag : ByteArray) : Bool :=
  bytesEqual (hmac digest secret signingInput) tag

/-- RFC 7518 §3.2 requires an HMAC key at least as long as the digest, and HMAC accepts any length
without complaining, so this is the only thing that refuses a short one. A key shorter than its
digest is searched more cheaply than the tag it produces suggests, and an empty one is not a
secret at all. -/
def secretLongEnough (digest : Sha2) (secret : ByteArray) : Except Error Unit :=
  if secret.size ≥ digest.size then .ok ()
  else .error (.keyTooShort secret.size digest.size)

/-- One signature, checked. The three answers stay apart: a refusal because this backend cannot
perform the algorithm, a refusal because the key is the wrong kind for it, and `false`, which is the
signature not being over these bytes with this key.

The key kind is checked here as well as during selection. Selection is what keeps an RSA public key
from being tried as an HMAC secret in ordinary use; this is what keeps it true of a caller who
assembled a key set by hand. -/
def verifySignature (alg : Alg) (key : Key) (signingInput signature : ByteArray) :
    Except Error Bool :=
  match alg.scheme, key with
  | .hmac digest, .oct secret => do
    secretLongEnough digest secret
    .ok (mac digest secret signingInput signature)
  | .pkcs1 digest, .rsa key => .ok (Rsa.verifyPkcs1v15 digest key signingInput signature)
  | .pss digest saltLength, .rsa key =>
    .ok (Rsa.Pss.verify digest saltLength key signingInput signature)
  | .ecdsa _ _, _ | .eddsa _, _ => .error (.algUnsupported alg name)
  | _, key => .error (.keyKindMismatch alg key.kind)

/-- A tag over the signing input. Only the HMAC algorithms are here: signing with `rs*` or `ps*`
needs a private key, which this package does not read, and `es*` and `eddsa` need curve arithmetic
it does not have. The two refusals stay apart, so a caller offering an RSA key to `HS256` is told
that rather than that the algorithm is missing. -/
def signature (alg : Alg) (key : Key) (signingInput : ByteArray) : Except Error ByteArray :=
  match alg.scheme, key with
  | .hmac digest, .oct secret => do
    secretLongEnough digest secret
    .ok (hmac digest secret signingInput)
  | .hmac _, key => .error (.keyKindMismatch alg key.kind)
  | _, _ => .error (.algUnsupported alg name)

end Pure

/-- The pure backend, which is `Jose.Pure` lifted into `IO`. -/
def Backend.pure : Backend where
  PreparedKey := Pure.Key
  prepare jwk := return .ok (Pure.prepare jwk)
  verify alg key signingInput signature :=
    return Pure.verifySignature alg key signingInput signature
  sign alg key signingInput := return Pure.signature alg key signingInput

namespace Pure

/-- A key set prepared for this backend without touching `IO`, which is the same set
`Jws.verify Backend.pure` takes. -/
def keySet (set : Jwks) : KeySet Backend.pure :=
  { keys := set.keys.map fun key => { jwk := key, key := prepare key }, skipped := set.skipped }

/-- The whole of verification, pure: a token in, the payload it signed out, and one error for every
other outcome. `Jws.verify Backend.pure` is this reached through `IO`; both run the same checks in
the same order, because both are `Jws.prepare` followed by an attempt against each selected key. -/
def verify (policy : Policy) (keys : KeySet Backend.pure) (token : String)
    (limits : Limits := {}) : Except Error ByteArray := do
  let request ← Jws.prepare policy token limits
  let selected := keys.select request.kid #[request.alg]
  let mut verified := false
  let mut reason : Option Error := none
  for prepared in selected do
    if !verified then
      match verifySignature request.alg prepared.key request.parts.signingInputBytes
          request.signature with
      | .error refusal => reason := reason.orElse fun _ => some refusal
      | .ok true => verified := true
      | .ok false => pure ()
  Jws.outcome verified reason request.kid selected.size
  Jws.payload request

/-- A signed token, pure. The header is the caller's text rather than something written here, so
that what is signed is what the caller meant to sign. -/
def token (alg : Alg) (key : Key) (header payload : String) : Except Error String := do
  let input := Jws.signingInput header payload
  let tag ← signature alg key input.toUTF8
  .ok (input ++ "." ++ Leancrypto.Codec.Base64Url.encodeString tag)

end Pure
end Jose
