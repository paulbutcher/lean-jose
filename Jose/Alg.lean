/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Leancrypto.Sha2

@[expose] public section

namespace Jose

/-- The curves RFC 7518 names for ECDSA. `EdDSA` has no entry here because RFC 8037 puts its curve
in the key rather than in the algorithm. -/
inductive Crv where
  | p256
  | p384
  | p521
  deriving Repr, DecidableEq

/-- The width of one coordinate, which is also the width of each half of an ECDSA signature.
P-521 rounds up to 66 bytes, which is neither the width of its digest nor a power of two, so
nothing may derive this from anything but the curve. -/
def Crv.coordinateSize : Crv → Nat
  | .p256 => 32
  | .p384 => 48
  | .p521 => 66

def Crv.name : Crv → String
  | .p256 => "P-256"
  | .p384 => "P-384"
  | .p521 => "P-521"

def Crv.ofString : String → Option Crv
  | "P-256" => some .p256
  | "P-384" => some .p384
  | "P-521" => some .p521
  | _ => none

/-- The curve RFC 8037 names for EdDSA. Ed448 is out of scope, and this module is where it would
be added. -/
inductive OkpCrv where
  | ed25519
  deriving Repr, DecidableEq

/-- The width of the public key, which RFC 8032 fixes. -/
def OkpCrv.keySize : OkpCrv → Nat
  | .ed25519 => 32

def OkpCrv.name : OkpCrv → String
  | .ed25519 => "Ed25519"

def OkpCrv.ofString : String → Option OkpCrv
  | "Ed25519" => some .ed25519
  | _ => none

/-- The kinds of key JWK distinguishes, which are its `kty` values. -/
inductive KeyKind where
  | oct
  | rsa
  | ec
  | okp
  deriving Repr, DecidableEq

def KeyKind.name : KeyKind → String
  | .oct => "oct"
  | .rsa => "RSA"
  | .ec => "EC"
  | .okp => "OKP"

def KeyKind.ofString : String → Option KeyKind
  | "oct" => some .oct
  | "RSA" => some .rsa
  | "EC" => some .ec
  | "OKP" => some .okp
  | _ => none

/-- The signature algorithms of RFC 7518 and RFC 8037. There is no `none`, so a token whose `alg`
is absent, unknown, or `"none"` has no value of this type to become, and no policy can be written
that admits one. -/
inductive Alg where
  | hs256 | hs384 | hs512
  | rs256 | rs384 | rs512
  | ps256 | ps384 | ps512
  | es256 | es384 | es512
  | eddsa
  deriving Repr, DecidableEq

def Alg.name : Alg → String
  | .hs256 => "HS256" | .hs384 => "HS384" | .hs512 => "HS512"
  | .rs256 => "RS256" | .rs384 => "RS384" | .rs512 => "RS512"
  | .ps256 => "PS256" | .ps384 => "PS384" | .ps512 => "PS512"
  | .es256 => "ES256" | .es384 => "ES384" | .es512 => "ES512"
  | .eddsa => "EdDSA"

def Alg.ofString : String → Option Alg
  | "HS256" => some .hs256 | "HS384" => some .hs384 | "HS512" => some .hs512
  | "RS256" => some .rs256 | "RS384" => some .rs384 | "RS512" => some .rs512
  | "PS256" => some .ps256 | "PS384" => some .ps384 | "PS512" => some .ps512
  | "ES256" => some .es256 | "ES384" => some .es384 | "ES512" => some .es512
  | "EdDSA" => some .eddsa
  | _ => none

instance : ToString Alg := ⟨Alg.name⟩

/-- The signature scheme an algorithm names, with everything the scheme is parameterised by. This
is the only table in the library that maps an algorithm to a digest, a curve, or a salt length, so a
backend chooses what to call and never which digest to call it with.

An algorithm no backend here implements still has a scheme. `Backend.pure` refuses `ecdsa` and
`eddsa` by name, and a backend that implements them reads the curve and the digest from here. -/
inductive Scheme where
  | hmac (digest : Leancrypto.Sha2)
  | pkcs1 (digest : Leancrypto.Sha2)
  | pss (digest : Leancrypto.Sha2) (saltLength : Nat)
  | ecdsa (crv : Crv) (digest : Leancrypto.Sha2)
  | eddsa (crv : OkpCrv)
  deriving Repr, DecidableEq

/-- RFC 7518 §3.5 fixes the PSS salt at the length of the digest, and RFC 7518 §3.4 pairs each
ECDSA algorithm with one curve. `EdDSA` names no digest: RFC 8032 hashes inside the signature and
takes the message itself, so a caller reaching for one here has misread it rather than found a gap.
-/
def Alg.scheme : Alg → Scheme
  | .hs256 => .hmac .sha256
  | .hs384 => .hmac .sha384
  | .hs512 => .hmac .sha512
  | .rs256 => .pkcs1 .sha256
  | .rs384 => .pkcs1 .sha384
  | .rs512 => .pkcs1 .sha512
  | .ps256 => .pss .sha256 32
  | .ps384 => .pss .sha384 48
  | .ps512 => .pss .sha512 64
  | .es256 => .ecdsa .p256 .sha256
  | .es384 => .ecdsa .p384 .sha384
  | .es512 => .ecdsa .p521 .sha512
  | .eddsa => .eddsa .ed25519

/-- The one kind of key an algorithm admits, read off its scheme rather than listed again. A key of
any other kind is an error at every use site; nothing coerces one kind into another. -/
def Alg.keyKind (alg : Alg) : KeyKind :=
  match alg.scheme with
  | .hmac _ => .oct
  | .pkcs1 _ | .pss _ _ => .rsa
  | .ecdsa _ _ => .ec
  | .eddsa _ => .okp

/-- The curve an ECDSA algorithm is defined over, which fixes the width of the two halves of its
signature. A key naming a different one is a mismatch rather than a choice. -/
def Alg.curve (alg : Alg) : Option Crv :=
  match alg.scheme with
  | .ecdsa crv _ => some crv
  | _ => none

end Jose
