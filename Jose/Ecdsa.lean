/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Alg
public import Leancrypto.Der
public import Leancrypto.Rsa

/-!
The two spellings of an ECDSA signature: the fixed-width `R‖S` of RFC 7518 §3.4, which is what a
JWS carries, and the DER `SEQUENCE` of two `INTEGER`s, which is what a library built on OpenSSL
takes. Nothing in this package verifies an ECDSA signature; this is here because it is pure, and so
belongs where it can be reasoned about rather than in a package that cannot.
-/

@[expose] public section

namespace Jose
namespace Ecdsa

open Leancrypto

/-- The width of each half comes from the curve, never from the digest: ES512 is P-521, whose
coordinates are 66 bytes, while its digest is 64. -/
def toDer (crv : Crv) (raw : ByteArray) : Option ByteArray :=
  let width := crv.coordinateSize
  if raw.size = 2 * width then
    some (Der.sequence
      (Der.integer (Rsa.natOfBytes (raw.extract 0 width))
        ++ Der.integer (Rsa.natOfBytes (raw.extract width (2 * width)))))
  else
    none

/-- The inverse, which refuses anything the writer above would not have produced: bytes after the
`SEQUENCE`, bytes after the two `INTEGER`s inside it, and a value too wide for the curve. That last
one matters most, because `Rsa.bytesOfNat` would otherwise silently drop the high bytes of an
oversized value and hand back a well-formed signature over a different number. -/
def ofDer (crv : Crv) (der : ByteArray) : Option ByteArray := do
  let width := crv.coordinateSize
  let sequence ← Der.readTagged Der.sequenceTag der der.size 0
  guard (sequence.next = der.size)
  let (r, afterR) ← Der.readNat der sequence.next sequence.start
  let (s, afterS) ← Der.readNat der sequence.next afterR
  guard (afterS = sequence.next)
  guard (r < 256 ^ width)
  guard (s < 256 ^ width)
  some (Rsa.bytesOfNat width r ++ Rsa.bytesOfNat width s)

end Ecdsa
end Jose
