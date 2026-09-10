/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Jose.Ecdsa
import Leancrypto.Compare
import Tests.Property

/-!
The two spellings of an ECDSA signature, and the conversion between them.

What is proved is the fixed-width half: that a coordinate survives the trip through a natural
number, leading zeros and all, and that a coordinate of the curve's width always passes the width
guard `ofDer` applies. What is checked rather than proved is the DER half, that the reader gives
back the two integers the writer put in. Stating that is easy and proving it is not: the reader
works by index into a whole `ByteArray` under a limit, so it would need a lemma placing each
integer's offset inside the concatenation the writer builds, at a width that is a variable, and
across the boundary where the sequence's own length crosses into the long form at P-521. That half
is covered twice instead: by checks over every shape of coordinate the encoding distinguishes, and
by a property over coordinates drawn at random.
-/

namespace Tests.Ecdsa
open Jose Leancrypto

/-- The big-endian value of `l`, accumulated onto `acc`. The accumulator is a parameter because the
recursion below needs one; `Rsa.natOfBytes` is this with `acc` at zero. -/
private def foldFrom (acc : Nat) (l : List UInt8) : Nat :=
  l.foldl (fun acc byte => acc * 256 + byte.toNat) acc

private theorem natOfBytes_eq (l : List UInt8) : Rsa.natOfBytes ⟨⟨l⟩⟩ = foldFrom 0 l := by
  simp [Rsa.natOfBytes, foldFrom]

private theorem foldFrom_concat (acc : Nat) (l : List UInt8) (b : UInt8) :
    foldFrom acc (l ++ [b]) = foldFrom acc l * 256 + b.toNat := by
  simp [foldFrom]

/--
The digits written for a value are the bytes that value was read from, however many bytes that was.
This is the step the two theorems below are built out of, and it is stated with the list reversed
because `Rsa.digitsOfNat` produces its last digit first while the fold consumes its first byte
first.

`l.length` is the width being written to and `foldFrom acc l.reverse` the value read from those same
bytes, so the equation says writing recovers them in front of whatever tail the recursion has
accumulated. `acc` is arbitrary: `Rsa.digitsOfNat` writes a fixed count of digits and drops what
will not fit, so anything the accumulator carries above that width cannot reach the result. That is
what makes this the right statement to induct with, and it is instantiated at zero below.
-/
private theorem digits_foldFrom : ∀ (l : List UInt8) (acc : Nat) (tail : List UInt8),
    Rsa.digitsOfNat l.length (foldFrom acc l.reverse) tail = l.reverse ++ tail
  | [], _, _ => rfl
  | b :: rest, acc, tail => by
    have hb : b.toNat < 256 := b.toNat_lt_size
    have ih := digits_foldFrom rest acc (b :: tail)
    rw [List.reverse_cons, foldFrom_concat, List.length_cons, Rsa.digitsOfNat,
      show (foldFrom acc rest.reverse * 256 + b.toNat) / 256 = foldFrom acc rest.reverse by omega,
      show (foldFrom acc rest.reverse * 256 + b.toNat) % 256 = b.toNat by omega]
    simp only [UInt8.ofNat_toNat, ih, List.append_assoc, List.cons_append, List.nil_append]

private theorem digits_natOfList (l : List UInt8) :
    Rsa.digitsOfNat l.length (foldFrom 0 l) [] = l := by
  have h := digits_foldFrom l.reverse 0 []
  rw [List.reverse_reverse, List.length_reverse] at h
  simpa using h

/--
Every fixed-width coordinate survives the trip through the natural number `Der.integer` is written
from. This is the whole of the arithmetic between `toDer` and `ofDer`, and the half of the round
trip that a curve's width makes delicate: a coordinate whose leading bytes are zero has a value that
no longer records them, so nothing but the width restores it, and a conversion that lost one would
put a signature over a different number back on the wire.

`bytes.size` is the width the coordinate arrived at, `Rsa.natOfBytes` folds those bytes big-endian
into a value, and `Rsa.bytesOfNat` writes that value back to that same width. The equation holds of
every `ByteArray`, so no shape is exempt: a coordinate that is entirely zero, one whose leading
bytes are zero, and one that fills its width.
-/
theorem bytesOfNat_natOfBytes (bytes : ByteArray) :
    Rsa.bytesOfNat bytes.size (Rsa.natOfBytes bytes) = bytes := by
  obtain ⟨⟨l⟩⟩ := bytes
  rw [natOfBytes_eq, show (ByteArray.mk ⟨l⟩).size = l.length from rfl, Rsa.bytesOfNat,
    digits_natOfList l]

private theorem foldFrom_lt : ∀ l : List UInt8, foldFrom 0 l.reverse < 256 ^ l.length
  | [] => by simp [foldFrom]
  | b :: rest => by
    have hb : b.toNat < 256 := b.toNat_lt_size
    have ih := foldFrom_lt rest
    rw [List.reverse_cons, foldFrom_concat, List.length_cons, Nat.pow_succ]
    omega

/--
A coordinate of a given width never denotes a value too wide for it. `ofDer` refuses a value that
will not fit the curve, because `Rsa.bytesOfNat` truncates rather than fails and a truncated
coordinate would be a well-formed signature over a different number; this says that guard refuses
nothing a genuine signature of that width could carry, so it is a check on the encoding and not a
limit on the values.

`Rsa.natOfBytes bytes` is the big-endian value of the coordinate and `bytes.size` its width, so
`256 ^ bytes.size` is the first value that width cannot hold. The bound is strict, which is what
makes it the same comparison `ofDer` performs.
-/
theorem natOfBytes_lt (bytes : ByteArray) : Rsa.natOfBytes bytes < 256 ^ bytes.size := by
  obtain ⟨⟨l⟩⟩ := bytes
  have h := foldFrom_lt l.reverse
  rw [List.reverse_reverse, List.length_reverse] at h
  rw [natOfBytes_eq, show (ByteArray.mk ⟨l⟩).size = l.length from rfl]
  exact h

private def bytes (l : List Nat) : ByteArray := ⟨(l.map UInt8.ofNat).toArray⟩

private def constant (width value : Nat) : ByteArray := bytes (List.replicate width value)

/-- Bytes that vary rather than repeat, so a width is filled with something other than a run of one
value. The first is below `0x80`, which is the coordinate that must not gain a sign octet. -/
private def varying (width : Nat) : ByteArray :=
  bytes ((List.range width).map fun index => (index * 37 + 11) % 251 + 1)

/-- One coordinate per shape the DER encoding of an integer distinguishes: zero, which is written as
a single zero octet; a value whose top bit is set, which gains a sign octet; the largest that does
not; a value whose leading octet is zero, whose width is recoverable only from the curve; and one
that varies. -/
private def coordinates (width : Nat) : List ByteArray :=
  [ constant width 0x00,
    constant width 0xff,
    bytes (0x7f :: List.replicate (width - 1) 0xff),
    bytes (0x00 :: List.replicate (width - 1) 0xab),
    bytes (0x00 :: 0x00 :: List.replicate (width - 2) 0x01),
    varying width,
    bytes (0x80 :: (varying (width - 1)).data.toList.map UInt8.toNat) ]

private def roundTrips (crv : Crv) (raw : ByteArray) : Bool :=
  match Ecdsa.toDer crv raw with
  | none => false
  | some der =>
    match Ecdsa.ofDer crv der with
    | none => false
    | some back => bytesEqual back raw

private def roundTripsAt (crv : Crv) : Bool :=
  let width := crv.coordinateSize
  (coordinates width).all fun r => (coordinates width).all fun s => roundTrips crv (r ++ s)

/-- Fits drawn bytes to the pair of coordinates a signature carries, so that a property quantifies
over the values one can hold rather than over the widths it cannot have. A draw shorter than the
pair is repeated rather than padded, so that the second coordinate carries drawn bytes at every
size; padding would have left it zero whenever the draw was shorter than one coordinate, and the
leading octet of each is what decides whether the encoding gains a sign octet. -/
private def coordinatePair (crv : Crv) (drawn : List Nat) : ByteArray :=
  let width := 2 * crv.coordinateSize
  if drawn.isEmpty then bytes (List.replicate width 0)
  else bytes ((List.replicate (width / drawn.length + 1) drawn).flatten.take width)

private def signature (crv : Crv) : ByteArray :=
  (Ecdsa.toDer crv (varying crv.coordinateSize ++ varying crv.coordinateSize)).getD ⟨#[]⟩

private def refuses (crv : Crv) (der : ByteArray) : Bool := (Ecdsa.ofDer crv der).isNone

private def minimal (crv : Crv) : ByteArray :=
  Der.integer (Rsa.natOfBytes (varying crv.coordinateSize))

/-- A coordinate written behind a zero octet it does not need. DER admits one spelling of an
integer, so this is a second encoding of a signature that already has one, and accepting it would
make a signature malleable without touching the curve. -/
private def nonMinimal (crv : Crv) : ByteArray :=
  Der.tlv Der.integerTag (⟨#[0x00]⟩ ++ varying crv.coordinateSize)

private def curves : List Crv := [.p256, .p384, .p521]

public def checks : List (String × Bool) :=
  curves.map (fun crv =>
      (s!"{crv.name} signatures of every shape read back as they were written", roundTripsAt crv))
    ++ curves.map (fun crv =>
      (s!"{crv.name} refuses a coordinate written behind a needless zero octet",
        refuses crv (Der.sequence (nonMinimal crv ++ minimal crv))
          && refuses crv (Der.sequence (minimal crv ++ nonMinimal crv))))
    ++ curves.map (fun crv =>
      (s!"{crv.name} refuses a value too wide for the curve",
        refuses crv (Der.sequence
          (Der.integer (256 ^ crv.coordinateSize) ++ minimal crv))))
    ++ curves.map (fun crv =>
      (s!"{crv.name} refuses bytes after the sequence", refuses crv (signature crv ++ ⟨#[0x00]⟩)))
    ++ curves.map (fun crv =>
      (s!"{crv.name} refuses a third integer",
        refuses crv (Der.sequence (minimal crv ++ minimal crv ++ minimal crv))))
    ++ curves.map (fun crv =>
      (s!"{crv.name} refuses a single integer", refuses crv (Der.sequence (minimal crv))))
    ++ curves.map (fun crv =>
      (s!"{crv.name} refuses a sequence under another tag",
        refuses crv (Der.tlv 0x31 (minimal crv ++ minimal crv))))
    ++ curves.map (fun crv =>
      (s!"{crv.name} refuses a signature of the wrong width",
        (Ecdsa.toDer crv (varying (crv.coordinateSize * 2 - 1))).isNone
          && (Ecdsa.toDer crv (varying (crv.coordinateSize * 2 + 1))).isNone))

/-- The round trip over drawn coordinates rather than over the shapes above, which is the fallback
where the proof does not close. The arithmetic half is a theorem; the DER framing between the two
conversions is not, and this covers it over values nobody here chose.

Each draws bytes, fits them to the curve's two coordinates, and asks that writing them and reading
them back returns them. -/
public def properties : List (String × IO Bool) :=
  [ ("P-256 signatures made from drawn coordinates read back as they were written",
      Property.holds (∀ drawn : List Nat, roundTrips .p256 (coordinatePair .p256 drawn) = true)),
    ("P-384 signatures made from drawn coordinates read back as they were written",
      Property.holds (∀ drawn : List Nat, roundTrips .p384 (coordinatePair .p384 drawn) = true)),
    ("P-521 signatures made from drawn coordinates read back as they were written",
      Property.holds (∀ drawn : List Nat, roundTrips .p521 (coordinatePair .p521 drawn) = true)) ]

end Tests.Ecdsa
