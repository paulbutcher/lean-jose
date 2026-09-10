/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Read
public import Leancrypto.Codec.Base64Url

@[expose] public section

namespace Jose
namespace Compact

/-- The three parts as the token spells them, still base64url. They are kept as text because the
signing input is the text, and a part decoded and encoded again is not guaranteed to be the text
that was signed. -/
structure Parts where
  header : String
  payload : String
  signature : String
  deriving Repr, DecidableEq

/-- What the signature covers: RFC 7515 §5.2 step 8 takes the first two parts of the token as
received, joined by the separator between them. Nothing here re-encodes the parsed header, which is
how a verifier ends up checking a signature over something the signer never signed. -/
def Parts.signingInput (parts : Parts) : String := parts.header ++ "." ++ parts.payload

/-- The signing input is base64url and a dot, so its ASCII and its UTF-8 are the same bytes. -/
def Parts.signingInputBytes (parts : Parts) : ByteArray := parts.signingInput.toUTF8

/-- The first segment, and every segment after it, so that the count of segments is one more than
the count of separators by construction rather than by a check. -/
def splitDots : List Char → List Char × List (List Char)
  | [] => ([], [])
  | '.' :: rest => let (first, others) := splitDots rest; ([], first :: others)
  | c :: rest => let (first, others) := splitDots rest; (c :: first, others)

/-- Exactly three parts, exactly two separators, no whitespace anywhere, and a signature part that
is present. Whitespace is refused before the split rather than trimmed: a token is compared, logged,
and cached as the bytes that arrived, and trimming makes two different strings into one token.

The empty signature is what an `alg` of `none` produces, so refusing it here means the unsecured
JWS of RFC 7515 §6 is rejected by the shape of the token, before any header is read. -/
def parse (limits : Limits) (token : String) : Except Error Parts :=
  if token.utf8ByteSize > limits.maxTokenBytes then
    .error (.tokenTooLong token.utf8ByteSize limits.maxTokenBytes)
  else if token.toList.any Char.isWhitespace then
    .error .whitespaceInToken
  else
    match splitDots token.toList with
    | (header, [payload, signature]) =>
      if signature.isEmpty then .error .emptySignature
      else .ok {
        header := String.ofList header,
        payload := String.ofList payload,
        signature := String.ofList signature }
    | (_, others) => .error (.wrongPartCount (others.length + 1))

def decodePart (part : Source) (text : String) : Except Error ByteArray :=
  match Leancrypto.Codec.Base64Url.decodeString text with
  | some bytes => .ok bytes
  | none => .error (.badBase64Url part)

end Compact
end Jose
