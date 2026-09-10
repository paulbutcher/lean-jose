/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

/-!
Project Wycheproof's JSON Web Key vectors, from `json_web_key_test.json` in
`testvectors_v1`. Generated from that file rather than transcribed;
`Tests.WycheproofKeys` runs them. Each case is a key set and a token, and what it
says is whether the set should be read and the token accepted.

25 of the suite's 26 cases are here. The one left out is 7, which asks
for a modulus with the ROCA weakness to be refused; recognising one is a fingerprint
test on the key rather than anything JOSE defines, and belongs wherever keys are
admitted.
-/

public section

namespace Tests.WycheproofKeys

structure Case where
  id : Nat
  valid : Bool
  jws : String

structure Group where
  comment : String
  keys : String
  cases : List Case

def groups : List Group := [
  { comment := "jws_mixedSymmetryKeyset",
    keys := "{\"keys\":[{\"alg\":\"HS256\",\"k\":\"-ebuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBingg" ++
      "E\",\"kid\":\"kid-aes-sign\",\"kty\":\"oct\",\"use\":\"sig\"},{\"alg\":\"ES256\"" ++
      ",\"crv\":\"P-256\",\"kid\":\"kid-ec-sign\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":" ++
      "\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y\":\"UI8exy-C06a7DUnjIdENkxeF" ++
      "tHM4-l_41LqEw9nVgmw\"}]}",
    cases := [
      { id := 1, valid := false, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC1hZXMtc2lnbiJ9.Zm9v.TD37p4c_0jmreSrBSDmE0F3mYS" ++
            "PtkZ3WrSyI5wb_KTg" }] },
  { comment := "jws_keyset",
    keys := "{\"keys\":[{\"alg\":\"HS256\",\"k\":\"-ebuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBingg" ++
      "E\",\"kid\":\"kid-aes-sign\",\"kty\":\"oct\",\"use\":\"sig\"},{\"alg\":\"HS256\"" ++
      ",\"k\":\"-xbuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBinggE\",\"kid\":\"kid-aes-sign-2" ++
      "\",\"kty\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 2, valid := true, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC1hZXMtc2lnbiJ9.Zm9v.TD37p4c_0jmreSrBSDmE0F3mYS" ++
            "PtkZ3WrSyI5wb_KTg" },
      { id := 3, valid := false, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC1hZXMtc2lnbiJ9.Zm9v.XD37p4c_0jmreSrBSDmE0F3mYS" ++
            "PtkZ3WrSyI5wb_KTg" }] },
  { comment := "jws_duplicate_kid",
    keys := "{\"keys\":[{\"alg\":\"HS256\",\"k\":\"-ebuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBingg" ++
      "E\",\"kid\":\"kid-aes-sign\",\"kty\":\"oct\",\"use\":\"sig\"},{\"alg\":\"HS256\"" ++
      ",\"k\":\"-xxuDNsVZ2iJtos-akfXTSCt4UO2cruLCsbWlBingge\",\"kid\":\"kid-aes-sign\"," ++
      "\"kty\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 4, valid := false, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC1hZXMtc2lnbiJ9.Zm9v.TD37p4c_0jmreSrBSDmE0F3mYS" ++
            "PtkZ3WrSyI5wb_KTg" }] },
  { comment := "rs256",
    keys := "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"kid-rsa-sign\",\"kty\":\"" ++
      "RSA\",\"n\":\"kqGboBfAWttWPCA-0cGRgsY6SaYoIARt0B_PkaEcIq9HPYNdu9n6UuWHuuTHrjF_Zo" ++
      "QW97r5HaAorNvrMEGTGdxCHZdEtkHvNVVmrtxTBLiQCbCozXhFoIrVcr3qUBrdGnNn_M3jJi7Wg7p_-x" ++
      "62nS5gNG875oyheRkutHsQXikFZwsN3q_TsPNOVlCiHy8mxzaFTUQGm-X8UYexFyAivlDSjgDJLAZSWf" ++
      "xd7k9Gxuwa3AUfQqQcVcegmgKGCaErQ3qQbh1x7WB6iopE3_-GZ8HMAVtR9AmrVscqYsnjhaCehfAI0i" ++
      "KKs8zXr8tISc0ORbaalrkk03H1ZrsEnDKEWQ\",\"use\":\"sig\"}]}",
    cases := [
      { id := 5, valid := true, jws :=
          "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC1yc2Etc2lnbiJ9.Zm9v.HUwxI1-cZrZgcuOgBQ7G7NE-Gr" ++
            "qK79l6GV1KT4DKXnSMFwC8pfZCzE7pmLE7mYpLCIvzC87yuOjuhT0uW5oe6aaAEtR978cm-q8dfly45f" ++
            "lqMrd_ifhi9GCsMlyi8dpQ42Ou1etZljFZuWjfyk8CN1c5DaHRwhqjScAPIFp6xmzKIRUJ_xdQfUSfSl" ++
            "ujLaixtScU518EoNP4oo1v7E8RAz6ZO4g2N4Xqs8OvSxYydcoTEg42QnLHe9JnXgI37Q5gSwinwaPsG3" ++
            "Ry56UYiLoL8mCUa74S51y02VsIgVmmGWgaXjM-i_lCiKQDBiBnvWlka4XhVuvd6ZWibM9cbCPtPg" }] },
  { comment := "rs256",
    keys := "{\"keys\":[{\"alg\":\"RSA1_5\",\"e\":\"AQAB\",\"kid\":\"kid-rsa-sign\",\"kty\":" ++
      "\"RSA\",\"n\":\"kqGboBfAWttWPCA-0cGRgsY6SaYoIARt0B_PkaEcIq9HPYNdu9n6UuWHuuTHrjF_" ++
      "ZoQW97r5HaAorNvrMEGTGdxCHZdEtkHvNVVmrtxTBLiQCbCozXhFoIrVcr3qUBrdGnNn_M3jJi7Wg7p_" ++
      "-x62nS5gNG875oyheRkutHsQXikFZwsN3q_TsPNOVlCiHy8mxzaFTUQGm-X8UYexFyAivlDSjgDJLAZS" ++
      "Wfxd7k9Gxuwa3AUfQqQcVcegmgKGCaErQ3qQbh1x7WB6iopE3_-GZ8HMAVtR9AmrVscqYsnjhaCehfAI" ++
      "0iKKs8zXr8tISc0ORbaalrkk03H1ZrsEnDKEWQ\",\"use\":\"enc\"}]}",
    cases := [
      { id := 6, valid := false, jws :=
          "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC1yc2Etc2lnbiJ9.Zm9v.HUwxI1-cZrZgcuOgBQ7G7NE-Gr" ++
            "qK79l6GV1KT4DKXnSMFwC8pfZCzE7pmLE7mYpLCIvzC87yuOjuhT0uW5oe6aaAEtR978cm-q8dfly45f" ++
            "lqMrd_ifhi9GCsMlyi8dpQ42Ou1etZljFZuWjfyk8CN1c5DaHRwhqjScAPIFp6xmzKIRUJ_xdQfUSfSl" ++
            "ujLaixtScU518EoNP4oo1v7E8RAz6ZO4g2N4Xqs8OvSxYydcoTEg42QnLHe9JnXgI37Q5gSwinwaPsG3" ++
            "Ry56UYiLoL8mCUa74S51y02VsIgVmmGWgaXjM-i_lCiKQDBiBnvWlka4XhVuvd6ZWibM9cbCPtPg" }] },
  { comment := "keysize_too_small",
    keys := "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"RS256_1024\",\"kty\":\"RS" ++
      "A\",\"n\":\"rJBIp6T1YK-RtPyvYqFFlcucqewSAA_IReSFchE8qyiQrbARqRlXWkB2DR8j_pJQnIpY" ++
      "ELbQWZC5Cd0PTGAU8rMbar2AW6zpmBbi7aQf17lUBdt8XI9M9rq7FPVQ1dDdUXm1SVH_9qqWhvMPR422" ++
      "SbfHBEzCAtzK0ANDRo6qz78\",\"use\":\"sig\"}]}",
    cases := [
      { id := 8, valid := false, jws :=
          "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTMjU2XzEwMjQifQ..AFuv9BiuEQP1Nmidc5xFw0qIT1d0Nmgq" ++
            "akVKmJ-mMJNzg_J1L6nNXxMrSXCS6sfGIgXc44-vk8StVf7eIKjxozqzZ3Z2jT8AX_vp6_1WOje9jSPY" ++
            "Ewf-3OgmD2QcyV14jXVTx9s0M8WKoYIo4_zA4qGiViE18khwGd9uqsjrJVA" }] },
  { comment := "exponentOne",
    keys := "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQ\",\"kid\":\"RS256_2048\",\"kty\":\"RSA" ++
      "\",\"n\":\"u-SfdHPjFtGmzuoH6gheIIZ4nLwUHBQEtFGqOe0N8JuZUc5VOzlI8yl0r8ESilAouttkd" ++
      "ftexj4VFJz5R9FH90ypVQDPL0H4mC_RtkcJ1DBB8MriU8dmzqSXP1SBs4s5L-pJWxKKLjXddD6gXJZ7H" ++
      "T_aPl2olvlLh8JkD_52U6sjdeP3OWDKvMu5GsrMlS9XJCVaCx8r9698OEElwK-ZW9PztgTSb-MvyTuyz" ++
      "is5Yc13n_z0wMLahpDilI2fzNsZ3yH6htu4VXPraSEZV6C0Z7epAAAUqiUnxh3WRupEICaewYEnW3MVS" ++
      "2hHwLwtPu_RR0XHoZr1oPSlQMP3Zi2QKw\",\"use\":\"sig\"}]}",
    cases := [
      { id := 9, valid := false, jws :=
          "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJTMjU2XzIwNDgifQ..AAH_____________________________" ++
            "________________________________________________________________________________" ++
            "________________________________________________________________________________" ++
            "________________________________________________________________________________" ++
            "ADAxMA0GCWCGSAFlAwQCAQUABCC2RQuThyxZrC1hF3430kwQRUtpKnK2r9hhkP2mQe8zsg" }] },
  { comment := "HS256",
    keys := "{\"keys\":[{\"alg\":\"HS256\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg" ++
      "\",\"kid\":\"short_hs256_key\",\"kty\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 10, valid := false, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6InNob3J0X2hzMjU2X2tleSJ9.Zm9v.OHXFiYUEmZcuvFx8FTvvN0" ++
            "fCfe8bspBX1ctB4dqcv0U" }] },
  { comment := "HS384",
    keys := "{\"keys\":[{\"alg\":\"HS384\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh" ++
      "8gISIjJCUmJygpKissLS4\",\"kid\":\"short_hs384_key\",\"kty\":\"oct\",\"use\":\"si" ++
      "g\"}]}",
    cases := [
      { id := 11, valid := false, jws :=
          "eyJhbGciOiJIUzM4NCIsImtpZCI6InNob3J0X2hzMzg0X2tleSJ9.Zm9v.TKvI_fld4zqTKPhLBgiDAr" ++
            "C88o2Lr4XyabrrD50VJUPQGev0k_q3g2kTIgK6evi8" }] },
  { comment := "HS512",
    keys := "{\"keys\":[{\"alg\":\"HS512\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh" ++
      "8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-\",\"kid\":\"short_hs512_key\",\"kty\"" ++
      ":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 12, valid := false, jws :=
          "eyJhbGciOiJIUzUxMiIsImtpZCI6InNob3J0X2hzNTEyX2tleSJ9.Zm9v.8e1Oohdq6XP8EjQUEpX-E5" ++
            "fdbj9GG4JscFqPfxdN86R6DdFiRLXW6l0FZ5k4m-itvXSKDLvIsrdtJ6rZriHWiw" }] },
  { comment := "HS256",
    keys := "{\"keys\":[{\"alg\":\"HS256\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh" ++
      "8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A\",\"kid\":\"long_hs256_key\",\"kty" ++
      "\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 13, valid := true, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImxvbmdfaHMyNTZfa2V5In0.Zm9v.21LcS4mucXHeWxB34_udiXx" ++
            "b3M3MHd0127KdnfF726o" }] },
  { comment := "HS384",
    keys := "{\"keys\":[{\"alg\":\"HS384\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh" ++
      "8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A\",\"kid\":\"long_hs384_key\",\"kty" ++
      "\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 14, valid := true, jws :=
          "eyJhbGciOiJIUzM4NCIsImtpZCI6ImxvbmdfaHMzODRfa2V5In0.Zm9v.Ets-iThpZ2a7MChVHGPUIdd" ++
            "l87WDNMWBXzUuaqqwXhy1JQJ2e7qzF395b8dTM8XE" }] },
  { comment := "HS512",
    keys := "{\"keys\":[{\"alg\":\"HS512\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh" ++
      "8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A\",\"kid\":\"long_hs512_key\",\"kty" ++
      "\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 15, valid := true, jws :=
          "eyJhbGciOiJIUzUxMiIsImtpZCI6ImxvbmdfaHM1MTJfa2V5In0.Zm9v.QNYWqEdHjNGYfU3_Nf-Zfwa" ++
            "TuW9sNCtzQCNYcp64VJJPeFzph9CsN2CbBhCa2LKTJ7xXwpZPyS3KkwqLAwy17g" }] },
  { comment := "HS256",
    keys := "{\"keys\":[{\"alg\":\"HS256\",\"k\":\"\",\"kid\":\"hs256_key\",\"kty\":\"oct\"," ++
      "\"use\":\"sig\"}]}",
    cases := [
      { id := 16, valid := false, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImhzMjU2X2tleSJ9.Zm9v.fyLEImF-r3ro2KJGK6cE1r304rKYqP" ++
            "MDLOwWF7A8cn4" }] },
  { comment := "HS384",
    keys := "{\"keys\":[{\"alg\":\"HS384\",\"k\":\"\",\"kid\":\"hs384_key\",\"kty\":\"oct\"," ++
      "\"use\":\"sig\"}]}",
    cases := [
      { id := 17, valid := false, jws :=
          "eyJhbGciOiJIUzM4NCIsImtpZCI6ImhzMzg0X2tleSJ9.Zm9v.MucSluWWs1vlepYBpVrIrCv9_j1E3Q" ++
            "jP2_bjx6Elmv6hs08BFpZHZgAzKmkuE8Hq" }] },
  { comment := "HS512",
    keys := "{\"keys\":[{\"alg\":\"HS512\",\"k\":\"\",\"kid\":\"hs512_key\",\"kty\":\"oct\"," ++
      "\"use\":\"sig\"}]}",
    cases := [
      { id := 18, valid := false, jws :=
          "eyJhbGciOiJIUzUxMiIsImtpZCI6ImhzNTEyX2tleSJ9.Zm9v.DvLOFJrm8h9rvMXLtami3YIXZXrDVx" ++
            "nKAjputDbIo4NWt5WvfCkV7xlf8kqOhmQeBSi38VBBSI-Jl0tqJvrfNg" }] },
  { comment := "wrong_algorithm",
    keys := "{\"keys\":[{\"alg\":\"ES521\",\"crv\":\"P-256\",\"kid\":\"kid-ec-sign\",\"kty\":" ++
      "\"EC\",\"use\":\"sig\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y" ++
      "\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\"}]}",
    cases := [
      { id := 19, valid := false, jws :=
          "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC1lYy1zaWduIn0.Zm9v.5cA0OHyMP7ezamUd5c9kV-FrGxd" ++
            "x4hbGXOdplQkutrqWrte5P-pAvsE3Ve6xSyU3YDQwUHjVVOtvcrEbbnZ8yA" }] },
  { comment := "invalid_algorithm",
    keys := "{\"keys\":[{\"alg\":\"ES224\",\"crv\":\"P-256\",\"kid\":\"kid-ec-sign\",\"kty\":" ++
      "\"EC\",\"use\":\"sig\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y" ++
      "\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\"}]}",
    cases := [
      { id := 20, valid := false, jws :=
          "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC1lYy1zaWduIn0.Zm9v.5cA0OHyMP7ezamUd5c9kV-FrGxd" ++
            "x4hbGXOdplQkutrqWrte5P-pAvsE3Ve6xSyU3YDQwUHjVVOtvcrEbbnZ8yA" }] },
  { comment := "invalid_use",
    keys := "{\"keys\":[{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kid\":\"kid-ec-sign\",\"kty\":" ++
      "\"EC\",\"use\":\"enc\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y" ++
      "\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\"}]}",
    cases := [
      { id := 21, valid := false, jws :=
          "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC1lYy1zaWduIn0.Zm9v.5cA0OHyMP7ezamUd5c9kV-FrGxd" ++
            "x4hbGXOdplQkutrqWrte5P-pAvsE3Ve6xSyU3YDQwUHjVVOtvcrEbbnZ8yA" }] },
  { comment := "invalid_point",
    keys := "{\"keys\":[{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kid\":\"kid-ec-sign\",\"kty\":" ++
      "\"EC\",\"use\":\"sig\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y" ++
      "\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgnw\"}]}",
    cases := [
      { id := 22, valid := false, jws :=
          "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC1lYy1zaWduIn0.Zm9v.5cA0OHyMP7ezamUd5c9kV-FrGxd" ++
            "x4hbGXOdplQkutrqWrte5P-pAvsE3Ve6xSyU3YDQwUHjVVOtvcrEbbnZ8yA" }] },
  { comment := "wrong_curve",
    keys := "{\"keys\":[{\"alg\":\"ES256\",\"crv\":\"P-384\",\"kid\":\"kid-ec-sign\",\"kty\":" ++
      "\"EC\",\"use\":\"sig\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"y" ++
      "\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\"}]}",
    cases := [
      { id := 23, valid := false, jws :=
          "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC1lYy1zaWduIn0.Zm9v.5cA0OHyMP7ezamUd5c9kV-FrGxd" ++
            "x4hbGXOdplQkutrqWrte5P-pAvsE3Ve6xSyU3YDQwUHjVVOtvcrEbbnZ8yA" }] },
  { comment := "wrong_kty",
    keys := "{\"keys\":[{\"alg\":\"ES256\",\"crv\":\"P-256\",\"kid\":\"kid-ec-sign\",\"kty\":" ++
      "\"RSA\",\"use\":\"sig\",\"x\":\"04N0xi21hshyvBp7I167sbE_bXqyqkAPfefdklMO7wY\",\"" ++
      "y\":\"UI8exy-C06a7DUnjIdENkxeFtHM4-l_41LqEw9nVgmw\"}]}",
    cases := [
      { id := 24, valid := false, jws :=
          "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC1lYy1zaWduIn0.Zm9v.5cA0OHyMP7ezamUd5c9kV-FrGxd" ++
            "x4hbGXOdplQkutrqWrte5P-pAvsE3Ve6xSyU3YDQwUHjVVOtvcrEbbnZ8yA" }] },
  { comment := "invalid_aes_gcm_key",
    keys := "{\"keys\":[{\"alg\":\"A256GCM\",\"k\":\"-ebuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBin" ++
      "ggE\",\"kid\":\"kid-aes-sign\",\"kty\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 25, valid := false, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC1hZXMtc2lnbiJ9.Zm9v.TD37p4c_0jmreSrBSDmE0F3mYS" ++
            "PtkZ3WrSyI5wb_KTg" }] },
  { comment := "invalid_aes_kw_key",
    keys := "{\"keys\":[{\"alg\":\"A256KW\",\"k\":\"-ebuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBing" ++
      "gE\",\"kid\":\"kid-aes-sign\",\"kty\":\"oct\",\"use\":\"sig\"}]}",
    cases := [
      { id := 26, valid := false, jws :=
          "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZC1hZXMtc2lnbiJ9.Zm9v.TD37p4c_0jmreSrBSDmE0F3mYS" ++
            "PtkZ3WrSyI5wb_KTg" }] }]

end Tests.WycheproofKeys
