"""Authenticode trust for Microsoft first-party code (industry-standard allowlisting).

A file is TRUSTED only if ALL hold:
  1. LIEF verify_signature() == OK: every embedded signature is intact and the
     Authenticode digest matches the file contents (the file was not modified).
  2. The signer certificate was issued by a PINNED Microsoft code-signing PCA and its
     RSA signature verifies under that PCA's public key. This is checked here, in pure
     Python, rather than trusting subject/issuer *strings*: an attacker can mint a
     self-signed cert named "Microsoft Corporation" and copy the genuine PCA cert into
     the PKCS#7 bag, but cannot produce a leaf the PCA's key actually signed.
     (LIEF's own x509.verify cannot be used: PCA 2011 expired 2026-07 and mbedtls then
     reports NOT_TRUSTED for genuine and forged chains alike.)
  3. No bytes after the certificate table (CVE-2013-3900 / EnableCertPaddingCheck):
     Authenticode does not cover data appended after the signature, a known way to
     smuggle a payload inside a validly signed file.

Pins are Microsoft's own code-signing PCAs only. Deliberately NOT pinned: "Microsoft
Windows Third Party Component CA" and the Windows Hardware Compatibility (WHCP) PCAs --
those sign OTHER vendors' code and the WHCP route has been abused to get malicious
drivers Microsoft-signed. Pins were taken from Microsoft packages on nuget.org (never
from evaluation data); PCA 2011's SHA-1 f252e794...2c52135 matches Microsoft's
published thumbprint.

v3.1 adds the two pre-2010 generations of the same first-party PCA, which the v3 list
lacked (Microsoft re-keyed "Microsoft Code Signing PCA" in 2006-01 and again in 2010-08;
only the 2010 issue was pinned, so 2006-2012 Microsoft binaries fell through to the ML
layer). Provenance (tests/fixtures/ms_pki/README.md, checked by tests/test_v31.py):
  * the 2000 PCA is byte-identical to http://www.microsoft.com/pki/certs/CodeSignPCA2.crt;
  * the 2006 PCA's own RSA signature verifies under the Microsoft Root Certificate
    Authority (http://www.microsoft.com/pki/certs/MicrosoftRootCert.crt, the AIA URL the
    PCA itself names), so its authenticity does not depend on where its bytes came from.

Any parsing error -> not trusted (the ML models then decide, fail-toward-detection).
"""
from __future__ import annotations
import hashlib

import lief

# sha256(DER) of Microsoft first-party code-signing PCA certificates (sha1 in comment).
PINNED_PCA_FULL: dict[str, str] = {
    "3dadfaf812dd1bbaef45834ccbd188f3cd97139e2ed1aca69c2dd63082142f8f": "Microsoft Code Signing PCA 2024",          # 5039c8dc...
    "56da8722afd94066ffe1e4595473a4854892b843a0827d53fb7d8f4aeed1e18b": "Microsoft Code Signing PCA 2011",          # f252e794...
    "fe229efc927f6d77b738896752a21803a59736baa17bf5be9a50c72e219cbcd2": "Microsoft Windows Code Signing PCA 2024",  # d30f05f6...
    "9cbf22fae0dd53a7395556ce6154aa14a0d03360aa8c51cfea05d1fd8819e043": "Microsoft Code Signing PCA",               # 3caf9ba2...
    "9aad6c1a83a1b974ba574a995af35b8ca772da919270db1605a8b81e1bbc896f": "Microsoft Code Signing PCA 2010",          # 8bfe3107...
    # v3.1: earlier issues of the first-party "Microsoft Code Signing PCA" (see docstring)
    "930c1e42359239558adce064b019473db84dd09b9f3fc6586d099dc222a5a392": "Microsoft Code Signing PCA (2006 issue)",   # fdd1314e...
    "6a3c4d89cd6297023831b9c4f718ce71cf8753a2be49e021245ec6ba5066ff00": "Microsoft Code Signing PCA (2000 issue)",   # d07ea640...
}

_DIGESTINFO = {
    "06092a864886f70d010105": ("sha1", bytes.fromhex("3021300906052b0e03021a05000414")),
    "06092a864886f70d01010b": ("sha256", bytes.fromhex("3031300d060960864801650304020105000420")),
    "06092a864886f70d01010c": ("sha384", bytes.fromhex("3041300d060960864801650304020205000430")),
    "06092a864886f70d01010d": ("sha512", bytes.fromhex("3051300d060960864801650304020305000440")),
}


def _tlv(buf: bytes, i: int) -> tuple[int, int, int]:
    """DER TLV at i -> (tag, value_start, value_end)."""
    tag = buf[i]
    ln = buf[i + 1]
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i + 2:i + 2 + n], "big")
        start = i + 2 + n
    else:
        start = i + 2
    return tag, start, start + ln


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    out, i = [], start
    while i < end:
        tag, s, e = _tlv(buf, i)
        out.append((tag, i, s, e))
        i = e
    return out


def _cert_parts(der: bytes):
    """-> (tbs_der, sigalg_oid_tlv_hex, signature_bytes, rsa_n, rsa_e)."""
    _, s, e = _tlv(der, 0)
    tbs, alg, sigv = _children(der, s, e)[:3]
    tbs_der = der[tbs[1]:tbs[3]]
    alg_oid = _children(der, alg[2], alg[3])[0]
    oid_hex = der[alg_oid[1]:alg_oid[3]].hex()
    signature = der[sigv[2] + 1:sigv[3]]  # skip BIT STRING unused-bits byte
    fields = _children(der, tbs[2], tbs[3])
    if fields and fields[0][0] == 0xA0:  # explicit [0] version
        fields = fields[1:]
    spki = fields[5]  # serial, sigalg, issuer, validity, subject, SPKI
    _, bit = _children(der, spki[2], spki[3])[:2]
    rsapub = der[bit[2] + 1:bit[3]]
    _, rs, re_ = _tlv(rsapub, 0)
    n_t, e_t = _children(rsapub, rs, re_)[:2]
    n = int.from_bytes(rsapub[n_t[2]:n_t[3]], "big")
    e_ = int.from_bytes(rsapub[e_t[2]:e_t[3]], "big")
    return tbs_der, oid_hex, signature, n, e_


def rsa_signed_by(child_der: bytes, issuer_der: bytes) -> bool:
    """True iff child's PKCS#1 v1.5 signature verifies under issuer's RSA key."""
    tbs, oid, sig, _, _ = _cert_parts(child_der)
    if oid not in _DIGESTINFO:
        return False
    hname, prefix = _DIGESTINFO[oid]
    _, _, _, n, e = _cert_parts(issuer_der)
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = prefix + hashlib.new(hname, tbs).digest()
    return em == b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t


def is_trusted_microsoft(bytez: bytes, pe=None) -> bool:
    try:
        pe = pe if pe is not None else lief.PE.parse(bytez)
        if pe is None or not pe.has_signatures:
            return False
        if pe.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK:
            return False
        cd = pe.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
        if cd.size == 0 or cd.rva + cd.size < len(bytez) - 8:
            return False
        for sig in pe.signatures:
            leaf = sig.signers[0].cert
            if leaf is None:
                return False
            leaf_der = bytes(leaf.raw)
            ok = False
            for ca in sig.certificates:
                der = bytes(ca.raw)
                if hashlib.sha256(der).hexdigest() in PINNED_PCA_FULL and ca.subject == leaf.issuer:
                    ok = rsa_signed_by(leaf_der, der)
                    if ok:
                        break
            if not ok:
                return False
        return True
    except Exception:
        return False
