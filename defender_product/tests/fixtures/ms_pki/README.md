# Microsoft PKI certificates used as test fixtures

Public certificate-authority certificates (not samples). Provenance, 2026-10-20:

| file | subject | sha1 | obtained from |
|---|---|---|---|
| `ms_root_certificate_authority_2001.der` | CN=Microsoft Root Certificate Authority | cdd4eeae6000ac7f40c3802c171e30148030c072 | http://www.microsoft.com/pki/certs/MicrosoftRootCert.crt (the AIA URL named inside the 2006 PCA) |
| `ms_code_signing_pca_2000.der` | OU=Copyright (c) 2000 Microsoft Corp., CN=Microsoft Code Signing PCA | d07ea64088a80085f01bd40aa4ead82f470482a6 | http://www.microsoft.com/pki/certs/CodeSignPCA2.crt (AIA URL in 2006-era Microsoft leaves) |
| `ms_code_signing_pca_2006.der` | CN=Microsoft Code Signing PCA (issued 2006-01-25, serial 61 15 08 27 ...) | fdd1314ed3268a95e198603ba8316fa63cbcd82d | certificate bag of a Microsoft-signed Sysinternals binary; **verified cryptographically** against the root above (`test_v31.py`) |
| `ms_code_signing_pca_2010.der` | CN=Microsoft Code Signing PCA (re-issued 2010-08-31, new key) | 3caf9ba2db5570caf76942ff99101b993888e257 | http://www.microsoft.com/pki/certs/MicCodSigPCA_08-31-2010.crt |

Microsoft's PKI repository page no longer lists the pre-2010 code-signing PCAs, so the
2006 issue cannot be downloaded from microsoft.com any more; its authenticity rests on
its RSA signature verifying under the Microsoft Root Certificate Authority key, which the
test suite checks (and checks that a one-byte change breaks it).
