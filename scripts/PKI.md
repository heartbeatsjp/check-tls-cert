# PKI Diagram

- Root CA G1 RSA (an old-generation root CA)
    - Root CA G2 RSA (cross-signing)
    - Root CA G2 ECDSA (cross-signing)
- Root CA G2 RSA
    - Intermediate CA A RSA
        - server-a.test (RSA)
        - server-a.test (ECDSA)
        - server-a.test (Ed25199)
        - server-a.test (Ed448) (Not supported by check-tls-cert)
    - Intermediate CA B RSA
        - server-b.test (RSA)
        - server-b.test (ECDSA)
        - server-b.test (Ed25199)
        - server-b.test (Ed448) (Not supported by check-tls-cert)
- Root CA G2 ECDSA
    - Intermediate CA ECDSA
        - server-c.test (RSA)
        - server-c.test (ECDSA)
        - server-c.test (Ed25199)
        - server-c.test (Ed448) (Not supported by check-tls-cert)

