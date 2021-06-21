# check-tls-cert

Check-tls-cert is a TLS certificate checker.

Check-tls-cert checks the validity of certificates and certificate chains.

Check-tls-cert has two commands, 'file' and 'net'. The 'file' command checks TLS certificate files and a private key. The 'net' command connects to a server and checks a TLS certificate.


## Requirement

- Go 1.16

## file command

The 'file' command checks TLS certificate files and a private key.

It runs the following checks:

- Certificate Files
- Private Key/Certificate Pair
- Hostname
- Validity
- Certificate Chains

### Usage

```
Checks TLS certificate files.

Usage:
  check-tls-cert file [flags]

Flags:
      --ca-file file        trusted CA certificates file. It includes intermediate certificates and a root certificate. Used for the ssl_trusted_certificate directive in nginx and the SSLCACertificateFile directive in Apache HTTP Server.
  -f, --cert-file file      certificates file. It includes a server certificate and intermediate certificates. (required)
  -C, --chain-file file     certificate chain file. It includes intermediate certificates. Used for the SSLCertificateChainFile directive in old Apache HTTP Server.
  -h, --help                help for file
  -H, --hostname hostname   hostname for verifying certificate. (required)
  -k, --key-file file       private key file. (required)

Global Flags:
  -c, --critical days    critical threshold in days before expiration date (default 14)
      --dn-type string   Distinguished Name Type. 'strict' (RFC 4514), 'loose' (with space), or 'openssl' (default "loose")
      --root-file file   root certificate file (default system root certificate file)
  -v, --verbose count    verbose mode. Multiple -v options increase the verbosity. The maximum is 3.
  -w, --warning days     warning threshold in days before expiration date (default 28)
```

## net command

The 'net' command connects to a server and checks a TLS certificate. It supports STARTTLS.

It runs the following checks:

- Certificate List
- Hostname
- Validity
- Certificate Chains

### Usage

```
Connects to a host and checks the TLS certificate.

Usage:
  check-tls-cert net [flags]

Flags:
  -h, --help                 help for net
  -H, --hostname hostname    hostname for verifying certificate
  -I, --ip-address address   IP address
  -p, --port number          port number (default 443)
      --starttls type        STARTTLS type. 'smtp', 'pop3, or 'imap'
  -t, --timeout seconds      connection timeout in seconds (default 10)
  -4, --use-ipv4             use IPv4
  -6, --use-ipv6             use IPv6

Global Flags:
  -c, --critical days    critical threshold in days before expiration date (default 14)
      --dn-type string   Distinguished Name Type. 'strict' (RFC 4514), 'loose' (with space), or 'openssl' (default "loose")
      --root-file file   root certificate file (default system root certificate file)
  -v, --verbose count    verbose mode. Multiple -v options increase the verbosity. The maximum is 3.
  -w, --warning days     warning threshold in days before expiration date (default 28)
```

## Limitations

Due to limitations of Golang, only the following algorithms are supported:

- RSA
- ECDSA
    - NIST P-224 (secp224r1)
    - NIST P-256 (secp256r1, prime256v1)
    - NIST P-384 (secp384r1)
    - NIST P-521 (secp521r1)
- Ed25519

Due to limitations of Golang, ECDSA supports only the uncompressed form.


## Example of execution

### file command

#### Monitoring plugin

To use it as a monitoring plugin, run it without the '-v' option.

```
$ check-tls-cert file -H server-a.test \
    -k test/testdata/pki/private/server-a-rsa.key \
    -f test/testdata/pki/chain/fullchain-a-rsa.pem
OK: all checks have been passed
```

#### Detailed output of each check result

To get the details of each check result, use the '-vv' option.

```
$ check-tls-cert file -H server-a.test \
    -k test/testdata/pki/private/server-a-rsa.key \
    -f test/testdata/pki/chain/fullchain-a-rsa.pem -vv
OK: all checks have been passed

[Certificate]
OK: the certificate information is as follows
    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a.test
    Subject Alternative Names:
        DNS: server-a.test
        DNS: www.server-a.test
    Validity
        Not Before: 2021-02-26 01:17:34 +0000 UTC
        Not After : 2022-02-26 01:17:34 +0000 UTC

[Certificate Files]
OK: all files contain one or more certificates
    OK: Certificate File
        File: test/testdata/pki/chain/fullchain-a-rsa.pem
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: 2022-02-26 10:17:34 +0900
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: 2031-02-27 10:17:34 +0900

[Private Key/Certificate Pair]
OK: the private key is paired with the certificate
    Private Key:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:
                00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:
                ...(ommited)
            Exponent: 65537 (0x10001)
    Certificate:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:
                00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:
                ...(ommited)
            Exponent: 65537 (0x10001)
    
    To get the full public key, use the '-vvv' option.

[Hostname]
OK: the hostname 'server-a.test' is valid for the certificate
    Common Name: server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test

[Validity]
OK: the certificate will expire in 365 days on 2022-02-26 10:17:34 +0900
    Not Before: 2021-02-26 10:17:34 +0900
    Not After : 2022-02-26 10:17:34 +0900

[Certificate Chains]
OK: the certificate chain is valid
    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: 2035-01-01 09:00:00 +0900
      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: 2031-02-27 10:17:34 +0900
        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: 2022-02-26 10:17:34 +0900

[Summary]
OK: all checks have been passed

To get more detailed information, use the '-vvv' option.
```

### net command

#### Monitoring plugin

To use it as a monitoring plugin, run it without the '-v' option.

```
$ check-tls-cert net -H server-a.test 
OK: all checks have been passed
```

#### Detailed output of each check result

To get the details of each check result, use the '-vv' option.

```
$ check-tls-cert net -H server-a.test -vv
OK: all checks have been passed

[Certificate]
OK: the certificate information is as follows
    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a.test
    Subject Alternative Names:
        DNS: server-a.test
        DNS: www.server-a.test
    Validity:
        Not Before: 2021-02-26 01:17:34 +0000 UTC
        Not After : 2022-02-26 01:17:34 +0000 UTC

[Certificate List]
OK: certificates are valid
    - OK: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: 2022-02-26 10:17:34 +0900
    - OK: Intermediate CA A RSA
        Subject   : CN=Intermediate CA A RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: 2031-02-27 10:17:34 +0900

[Hostname]
OK: the hostname 'server-a.test' is valid for the certificate
    Common Name: server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test

[Validity]
OK: the certificate will expire in 365 days on 2022-02-26 10:17:34 +0900
    Not Before: 2021-02-26 10:17:34 +0900
    Not After : 2022-02-26 10:17:34 +0900

[Certificate Chains]
OK: the certificate chain is valid
    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: 2035-01-01 09:00:00 +0900
      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: 2031-02-27 10:17:34 +0900
        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: 2022-02-26 10:17:34 +0900

[Summary]
OK: all checks have been passed

To get more detailed information, use the '-vvv' option.
```

## LICENSE

Copyright 2021 HEARTBEATS Corporation. All rights reserved.
Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
