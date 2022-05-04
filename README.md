# check-tls-cert

## OVERVIEW

Check-tls-cert is a TLS certificate checker.

Check-tls-cert checks the validity of certificates and certificate chains.

Check-tls-cert has two commands, 'file' and 'net'. The 'file' command checks TLS certificate files and a private key. The 'net' command connects to a server and checks a TLS certificate.


### file command

The 'file' command checks TLS certificate files and a private key.

It runs the following checks:

- Certificate Files
- Private Key/Certificate Pair
- Hostname
- Validity
- Certificate Chains


### net command

The 'net' command connects to a server and checks a TLS certificate. It supports STARTTLS.

It runs the following checks:

- Certificate List
- Hostname
- Validity
- Certificate Chains
- OCSP Stapling
- OCSP Responder

## INSTALL

You can install check-tls-cert in the following way:

```
go install github.com/heartbeatsjp/check-tls-cert@latest
```

You can download the binary file of check-tls-cert from the following page:

- https://github.com/heartbeatsjp/check-tls-cert/releases

Note: Only binaries for Linux and macOS are available.

## CHECKERS

### Certificate Files Checker

It checks the order of certificates in a certificate file and the validity of those certificates.
It verifies the digital signature, Subject, Issuer, and expiration date of the certificate.

Note: The certificate chain from the root certificate is not checked. Therefore, even if the root certificate is not installed on the system, no error will occur.

### Certificate List Checker

It checks the order in which certificates are received from the server and the validity of those certificates.
It verifies the digital signature, Subject, Issuer, and expiration date of the certificate.

Note: The certificate chain from the root certificate is not checked. Therefore, even if the root certificate is not installed on the system, no error will occur.

### Private Key/Certificate Pair Checker

It checks that the private key and certificate are paired.
It checks that the public key contained in the private key matches the public key in the certificate.

### Hostname Checker

It checks the specified hostname is a valid hostname for the certificate.
It verifies the DNS field in the SANs (Subject Alternative Names).
The legacy CN (Common Name) field is ignored.

### Validity Checker

It checks the validity of the certificate.
You can set options `-w`/`--warning` and `-c`/`--critical`. These are 14 days and 28 days by default.

### Certificate Chains Checker

It checks the validity of certificate chains.
It verifies the digital signature, Subject, Issuer, and expiration date of the certificate.

The certificate chain from the root certificate to the server certificate is checked. Therefore, if the root certificate is not installed on the system, an error will occur.
By setting the option `--root-file`, you can specify a root certificate file to validate the certificate chain.

By default, system certificate directories and the environmenrt variable SSL_CERT_DIR are disabled.
This is a workaround for the following issue:

- https://github.com/golang/go/issues/39540  

You can enable them by setting the option `--enable-ssl-cert-dir`.


### OCSP Stapling Checker

It checks the OCSP response obtained by OCSP stapling.

You can set one of the options `--ocsp no`, `--ocsp as-is`, `--ocsp stapling`, or `--ocsp fallback` to run this checker.

With the option `--ocsp no`, it disables OCSP stapling checker. You should use it when `insecure algorithm SHA1-RSA` error on `OCSP Stapling` occurs. 

With the option `--ocsp as-is` (by default), if there is no OCSP response, the status will be "INFO".

With the option `--ocsp stapling`, if there is no OCSP response, it will retry the TLS connection up to two times every second. If there is still no OCSP response, the status will be "WARNING". The reason for retrying is that there may be no OCSP response immediately after starting the web server.

With the option `--ocsp fallback`, if there is no OCSP response, the OCSP Responder Checker will be executed.


### OCSP Responder Checker

Experimental: It checks the OCSP response from an OCSP responder.

You can set either the `--ocsp responder` or the `--ocsp fallback` option to run this checker.

If the status of the certificate is "good", the status will be "OK".
If the status of the certificate is "revoked" or "unknown", the staus will be "CRITICAL".

If the response has an error and the response error is "unauthorized", the status will be "CRITICAL".
If the response error is others, the status will be "UNKNOWN".


## LIMITATIONS

### Encoding format for certificates and private keys

Only PEM and DER formats are supported.

### Digital signature algorithms

Only the following algorithms are supported:

- RSA
- ECDSA
    - NIST P-224 (secp224r1)
    - NIST P-256 (secp256r1, prime256v1)
    - NIST P-384 (secp384r1)
    - NIST P-521 (secp521r1)
- Ed25519

Only the uncompressed form of ECDSA is supported.

These are due to limitations of Golang.

### SHA-1 certificates

Certificates that use SHA1WithRSA and ECDSAWithSHA1 signatures are not supported.

This is due to limitations of Go 1.18. See also:

- https://tip.golang.org/doc/go1.18#sha1


## KNOWN ISSUES

### Verification of certificates that do not have SCT fail

On macOS, verification of certificates that do not have SCT fail.

This is due to Apple's Certificate Transparency policy.

- https://support.apple.com/en-us/HT205280

For reference, on Windows, macOS, and iOS, Go 1.18 uses the platform verifier APIs for certificate verifications.

- https://tip.golang.org/doc/go1.18#minor_library_changes


## USAGE

### file command

```
Checks TLS certificate files.

Usage:
  check-tls-cert file [flags]

Flags:
  -H, --hostname hostname    hostname for verifying certificate. (required)
  -k, --key-file file        private key file. (required)
  -f, --cert-file file       certificates file. It includes a server certificate and intermediate certificates. (required)
  -C, --chain-file file      certificate chain file. It includes intermediate certificates. Used for the SSLCertificateChainFile directive in old Apache HTTP Server.
      --ca-file file         trusted CA certificates file. It includes intermediate certificates and a root certificate. Used for the ssl_trusted_certificate directive in nginx and the SSLCACertificateFile directive in Apache HTTP Server.
  -P, --password-file file   password file for the private key file if the private key file is encrypted. If it is not specified, you will be prompted to enter the password.
  -w, --warning days         warning threshold in days before expiration date (default 28)
  -c, --critical days        critical threshold in days before expiration date (default 14)
  -h, --help                 help for file

Global Flags:
      --dn-type string         Distinguished Name type. 'strict' (RFC 4514), 'loose' (with space), or 'openssl' (default "loose")
      --enable-ssl-cert-dir    enable system default certificate directories or environment variable SSL_CERT_DIR
  -O, --output-format string   output format. 'default' or 'json' (default "default")
      --root-file file         root certificate file (default system root certificate file)
  -v, --verbose count          verbose mode. Multiple -v options increase the verbosity. The maximum is 3.
```

### net command

```
Connects to a host and checks the TLS certificate.

Usage:
  check-tls-cert net [flags]

Flags:
  -H, --hostname hostname         hostname for verifying certificate
  -I, --ip-address address        IP address
  -p, --port number               port number (default 443)
  -4, --use-ipv4                  use IPv4
  -6, --use-ipv6                  use IPv6
      --starttls type             STARTTLS type. 'smtp', 'pop3, or 'imap'
      --tls-min-version version   TLS minimum version. '1.0', '1.1', '1.2', or '1.3' (default "1.0")
      --ocsp type                 OCSP checker type. 'no', 'as-is', 'stapling', 'responder', or 'fallback'. 'responder' and 'fallback' are experimental. (default "as-is")
  -t, --timeout seconds           connection timeout in seconds (default 10)
  -w, --warning days              warning threshold in days before expiration date (default 28)
  -c, --critical days             critical threshold in days before expiration date (default 14)
  -h, --help                      help for net

Global Flags:
      --dn-type string         Distinguished Name type. 'strict' (RFC 4514), 'loose' (with space), or 'openssl' (default "loose")
      --enable-ssl-cert-dir    enable system default certificate directories or environment variable SSL_CERT_DIR
  -O, --output-format string   output format. 'default' or 'json' (default "default")
      --root-file file         root certificate file (default system root certificate file)
  -v, --verbose count          verbose mode. Multiple -v options increase the verbosity. The maximum is 3.
```

## EXAMPLE OF EXECUTION

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

To get the details of each check result, use the '-v' option.

```
$ check-tls-cert file -H server-a.test \
    -k test/testdata/pki/private/server-a-rsa.key \
    -f test/testdata/pki/chain/fullchain-a-rsa.pem -v
OK: all checks have been passed

[Certificate]
INFO: the certificate information is as follows
    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a.test
    Subject Alternative Name:
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
                ...(omitted)
            Exponent: 65537 (0x10001)
    Certificate:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:
                00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:
                ...(omitted)
            Exponent: 65537 (0x10001)
    
    To get the full public key, use the '-vv' option.

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

To get more detailed information, use the '-vv' option.
```

### net command

#### Monitoring plugin

To use it as a monitoring plugin, run it without the '-v' option.

```
$ check-tls-cert net -H server-a.test 
OK: all checks have been passed
```

#### Detailed output of each check result

To get the details of each check result, use the '-v' option.

```
$ check-tls-cert net -H server-a.test -v
OK: all checks have been passed

[Certificate]
INFO: the certificate information is as follows
    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a.test
    Subject Alternative Name:
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

[OCSP Stapling]
OK: certificate is valid
    OCSP Response Data:
        OCSP Response Status: success (0x0)
        Cert Status: good
        Produced At: 2021-06-28 06:39:00 +0000 UTC
        This Update: 2021-06-27 06:39:22 +0000 UTC
        Next Update: 2021-06-29 06:39:22 +0000 UTC
    Certificate:
        Issuer : CN=Intermediate CA A RSA
        Subject: CN=Intermediate CA A RSA OCSP Responder
        Validity:
            Not Before: 2021-06-28 06:23:10 +0000 UTC
            Not After : 2022-06-28 06:23:10 +0000 UTC

[Summary]
OK: all checks have been passed

To get more detailed information, use the '-vv' option.
```

### JSON format

If the `--output-format json` option is specified, you can output in JSON format.
In this case, the exit code is 0 regardless of the status.

```
$ check-tls-cert file -H server-a.test \
    -k test/testdata/pki/private/server-a-rsa.key \
    -f test/testdata/pki/chain/fullchain-a-rsa.pem \
    --output-format json -v
{
  "metadata": {
    "name": "check-tls-cert",
    "timestamp": "2022-04-18T15:40:55+09:00",
    "command": "check-tls-cert file -H server-a.test -k test/testdata/pki/private/server-a-rsa.key -f test/testdata/pki/chain/fullchain-a-rsa.pem -v --output-format json",
    "status": 0
  },
  "result": {
    "summary": {
      "name": "Summary",
      "status": "OK",
      "message": "all checks have been passed"
    },
    "checkers": [
      {
        "name": "Certificate",
        "status": "INFO",
        "message": "the certificate information is as follows",
        "details": {
          "issuer": "CN=Intermediate CA A RSA",
          "subject": "CN=server-a.test",
          "subjectAltName": [
            {
              "dns": "server-a.test"
            },
            {
              "dns": "www.server-a.test"
            },
            {
              "iPAddress": "192.0.2.1"
            },
            {
              "email": "foo@example.test"
            },
            {
              "uri": "https://server-a.test/"
            }
          ],
          "validity": {
            "notBefore": "2022-04-18 06:17:24 +0000 UTC",
            "notAfter": "2023-04-18 06:17:24 +0000 UTC"
          }
        }
      },
      {
        "name": "Certificate Files",
        "status": "OK",
        "message": "all files contain one or more certificates",
        "details": [
          {
            "name": "Certificate File",
            "file": "test/testdata/pki/chain/fullchain-a-rsa.pem",
            "status": "OK",
            "certificate": [
              {
                "commonName": "server-a.test",
                "status": "OK",
                "subject": "CN=server-a.test",
                "issuer": "CN=Intermediate CA A RSA",
                "expiration": "2023-04-18 15:17:24 +0900"
              },
              {
                "commonName": "Intermediate CA A RSA",
                "status": "OK",
                "subject": "CN=Intermediate CA A RSA",
                "issuer": "CN=ROOT CA G2 RSA",
                "expiration": "2032-04-18 15:17:24 +0900"
              }
            ]
          },
          {
            "name": "Root Certificates File (list only, unverified)",
            "file": "test/testdata/pki/root-ca/ca-root.pem",
            "status": "OK",
            "certificate": [
              {
                "commonName": "ROOT CA G1 RSA",
                "status": "INFO",
                "subject": "CN=ROOT CA G1 RSA",
                "issuer": "CN=ROOT CA G1 RSA",
                "expiration": "2035-01-01 09:00:00 +0900"
              },
              {
                "commonName": "ROOT CA G2 RSA",
                "status": "INFO",
                "subject": "CN=ROOT CA G2 RSA",
                "issuer": "CN=ROOT CA G2 RSA",
                "expiration": "2035-01-01 09:00:00 +0900"
              },
              {
                "commonName": "ROOT CA G2 ECDSA",
                "status": "INFO",
                "subject": "CN=ROOT CA G2 ECDSA",
                "issuer": "CN=ROOT CA G2 ECDSA",
                "expiration": "2035-01-01 09:00:00 +0900"
              }
            ]
          }
        ]
      },
      {
        "name": "Private Key/Certificate Pair",
        "status": "OK",
        "message": "the private key is paired with the certificate",
        "details": {
          "privateKey": {
            "publicKeyAlgorithm": "RSA",
            "type": "RSA Public-Key: (2048 bit)",
            "modulus": "00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:\n...(omitted)",
            "exponent": "65537 (0x10001)"
          },
          "certificate": {
            "publicKeyAlgorithm": "RSA",
            "type": "RSA Public-Key: (2048 bit)",
            "modulus": "00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:\n...(omitted)",
            "exponent": "65537 (0x10001)"
          }
        }
      },
      {
        "name": "Hostname",
        "status": "OK",
        "message": "the hostname 'server-a.test' is valid for the certificate",
        "details": {
          "commonName": "server-a.test",
          "subjectAltName": [
            {
              "dns": "server-a.test"
            },
            {
              "dns": "www.server-a.test"
            },
            {
              "iPAddress": "192.0.2.1"
            },
            {
              "email": "foo@example.test"
            },
            {
              "uri": "https://server-a.test/"
            }
          ]
        }
      },
      {
        "name": "Validity",
        "status": "OK",
        "message": "the certificate will expire in 365 days on 2023-04-18 15:17:24 +0900",
        "details": {
          "notBefore": "2022-04-18 15:17:24 +0900",
          "notAfter": "2023-04-18 15:17:24 +0900"
        }
      },
      {
        "name": "Certificate Chains",
        "status": "OK",
        "message": "the certificate chain is valid",
        "details": [
          [
            {
              "commonName": "ROOT CA G2 RSA",
              "status": "OK",
              "subject": "CN=ROOT CA G2 RSA",
              "issuer": "CN=ROOT CA G2 RSA",
              "expiration": "2035-01-01 09:00:00 +0900"
            },
            {
              "commonName": "Intermediate CA A RSA",
              "status": "OK",
              "subject": "CN=Intermediate CA A RSA",
              "issuer": "CN=ROOT CA G2 RSA",
              "expiration": "2032-04-18 15:17:24 +0900"
            },
            {
              "commonName": "server-a.test",
              "status": "OK",
              "subject": "CN=server-a.test",
              "issuer": "CN=Intermediate CA A RSA",
              "expiration": "2023-04-18 15:17:24 +0900"
            }
          ]
        ]
      }
    ]
  }
}
```

### Shell completions

`check-tls-cert completion` subcommand generates the autocompletion script for shells.

See `check-tls-cert completion bash/zsh/fish --help` to load them.

## LICENSE

Copyright 2021-2022 HEARTBEATS Corporation. All rights reserved.

Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
