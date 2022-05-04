// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestNewCertificateChecker(t *testing.T) {
	var (
		c          checker.Checker
		serverCert *x509.Certificate
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	// CN=server-a.test (RSA)
	//
	// INFO: the certificate information is as follows
	//     Issuer : CN=Intermediate CA A RSA
	//     Subject: CN=server-a.test
	//     Subject Alternative Name:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	//     Validity:
	//         Not Before: 2021-06-21 03:16:35 +0000 UTC
	//         Not After : 2022-06-21 03:16:35 +0000 UTC
	//     Signature Algorithm: SHA256WithRSA
	//     Subject Public Key Info:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                  00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:
	//                  6b:07:a1:5e:b6:85:19:db:0a:30:e3:59:a6:59:01:
	//                  60:0a:a3:0f:9f:96:d9:4c:36:24:ab:dd:29:53:a2:
	//                  76:f0:7e:cb:19:5c:bc:91:e0:2f:29:f3:aa:07:a5:
	//                  f3:52:d1:19:47:63:a5:0a:da:00:11:e2:2e:d9:f1:
	//                  52:4a:90:67:c2:59:6e:84:fd:4f:33:34:6f:96:fe:
	//                  10:e8:97:37:b9:8b:23:8b:33:40:24:ed:03:05:c3:
	//                  ff:73:d2:80:6a:9a:65:59:a5:4a:bf:3e:7d:13:6d:
	//                  ad:a2:26:cf:ff:02:1e:c4:e8:22:5b:73:0b:57:bd:
	//                  f3:16:c9:7f:08:a5:15:06:44:e4:a3:04:8a:17:af:
	//                  9e:4e:53:c8:77:d9:01:96:bf:d6:6d:bf:12:bf:f1:
	//                  3f:54:12:17:77:6e:a6:d4:93:38:f9:a9:d4:28:52:
	//                  02:18:b9:d1:02:ca:2f:21:1a:f7:c7:7f:1d:d2:b5:
	//                  60:78:d8:d5:24:43:8d:53:13:3d:ea:b0:b7:1f:1e:
	//                  ee:3c:77:13:51:f3:95:b3:e4:b8:7a:36:af:fb:eb:
	//                  48:8e:20:b2:b0:19:82:99:f2:51:eb:51:f9:c9:08:
	//                  12:53:dc:6b:e1:a4:53:d1:1b:6a:d7:31:dd:97:6c:
	//                  36:3f
	//             Exponent: 65537 (0x10001)
	//
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.pem")
	c = checker.NewCertificateChecker(serverCert)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.INFO, c.Status())
	assert.Contains(w.String(), `INFO: the certificate information is as follows`)

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test`)
	assert.Contains(w.String(), `    Signature Algorithm: SHA256WithRSA
    Subject Public Key Info:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)

	// CN=server-a.test (ECDSA)
	//
	// INFO: the certificate information is as follows
	//     Issuer : CN=Intermediate CA A RSA
	//     Subject: CN=server-a.test
	//     Subject Alternative Name:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	//     Validity:
	//         Not Before: 2021-06-21 03:16:35 +0000 UTC
	//         Not After : 2022-06-21 03:16:35 +0000 UTC
	//     Signature Algorithm: SHA256WithRSA
	//     Subject Public Key Info:
	//         Public Key Algorithm: ECDSA
	//             Public-Key: (256 bit)
	//             pub:
	//                  04:36:ee:23:87:98:ba:57:8d:a0:dc:72:40:18:ae:
	//                  67:2d:92:c3:2c:43:ac:fd:50:32:34:b6:26:f4:02:
	//                  fb:6c:ae:ff:f1:e7:3a:bd:30:7f:a4:b2:2d:2a:c7:
	//                  25:a7:5a:61:65:34:f8:cc:92:04:72:d4:5f:26:87:
	//                  14:e2:48:64:d6
	//             NIST CURVE: P-256
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-ecdsa.pem")
	c = checker.NewCertificateChecker(serverCert)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.INFO, c.Status())
	assert.Contains(w.String(), `INFO: the certificate information is as follows`)

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test`)
	assert.Contains(w.String(), `    Signature Algorithm: SHA256WithRSA
    Subject Public Key Info:
        Public Key Algorithm: ECDSA
            Public-Key: (256 bit)
            pub:`)

	// CN=server-a.test (Ed25519)
	//
	// INFO: the certificate information is as follows
	//     Issuer : CN=Intermediate CA A RSA
	//     Subject: CN=server-a.test
	//     Subject Alternative Name:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	//     Validity:
	//         Not Before: 2021-06-21 03:16:35 +0000 UTC
	//         Not After : 2022-06-21 03:16:35 +0000 UTC
	//     Signature Algorithm: SHA256WithRSA
	//     Subject Public Key Info:
	//         Public Key Algorithm: Ed25519
	//             ED25519 Public-Key:
	//             pub:
	//                  1d:84:84:80:3a:4f:0f:9a:d6:c7:77:73:8a:8d:c2:
	//                  5e:1d:23:ab:a7:aa:a1:71:c1:cf:fd:26:6a:c8:ba:
	//                  67:16
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-ed25519.pem")
	c = checker.NewCertificateChecker(serverCert)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.INFO, c.Status())
	assert.Contains(w.String(), `INFO: the certificate information is as follows`)

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test`)
	assert.Contains(w.String(), `    Signature Algorithm: SHA256WithRSA
    Subject Public Key Info:
        Public Key Algorithm: Ed25519
            ED25519 Public-Key:
            pub:`)

}

func TestCertificateChecker(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	serverCert, _ := x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.pem")

	// verbose 1
	checker.SetVerbose(1)
	c := checker.NewCertificateChecker(serverCert)
	assert.Equal("Certificate", c.Name())
	assert.Equal(checker.INFO, c.Status())
	assert.Equal("the certificate information is as follows", c.Message())

	assert.Equal("CN=server-a.test", c.Details().(*checker.CertificateDetails).Subject)

	c.PrintName()
	assert.Equal("[Certificate]\n", w.String())

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.INFO, c.Status())
	assert.Equal("INFO: the certificate information is as follows\n", w.String())

	w.Reset()
	c.PrintDetails()
	assert.Regexp(`    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a\.test
    Subject Alternative Name:
        DNS: server-a\.test
        DNS: www\.server-a\.test
        IP Address: 192\.0\.2\.1
        email: foo@example\.test
        URI: https://server-a\.test/
    Validity:
        Not Before: [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \+0000
        Not After : [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \+0000
`,
		w.String())

	// verbose 2
	checker.SetVerbose(2)
	c = checker.NewCertificateChecker(serverCert)

	w.Reset()
	c.PrintDetails()
	assert.Regexp(`    Issuer : CN=Intermediate CA A RSA
    Subject: CN=server-a\.test
    Subject Alternative Name:
        DNS: server-a\.test
        DNS: www\.server-a\.test
        IP Address: 192\.0\.2\.1
        email: foo@example\.test
        URI: https://server-a\.test/
    Validity:
        Not Before: [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \+0000
        Not After : [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \+0000
    Version: 3
    Serial Number:
        ([0-9A-F]{2}:)+[0-9A-F]{2}
    Signature Algorithm: SHA256WithRSA
    Subject Public Key Info:
        Public Key Algorithm: RSA
            RSA Public-Key: \(2048 bit\)
            Modulus:
                ([0-9a-f]{2}:)+
                ...\(omitted\)
            Exponent: 65537 \(0x10001\)
    Authority Key Identifier:
        ([0-9A-F]{2}:)+[0-9A-F]{2}
    Subject Key Identifier:
        ([0-9A-F]{2}:)+[0-9A-F]{2}
    Key Usage:
        Digital Signature \(digitalSignature\)
        Key Encipherment \(keyEncipherment\)
    Extended Key Usage:
        TLS Web Server Authentication \(serverAuth\)
        TLS Web Client Authentication \(clientAuth\)
    Basic Constraints:
        CA: false
`,
		w.String())

}
