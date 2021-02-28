// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckCertificateChain(t *testing.T) {
	var (
		state             checker.State
		serverCert        *x509.Certificate
		intermediateCerts []*x509.Certificate
		rootCerts         []*x509.Certificate
	)
	assert := assert.New(t)

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 17:09:50 +0900
	//         - OK: server-a.test
	//             Subject: CN=server-a.test
	//             Issuer: CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 17:09:50 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA A RSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	// CN=server-a.test (RSA)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:34:38 +0900
	//         - OK: server-a.test
	//             Subject: CN=server-a.test
	//             Issuer: CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 18:34:38 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA A RSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	// CN=server-a.test (ECDSA)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-ecdsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 17:09:50 +0900
	//         - OK: server-a.test
	//             Subject: CN=server-a.test
	//             Issuer: CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 17:09:50 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA A RSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	// CN=server-a.test (Ed25519)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-ed25519.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA B RSA
	//           Subject: CN=Intermediate CA B RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:50:48 +0900
	//         - OK: server-b.test
	//             Subject: CN=server-b.test
	//             Issuer: CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:50:48 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA B RSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	// CN=server-b.test (RSA)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-b-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA B RSA
	//           Subject: CN=Intermediate CA B RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:50:48 +0900
	//         - OK: server-b.test
	//             Subject: CN=server-b.test
	//             Issuer: CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:50:48 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA B RSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	// CN=server-b.test (ECDSA)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-b-ecdsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA B RSA
	//           Subject: CN=Intermediate CA B RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:50:48 +0900
	//         - OK: server-b.test
	//             Subject: CN=server-b.test
	//             Issuer: CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:50:48 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA B RSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	// CN=server-b.test (Ed25519)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-b-ed25519.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 ECDSA
	//         Subject: CN=ROOT CA G2 ECDSA
	//         Issuer: CN=ROOT CA G2 ECDSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA ECDSA
	//           Subject: CN=Intermediate CA ECDSA
	//           Issuer: CN=ROOT CA G2 ECDSA
	//           Expiration: 2031-02-22 18:40:06 +0900
	//         - OK: server-c.test
	//             Subject: CN=server-c.test
	//             Issuer: CN=Intermediate CA ECDSA
	//             Expiration: 2022-02-21 18:40:06 +0900
	//
	// CN=ROOT CA G2 ECDSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	// CN=Intermediate CA ECDSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	// CN=server-c.test (RSA)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-c-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 ECDSA
	//         Subject: CN=ROOT CA G2 ECDSA
	//         Issuer: CN=ROOT CA G2 ECDSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA ECDSA
	//           Subject: CN=Intermediate CA ECDSA
	//           Issuer: CN=ROOT CA G2 ECDSA
	//           Expiration: 2031-02-22 18:40:06 +0900
	//         - OK: server-c.test
	//             Subject: CN=server-c.test
	//             Issuer: CN=Intermediate CA ECDSA
	//             Expiration: 2022-02-21 18:40:06 +0900
	//
	// CN=ROOT CA G2 ECDSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	// CN=Intermediate CA ECDSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	// CN=server-c.test (ECDSA)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-c-ecdsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 ECDSA
	//         Subject: CN=ROOT CA G2 ECDSA
	//         Issuer: CN=ROOT CA G2 ECDSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA ECDSA
	//           Subject: CN=Intermediate CA ECDSA
	//           Issuer: CN=ROOT CA G2 ECDSA
	//           Expiration: 2031-02-22 18:40:06 +0900
	//         - OK: server-c.test
	//             Subject: CN=server-c.test
	//             Issuer: CN=Intermediate CA ECDSA
	//             Expiration: 2022-02-21 18:40:06 +0900
	//
	// CN=ROOT CA G2 ECDSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	// CN=Intermediate CA ECDSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	// CN=server-c.test (Ed25519)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-c-ed25519.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - INFO: ROOT CA G2 RSA
	//         Message: a valid root CA certificate cannot be found, or the certificate chain is broken.
	//       - ERROR: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:04:30 +0900
	//           Error     : x509: certificate signed by unknown authority
	//         - OK: server-a.test
	//             Subject: CN=server-a.test
	//             Issuer: CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 18:04:30 +0900
	//
	// CN=Intermediate CA A RSA (root CA certificate not found)
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	// CN=server-a.test
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, []*x509.Certificate{})
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Equal(checker.INFO, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// CRITICAL: the certificate chain is invalid
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:07:15 +0900
	//         - ERROR: server-a.test
	//             Subject: CN=server-a.test
	//             Issuer: CN=Intermediate CA A RSA
	//             Expiration: 2020-01-01 09:00:00 +0900
	//             Error: the certificate has expired on 2020-01-01 09:00:00 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA RSA
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	// CN=server-a.test (expired)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/expired/server-a-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// CRITICAL: the certificate chain is invalid
	//     - INFO: ROOT CA G2 RSA
	//         Message: a valid root CA certificate cannot be found, or the certificate chain is broken.
	//       - ERROR: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2020-01-01 09:00:00 +0900
	//           Error: the certificate has expired on 2020-01-01 09:00:00 +0900
	//         - OK: CN=server-a.test
	//             Subject: CN=server-a.test
	//             Issuer: CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 18:09:37 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA RSA (expired)
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/expired/ca-intermediate-a-rsa.crt")
	// CN=server-a.test
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains([]checker.Status{checker.OK, checker.INFO}, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// CRITICAL: the certificate chain is invalid
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:11:41 +0900
	//         - ERROR: server-b.test
	//             Subject: CN=server-b.test
	//             Issuer: CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:11:42 +0900
	//             Error: crypto/rsa: verification error
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA A RSA (not an issuer of CN=server-b.test)
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	// CN=server-b.test
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-b-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())

	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-23 09:01:04 +0900
	//
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=server-a.test (RSA) (specified file not correct)
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	// CN=Intermediate CA A RSA (specified file not correct)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())

	// An old-generation root CA Certificate and a cross-signing root CA Certificate
	//
	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G1 RSA
	//         Subject: CN=ROOT CA G1 RSA
	//         Issuer: CN=ROOT CA G1 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: ROOT CA G2 RSA
	//           Subject: CN=ROOT CA G2 RSA
	//           Issuer: CN=ROOT CA G1 RSA
	//           Expiration: 2035-01-01 09:00:00 +0900
	//         - OK: Intermediate CA A RSA
	//             Subject: CN=Intermediate CA A RSA
	//             Issuer: CN=ROOT CA G2 RSA
	//             Expiration: 2031-02-22 17:52:57 +0900
	//           - OK: server-a.test
	//               Subject: CN=server-a.test
	//               Issuer: CN=Intermediate CA A RSA
	//               Expiration: 2022-02-21 17:52:57 +0900
	// CN=ROOT CA G1 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g1-rsa.crt")
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA (cross-signing)
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa-cross.crt")
	// CN=server-a.test
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][3].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][3].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][3].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][3].Certificate.Issuer.String())

	// An old-generation root CA Certificate and a cross-signing root CA Certificate
	//
	// OK: The certificate chain is valid.
	//     - OK: ROOT CA G2 RSA
	//         Subject: CN=ROOT CA G2 RSA
	//         Issuer: CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject: CN=Intermediate CA A RSA
	//           Issuer: CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 17:52:57 +0900
	//         - OK: server-a.test
	//             Subject: CN=server-a.test
	//             Issuer: CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 17:52:57 +0900
	//     - OK: ROOT CA G1 RSA
	//         Subject: CN=ROOT CA G1 RSA
	//         Issuer: CN=ROOT CA G1 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: ROOT CA G2 RSA
	//           Subject: CN=ROOT CA G2 RSA
	//           Issuer: CN=ROOT CA G1 RSA
	//           Expiration: 2035-01-01 09:00:00 +0900
	//         - OK: Intermediate CA A RSA
	//             Subject: CN=Intermediate CA A RSA
	//             Issuer: CN=ROOT CA G2 RSA
	//             Expiration: 2031-02-22 17:52:57 +0900
	//           - OK: server-a.test
	//               Subject: CN=server-a.test
	//               Issuer: CN=Intermediate CA A RSA
	//               Expiration: 2022-02-21 17:52:57 +0900
	//
	// CN=ROOT CA G1 RSA
	// CN=ROOT CA G2 RSA
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g1-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA (cross-signing)
	intermediateCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa-cross.crt")
	// CN=server-a.test
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	state = checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts)
	assert.Equal(checker.OK, state.Status)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][0].Status)
	assert.Equal("ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][0].CommonName)
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][1].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[1][1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[1][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][2].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[1][2].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[1][2].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[1][2].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][3].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[1][3].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[1][3].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[1][3].Certificate.Issuer.String())

}
