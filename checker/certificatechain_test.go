// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckCertificateChain(t *testing.T) {
	var (
		state        checker.State
		certs        []*x509.Certificate
		rootCerts    []*x509.Certificate
		rootCertPool *x509.CertPool
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	// CN=server-a.test (RSA)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 17:09:50 +0900
	//         - OK: server-a.test
	//             Subject   : CN=server-a.test
	//             Issuer    : CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 17:09:50 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	// CN=server-a.test (ECDSA)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:34:38 +0900
	//         - OK: server-a.test
	//             Subject   : CN=server-a.test
	//             Issuer    : CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 18:34:38 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-ecdsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	// CN=server-a.test (Ed25519)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 17:09:50 +0900
	//         - OK: server-a.test
	//             Subject   : CN=server-a.test
	//             Issuer    : CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 17:09:50 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-ed25519.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	// CN=server-b.test (RSA)
	// CN=Intermediate CA B RSA
	// CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA B RSA
	//           Subject   : CN=Intermediate CA B RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:50:48 +0900
	//         - OK: server-b.test
	//             Subject   : CN=server-b.test
	//             Issuer    : CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:50:48 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA B RSA
          Subject   : CN=Intermediate CA B RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-b.test
            Subject   : CN=server-b.test
            Issuer    : CN=Intermediate CA B RSA
            Expiration: `)

	// CN=server-b.test (ECDSA)
	// CN=Intermediate CA B RSA
	// CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA B RSA
	//           Subject   : CN=Intermediate CA B RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:50:48 +0900
	//         - OK: server-b.test
	//             Subject   : CN=server-b.test
	//             Issuer    : CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:50:48 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-ecdsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA B RSA
          Subject   : CN=Intermediate CA B RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-b.test
            Subject   : CN=server-b.test
            Issuer    : CN=Intermediate CA B RSA
            Expiration: `)

	// CN=server-b.test (Ed25519)
	// CN=Intermediate CA B RSA
	// CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA B RSA
	//           Subject   : CN=Intermediate CA B RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:50:48 +0900
	//         - OK: server-b.test
	//             Subject   : CN=server-b.test
	//             Issuer    : CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:50:48 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-ed25519.crt", "../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA B RSA
          Subject   : CN=Intermediate CA B RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-b.test
            Subject   : CN=server-b.test
            Issuer    : CN=Intermediate CA B RSA
            Expiration: `)

	// CN=server-c.test (RSA)
	// CN=Intermediate CA ECDSA
	// CN=ROOT CA G2 ECDSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 ECDSA
	//         Subject   : CN=ROOT CA G2 ECDSA
	//         Issuer    : CN=ROOT CA G2 ECDSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA ECDSA
	//           Subject   : CN=Intermediate CA ECDSA
	//           Issuer    : CN=ROOT CA G2 ECDSA
	//           Expiration: 2031-02-22 18:40:06 +0900
	//         - OK: server-c.test
	//             Subject   : CN=server-c.test
	//             Issuer    : CN=Intermediate CA ECDSA
	//             Expiration: 2022-02-21 18:40:06 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-c-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 ECDSA
        Subject   : CN=ROOT CA G2 ECDSA
        Issuer    : CN=ROOT CA G2 ECDSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA ECDSA
          Subject   : CN=Intermediate CA ECDSA
          Issuer    : CN=ROOT CA G2 ECDSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-c.test
            Subject   : CN=server-c.test
            Issuer    : CN=Intermediate CA ECDSA
            Expiration: `)

	// CN=server-c.test (ECDSA)
	// CN=Intermediate CA ECDSA
	// CN=ROOT CA G2 ECDSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 ECDSA
	//         Subject   : CN=ROOT CA G2 ECDSA
	//         Issuer    : CN=ROOT CA G2 ECDSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA ECDSA
	//           Subject   : CN=Intermediate CA ECDSA
	//           Issuer    : CN=ROOT CA G2 ECDSA
	//           Expiration: 2031-02-22 18:40:06 +0900
	//         - OK: server-c.test
	//             Subject   : CN=server-c.test
	//             Issuer    : CN=Intermediate CA ECDSA
	//             Expiration: 2022-02-21 18:40:06 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-c-ecdsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 ECDSA
        Subject   : CN=ROOT CA G2 ECDSA
        Issuer    : CN=ROOT CA G2 ECDSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA ECDSA
          Subject   : CN=Intermediate CA ECDSA
          Issuer    : CN=ROOT CA G2 ECDSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-c.test
            Subject   : CN=server-c.test
            Issuer    : CN=Intermediate CA ECDSA
            Expiration: `)

	// CN=server-c.test (Ed25519)
	// CN=Intermediate CA ECDSA
	// CN=ROOT CA G2 ECDSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 ECDSA
	//         Subject   : CN=ROOT CA G2 ECDSA
	//         Issuer    : CN=ROOT CA G2 ECDSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA ECDSA
	//           Subject   : CN=Intermediate CA ECDSA
	//           Issuer    : CN=ROOT CA G2 ECDSA
	//           Expiration: 2031-02-22 18:40:06 +0900
	//         - OK: server-c.test
	//             Subject   : CN=server-c.test
	//             Issuer    : CN=Intermediate CA ECDSA
	//             Expiration: 2022-02-21 18:40:06 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-c-ed25519.crt", "../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 ECDSA
        Subject   : CN=ROOT CA G2 ECDSA
        Issuer    : CN=ROOT CA G2 ECDSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA ECDSA
          Subject   : CN=Intermediate CA ECDSA
          Issuer    : CN=ROOT CA G2 ECDSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-c.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-c.test
            Subject   : CN=server-c.test
            Issuer    : CN=Intermediate CA ECDSA
            Expiration: `)

	// CN=server-a.test
	// CN=Intermediate CA A RSA (root CA certificate not found)
	//
	// CRITICAL: the certificate chain is invalid / x509: certificate signed by unknown authority
	//     - INFO: ROOT CA G2 RSA
	//         Message   : a valid root CA certificate cannot be found, or the certificate chain is broken
	//       - ERROR: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:04:30 +0900
	//           Error     : x509: certificate signed by unknown authority
	//         - OK: server-a.test
	//             Subject   : CN=server-a.test
	//             Issuer    : CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 18:04:30 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	state = checker.CheckCertificateChain(certs, nil)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.INFO, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Contains(w.String(), `    - INFO: ROOT CA G2 RSA
        Message   : a valid root certificate cannot be found, or the certificate chain is broken`)

	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - ERROR: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	// CN=server-a.test (expired)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	//
	// CRITICAL: the certificate chain is invalid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:07:15 +0900
	//         - ERROR: server-a.test
	//             Subject   : CN=server-a.test
	//             Issuer    : CN=Intermediate CA A RSA
	//             Expiration: 2020-01-01 09:00:00 +0900
	//             Error     : the certificate has expired on 2020-01-01 09:00:00 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/expired/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - ERROR: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	// CN=server-a.test
	// CN=Intermediate CA A RSA (expired)
	// CN=ROOT CA G2 RSA
	//
	// CRITICAL: the certificate chain is invalid / x509: certificate has expired or is not yet valid: current time 2021-06-22T10:15:58+09:00 is after 2020-01-01T00:00:00Z
	//     - INFO: ROOT CA G2 RSA
	//         Message   : a valid root certificate cannot be found, or the certificate chain is broken
	//       - ERROR: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2020-01-01 09:00:00 +0900
	//           Error     : x509: certificate signed by unknown authority / the certificate has expired on 2020-01-01 09:00:00 +0900
	//         - OK: CN=server-a.test
	//             Subject   : CN=server-a.test
	//             Issuer    : CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 18:09:37 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/expired/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Contains([]checker.Status{checker.OK, checker.INFO}, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Contains(w.String(), `    - INFO: ROOT CA G2 RSA
        Message   : a valid root certificate cannot be found, or the certificate chain is broken`)

	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - ERROR: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	// CN=server-b.test
	// CN=Intermediate CA A RSA (not an issuer of CN=server-b.test)
	// CN=ROOT CA G2 RSA
	//
	// CRITICAL: the certificate chain is invalid / x509: certificate signed by unknown authority
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 18:11:41 +0900
	//         - ERROR: server-b.test
	//             Subject   : CN=server-b.test
	//             Issuer    : CN=Intermediate CA B RSA
	//             Expiration: 2022-02-21 18:11:42 +0900
	//             Error     : crypto/rsa: verification error / parent certificate may not be correct issuer
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.ERROR, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-b.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - ERROR: server-b.test
            Subject   : CN=server-b.test
            Issuer    : CN=Intermediate CA B RSA
            Expiration: `)

	// CN=Intermediate CA A RSA (specified file not correct)
	// CN=server-a.test (RSA) (specified file not correct)
	// CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-23 09:01:04 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/cert/valid/server-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	// An old-generation root CA Certificate and a cross-signing root CA Certificate
	//
	// CN=server-a.test
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA (cross-signing)
	// CN=ROOT CA G1 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G1 RSA
	//         Subject   : CN=ROOT CA G1 RSA
	//         Issuer    : CN=ROOT CA G1 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: ROOT CA G2 RSA
	//           Subject   : CN=ROOT CA G2 RSA
	//           Issuer    : CN=ROOT CA G1 RSA
	//           Expiration: 2035-01-01 09:00:00 +0900
	//         - OK: Intermediate CA A RSA
	//             Subject   : CN=Intermediate CA A RSA
	//             Issuer    : CN=ROOT CA G2 RSA
	//             Expiration: 2031-02-22 17:52:57 +0900
	//           - OK: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2022-02-21 17:52:57 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa-cross.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g1-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Contains(w.String(), `    - OK: ROOT CA G1 RSA
        Subject   : CN=ROOT CA G1 RSA
        Issuer    : CN=ROOT CA G1 RSA
        Expiration: `)

	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Contains(w.String(), `      - OK: ROOT CA G2 RSA
          Subject   : CN=ROOT CA G2 RSA
          Issuer    : CN=ROOT CA G1 RSA
          Expiration: `)

	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: Intermediate CA A RSA
            Subject   : CN=Intermediate CA A RSA
            Issuer    : CN=ROOT CA G2 RSA
            Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][3].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][3].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][3].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][3].Certificate.Issuer.String())
	assert.Contains(w.String(), `          - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	// An old-generation root CA Certificate and a cross-signing root CA Certificate
	//
	// CN=server-a.test
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA (cross-signing)
	// CN=ROOT CA G1 RSA, CN=ROOT CA G2 RSA
	//
	// OK: the certificate chain is valid
	//     - OK: ROOT CA G2 RSA
	//         Subject   : CN=ROOT CA G2 RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: Intermediate CA A RSA
	//           Subject   : CN=Intermediate CA A RSA
	//           Issuer    : CN=ROOT CA G2 RSA
	//           Expiration: 2031-02-22 17:52:57 +0900
	//         - OK: server-a.test
	//             Subject   : CN=server-a.test
	//             Issuer    : CN=Intermediate CA A RSA
	//             Expiration: 2022-02-21 17:52:57 +0900
	//     - OK: ROOT CA G1 RSA
	//         Subject   : CN=ROOT CA G1 RSA
	//         Issuer    : CN=ROOT CA G1 RSA
	//         Expiration: 2035-01-01 09:00:00 +0900
	//       - OK: ROOT CA G2 RSA
	//           Subject   : CN=ROOT CA G2 RSA
	//           Issuer    : CN=ROOT CA G1 RSA
	//           Expiration: 2035-01-01 09:00:00 +0900
	//         - OK: Intermediate CA A RSA
	//             Subject   : CN=Intermediate CA A RSA
	//             Issuer    : CN=ROOT CA G2 RSA
	//             Expiration: 2031-02-22 17:52:57 +0900
	//           - OK: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2022-02-21 17:52:57 +0900
	//
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa-cross.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g1-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	state = checker.CheckCertificateChain(certs, rootCertPool)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][1].Status)
	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[0][1].Certificate.Issuer.String())
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[0][2].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[0][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][0].Status)
	assert.Equal("ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][0].CommonName)
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][0].Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: ROOT CA G1 RSA
        Subject   : CN=ROOT CA G1 RSA
        Issuer    : CN=ROOT CA G1 RSA
        Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][1].Status)
	assert.Equal("ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[1][1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[1][1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([][]checker.CertificateInfo)[1][1].Certificate.Issuer.String())
	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][2].Status)
	assert.Contains(w.String(), `      - OK: ROOT CA G2 RSA
          Subject   : CN=ROOT CA G2 RSA
          Issuer    : CN=ROOT CA G1 RSA
          Expiration: `)

	assert.Equal("Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[1][2].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[1][2].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([][]checker.CertificateInfo)[1][2].Certificate.Issuer.String())
	assert.Contains(w.String(), `        - OK: Intermediate CA A RSA
            Subject   : CN=Intermediate CA A RSA
            Issuer    : CN=ROOT CA G2 RSA
            Expiration: `)

	assert.Equal(checker.OK, state.Data.([][]checker.CertificateInfo)[1][3].Status)
	assert.Equal("server-a.test", state.Data.([][]checker.CertificateInfo)[1][3].CommonName)
	assert.Equal("CN=server-a.test", state.Data.([][]checker.CertificateInfo)[1][3].Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([][]checker.CertificateInfo)[1][3].Certificate.Issuer.String())
	assert.Contains(w.String(), `          - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

}
