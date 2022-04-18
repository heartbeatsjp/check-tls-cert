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

func TestNewCertificateChainChecker(t *testing.T) {
	var (
		c            checker.Checker
		certs        []*x509.Certificate
		rootCerts    []*x509.Certificate
		rootCertPool *x509.CertPool
		chains       [][]checker.CertificateInfo
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

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
	c = checker.NewCertificateChainChecker(certs, rootCertPool)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	c.PrintDetails()
	chains = c.Details().(checker.CertificateChainDetails)

	assert.Equal(checker.OK, chains[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", chains[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Issuer)
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, chains[0][1].Status)
	assert.Equal("Intermediate CA A RSA", chains[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Issuer)
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, chains[0][2].Status)
	assert.Equal("server-a.test", chains[0][2].CommonName)
	assert.Equal("CN=server-a.test", chains[0][2].Subject)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][2].Issuer)
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
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
	c = checker.NewCertificateChainChecker(certs, rootCertPool)
	chains = c.Details().(checker.CertificateChainDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.OK, chains[0][0].Status)
	assert.Equal("ROOT CA G1 RSA", chains[0][0].CommonName)
	assert.Equal("CN=ROOT CA G1 RSA", chains[0][0].Subject)
	assert.Equal("CN=ROOT CA G1 RSA", chains[0][0].Issuer)
	assert.Equal(checker.OK, chains[0][1].Status)
	assert.Contains(w.String(), `    - OK: ROOT CA G1 RSA
        Subject   : CN=ROOT CA G1 RSA
        Issuer    : CN=ROOT CA G1 RSA
        Expiration: `)

	assert.Equal("ROOT CA G2 RSA", chains[0][1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G1 RSA", chains[0][1].Issuer)
	assert.Equal(checker.OK, chains[0][2].Status)
	assert.Contains(w.String(), `      - OK: ROOT CA G2 RSA
          Subject   : CN=ROOT CA G2 RSA
          Issuer    : CN=ROOT CA G1 RSA
          Expiration: `)

	assert.Equal("Intermediate CA A RSA", chains[0][2].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][2].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Issuer)
	assert.Contains(w.String(), `        - OK: Intermediate CA A RSA
            Subject   : CN=Intermediate CA A RSA
            Issuer    : CN=ROOT CA G2 RSA
            Expiration: `)

	assert.Equal(checker.OK, chains[0][3].Status)
	assert.Equal("server-a.test", chains[0][3].CommonName)
	assert.Equal("CN=server-a.test", chains[0][3].Subject)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][3].Issuer)
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
	c = checker.NewCertificateChainChecker(certs, rootCertPool)
	chains = c.Details().(checker.CertificateChainDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.OK, chains[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", chains[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Issuer)
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, chains[0][1].Status)
	assert.Equal("Intermediate CA A RSA", chains[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Issuer)
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, chains[0][2].Status)
	assert.Equal("server-a.test", chains[0][2].CommonName)
	assert.Equal("CN=server-a.test", chains[0][2].Subject)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][2].Issuer)
	assert.Contains(w.String(), `        - OK: server-a.test
            Subject   : CN=server-a.test
            Issuer    : CN=Intermediate CA A RSA
            Expiration: `)

	assert.Equal(checker.OK, chains[1][0].Status)
	assert.Equal("ROOT CA G1 RSA", chains[1][0].CommonName)
	assert.Equal("CN=ROOT CA G1 RSA", chains[1][0].Subject)
	assert.Equal("CN=ROOT CA G1 RSA", chains[1][0].Issuer)
	assert.Contains(w.String(), `    - OK: ROOT CA G1 RSA
        Subject   : CN=ROOT CA G1 RSA
        Issuer    : CN=ROOT CA G1 RSA
        Expiration: `)

	assert.Equal(checker.OK, chains[1][1].Status)
	assert.Equal("ROOT CA G2 RSA", chains[1][1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", chains[1][1].Subject)
	assert.Equal("CN=ROOT CA G1 RSA", chains[1][1].Issuer)
	assert.Equal(checker.OK, chains[1][2].Status)
	assert.Contains(w.String(), `      - OK: ROOT CA G2 RSA
          Subject   : CN=ROOT CA G2 RSA
          Issuer    : CN=ROOT CA G1 RSA
          Expiration: `)

	assert.Equal("Intermediate CA A RSA", chains[1][2].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[1][2].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[1][2].Issuer)
	assert.Contains(w.String(), `        - OK: Intermediate CA A RSA
            Subject   : CN=Intermediate CA A RSA
            Issuer    : CN=ROOT CA G2 RSA
            Expiration: `)

	assert.Equal(checker.OK, chains[1][3].Status)
	assert.Equal("server-a.test", chains[1][3].CommonName)
	assert.Equal("CN=server-a.test", chains[1][3].Subject)
	assert.Equal("CN=Intermediate CA A RSA", chains[1][3].Issuer)
	assert.Contains(w.String(), `          - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
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
	c = checker.NewCertificateChainChecker(certs, nil)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	c.PrintDetails()
	chains = c.Details().(checker.CertificateChainDetails)

	assert.Equal(checker.INFO, chains[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", chains[0][0].CommonName)
	assert.Contains(w.String(), `    - INFO: ROOT CA G2 RSA
        Message   : a valid root certificate cannot be found, or the certificate chain is broken`)

	assert.Equal(checker.ERROR, chains[0][1].Status)
	assert.Equal("Intermediate CA A RSA", chains[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Issuer)
	assert.Contains(w.String(), `      - ERROR: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, chains[0][2].Status)
	assert.Equal("server-a.test", chains[0][2].CommonName)
	assert.Equal("CN=server-a.test", chains[0][2].Subject)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][2].Issuer)
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
	c = checker.NewCertificateChainChecker(certs, rootCertPool)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	c.PrintDetails()
	chains = c.Details().(checker.CertificateChainDetails)

	assert.Equal(checker.OK, chains[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", chains[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Issuer)
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, chains[0][1].Status)
	assert.Equal("Intermediate CA A RSA", chains[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Issuer)
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.ERROR, chains[0][2].Status)
	assert.Equal("server-a.test", chains[0][2].CommonName)
	assert.Equal("CN=server-a.test", chains[0][2].Subject)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][2].Issuer)
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
	c = checker.NewCertificateChainChecker(certs, rootCertPool)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	c.PrintDetails()
	chains = c.Details().(checker.CertificateChainDetails)

	assert.Contains([]checker.Status{checker.OK, checker.INFO}, chains[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", chains[0][0].CommonName)
	assert.Contains(w.String(), `    - INFO: ROOT CA G2 RSA
        Message   : a valid root certificate cannot be found, or the certificate chain is broken`)

	assert.Equal(checker.ERROR, chains[0][1].Status)
	assert.Equal("Intermediate CA A RSA", chains[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Issuer)
	assert.Contains(w.String(), `      - ERROR: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.OK, chains[0][2].Status)
	assert.Equal("server-a.test", chains[0][2].CommonName)
	assert.Equal("CN=server-a.test", chains[0][2].Subject)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][2].Issuer)
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
	c = checker.NewCertificateChainChecker(certs, rootCertPool)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the certificate chain is invalid")

	w.Reset()
	c.PrintDetails()
	chains = c.Details().(checker.CertificateChainDetails)

	assert.Equal(checker.OK, chains[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", chains[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Issuer)
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, chains[0][1].Status)
	assert.Equal("Intermediate CA A RSA", chains[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Issuer)
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

	assert.Equal(checker.ERROR, chains[0][2].Status)
	assert.Equal("server-b.test", chains[0][2].CommonName)
	assert.Equal("CN=server-b.test", chains[0][2].Subject)
	assert.Equal("CN=Intermediate CA B RSA", chains[0][2].Issuer)
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
	c = checker.NewCertificateChainChecker(certs, rootCertPool)
	chains = c.Details().(checker.CertificateChainDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: the certificate chain is valid")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.OK, chains[0][0].Status)
	assert.Equal("ROOT CA G2 RSA", chains[0][0].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][0].Issuer)
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	assert.Equal(checker.OK, chains[0][1].Status)
	assert.Equal("Intermediate CA A RSA", chains[0][1].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject)
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Issuer)
	assert.Contains(w.String(), `      - OK: Intermediate CA A RSA
          Subject   : CN=Intermediate CA A RSA
          Issuer    : CN=ROOT CA G2 RSA
          Expiration: `)

}

func TestCertificateChainChecker(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	certs, _ := x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ := x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ := x509util.GetRootCertPool(rootCerts, false)
	c := checker.NewCertificateChainChecker(certs, rootCertPool)
	assert.Equal("Certificate Chains", c.Name())
	assert.Equal(checker.OK, c.Status())
	assert.Equal("the certificate chain is valid", c.Message())
	assert.Equal("ROOT CA G2 RSA", c.Details().(checker.CertificateChainDetails)[0][0].CommonName)

	c.PrintName()
	assert.Equal("[Certificate Chains]\n", w.String())

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Equal("OK: the certificate chain is valid\n", w.String())

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    - OK: ROOT CA G2 RSA
        Subject   : CN=ROOT CA G2 RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)
}
