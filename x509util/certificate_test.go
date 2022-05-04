// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestParseCertificateFiles(t *testing.T) {
	var (
		serverCertFile, chainCertFile, keyFile string
		certs                                  []*x509.Certificate
		err                                    error
	)
	assert := assert.New(t)

	keyFile = "../test/testdata/pki/private/server-a-rsa.key"
	chainCertFile = "../test/testdata/pki/chain/chain-a-rsa.pem"

	// non-existent file
	serverCertFile = "../test/testdata/pki/misc/non-existent.crt"
	_, err = x509util.ParseCertificateFiles(serverCertFile)
	assert.NotNil(err)

	// empty file
	serverCertFile = "../test/testdata/pki/misc/empty.crt"
	_, err = x509util.ParseCertificateFiles(serverCertFile)
	assert.NotNil(err)

	// invalid format file
	serverCertFile = "../test/testdata/pki/private/server-a-rsa.key"
	_, err = x509util.ParseCertificateFiles(serverCertFile)
	assert.NotNil(err)

	// valid file (PEM)
	serverCertFile = "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, err = x509util.ParseCertificateFiles(serverCertFile)
	assert.Nil(err)
	assert.Equal(1, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())

	// valid file (DER)
	serverCertFile = "../test/testdata/pki/cert/valid/server-a-rsa-der.crt"
	certs, err = x509util.ParseCertificateFiles(serverCertFile)
	assert.Nil(err)
	assert.Equal(1, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())

	// valid file with chain certificate file
	certs, err = x509util.ParseCertificateFiles(serverCertFile, chainCertFile)
	assert.Nil(err)
	assert.Equal(2, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certs[1].Subject.String())

	// mixed file with certificates and private key
	certs, err = x509util.ParseCertificateFiles(serverCertFile, chainCertFile, keyFile)
	assert.Nil(err)
	assert.Equal(2, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certs[1].Subject.String())

	// no EOL
	serverCertFile = "../test/testdata/pki/cert/valid/misc-no-eol.crt"
	certs, err = x509util.ParseCertificateFiles(serverCertFile, chainCertFile)
	assert.Nil(err)
	assert.Equal(2, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certs[1].Subject.String())

	// Explanatory Text
	serverCertFile = "../test/testdata/pki/cert/valid/misc-explanatory-text.crt"
	certs, err = x509util.ParseCertificateFiles(serverCertFile, chainCertFile)
	assert.Nil(err)
	assert.Equal(2, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certs[1].Subject.String())

}

func TestParseCertificateFile(t *testing.T) {
	var (
		serverCertFile string
		cert           *x509.Certificate
		err            error
	)
	assert := assert.New(t)

	// non-existent file
	serverCertFile = "../test/testdata/pki/misc/non-existent.crt"
	_, err = x509util.ParseCertificateFile(serverCertFile)
	assert.NotNil(err)

	// empty file
	serverCertFile = "../test/testdata/pki/misc/empty.crt"
	_, err = x509util.ParseCertificateFile(serverCertFile)
	assert.NotNil(err)

	// invalid format file
	serverCertFile = "../test/testdata/pki/private/server-a-rsa.key"
	_, err = x509util.ParseCertificateFile(serverCertFile)
	assert.NotNil(err, "file should not be a certificate: %s", serverCertFile)

	// valid file (PEM)
	serverCertFile = "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	cert, err = x509util.ParseCertificateFile(serverCertFile)
	assert.Nil(err)
	assert.Equal("CN=server-a.test", cert.Subject.String())

	// valid file (DER)
	serverCertFile = "../test/testdata/pki/cert/valid/server-a-rsa-der.crt"
	cert, err = x509util.ParseCertificateFile(serverCertFile)
	assert.Nil(err)
	assert.Equal("CN=server-a.test", cert.Subject.String())

	// no EOL
	serverCertFile = "../test/testdata/pki/cert/valid/misc-no-eol.crt"
	cert, err = x509util.ParseCertificateFile(serverCertFile)
	assert.Nil(err)
	assert.Equal("CN=server-a.test", cert.Subject.String())

	// Explanatory Text
	serverCertFile = "../test/testdata/pki/cert/valid/misc-explanatory-text.crt"
	cert, err = x509util.ParseCertificateFile(serverCertFile)
	assert.Nil(err)
	assert.Equal("CN=server-a.test", cert.Subject.String())
}

func TestVerifyValidity(t *testing.T) {
	var (
		message string
		err     error
	)
	assert := assert.New(t)
	currentTime := time.Now()

	// This certificate will expire in 365 days.
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	// This certificate has expired.
	expiredCertFile := "../test/testdata/pki/cert/expired/server-a-rsa.crt"
	expiredCerts, _ := x509util.ParseCertificateFiles(expiredCertFile)
	expiredCert := expiredCerts[0]

	// This certificate is not yet valid.
	notYetValidCertFile := "../test/testdata/pki/cert/notyetvalid/server-a-rsa.crt"
	notYetValidCerts, _ := x509util.ParseCertificateFiles(notYetValidCertFile)
	notYetValidCert := notYetValidCerts[0]

	// the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	message, err = x509util.VerifyValidity(cert, 0, currentTime)
	assert.Nil(err)
	assert.Contains(message, "the certificate will expire in ")

	// the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	message, err = x509util.VerifyValidity(cert, 28, currentTime)
	assert.Nil(err)
	assert.Contains(message, "the certificate will expire in ")

	// the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	_, err = x509util.VerifyValidity(cert, 366, currentTime)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate will expire in ")

	// the certificate has expired on 2020-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(expiredCert, 0, currentTime)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate has expired on ")

	// the certificate has expired on 2020-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(expiredCert, 10000, currentTime)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate has expired on ")

	// the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(notYetValidCert, 0, currentTime)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate is not yet valid and will be valid on ")

	// the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(notYetValidCert, 10000, currentTime)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate is not yet valid and will be valid on ")
}

func TestGetRootCertPoolAndGetIntermediateCertPool(t *testing.T) {
	var (
		roots         *x509.CertPool
		intermediates *x509.CertPool
		chains        [][]*x509.Certificate
		err           error
	)
	assert := assert.New(t)
	currentTime := time.Now()

	rootCertFile := "../test/testdata/pki/root-ca/ca-root-g2-rsa.crt"
	intermediateCertFile := "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt"
	serverCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"

	rootCerts, _ := x509util.ParseCertificateFiles(rootCertFile)
	intermediateCerts, _ := x509util.ParseCertificateFiles(intermediateCertFile)
	serverCert, _ := x509util.ParseCertificateFile(serverCertFile)

	roots, err = x509util.GetRootCertPool(rootCerts, false)
	assert.Nil(err)
	intermediates = x509util.GetIntermediateCertPool(intermediateCerts)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
	}
	chains, err = serverCert.Verify(opts)
	assert.Nil(err)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())
}

func TestBuildCertificateChains(t *testing.T) {
	var (
		certs        []*x509.Certificate
		rootCerts    []*x509.Certificate
		rootCertPool *x509.CertPool
		chains       [][]*x509.Certificate
	)
	assert := assert.New(t)
	currentTime := time.Now()

	// CN=server-a.test (RSA)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=server-a.test (ECDSA)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-ecdsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=server-a.test (Ed25519)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-ed25519.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=server-b.test (RSA)
	// CN=Intermediate CA B RSA
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-b.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=server-b.test (ECDSA)
	// CN=Intermediate CA B RSA
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-ecdsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-b.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=server-b.test (Ed25519)
	// CN=Intermediate CA B RSA
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-ed25519.crt", "../test/testdata/pki/cert/valid/ca-intermediate-b-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-b.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=server-c.test (RSA)
	// CN=Intermediate CA ECDSA
	// CN=ROOT CA G2 ECDSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-c-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-c.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", chains[0][2].Subject.String())

	// CN=server-c.test (ECDSA)
	// CN=Intermediate CA ECDSA
	// CN=ROOT CA G2 ECDSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-c-ecdsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-c.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", chains[0][2].Subject.String())

	// CN=server-c.test (Ed25519)
	// CN=Intermediate CA ECDSA
	// CN=ROOT CA G2 ECDSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-c-ed25519.crt", "../test/testdata/pki/cert/valid/ca-intermediate-ecdsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-ecdsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-c.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA ECDSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", chains[0][2].Subject.String())

	// CN=server-a.test
	// CN=Intermediate CA A RSA (root CA certificate not found)
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	chains = x509util.BuildCertificateChains(certs, nil, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())

	// CN=server-a.test (expired)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/expired/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=server-a.test
	// CN=Intermediate CA A RSA (expired)
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/expired/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())

	// CN=server-b.test
	// CN=Intermediate CA A RSA (not an issuer of CN=server-b.test)
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-b.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())

	// CN=Intermediate CA A RSA (specified file not correct)
	// CN=server-a.test (RSA) (specified file not correct)
	// CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/cert/valid/server-a-rsa.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=Intermediate CA A RSA", chains[0][0].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][1].Subject.String())

	// An old-generation root CA Certificate and a cross-signing root CA Certificate
	//
	// CN=server-a.test
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA (cross-signing)
	// CN=ROOT CA G1 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa-cross.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g1-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", chains[0][3].Subject.String())

	// An old-generation root CA Certificate and a cross-signing root CA Certificate
	//
	// CN=server-a.test
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA (cross-signing)
	// CN=ROOT CA G1 RSA, CN=ROOT CA G2 RSA
	certs, _ = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa-cross.crt")
	rootCerts, _ = x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root-g1-rsa.crt", "../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	rootCertPool, _ = x509util.GetRootCertPool(rootCerts, false)
	chains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
	assert.Equal("CN=server-a.test", chains[0][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[0][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[0][2].Subject.String())
	assert.Equal("CN=server-a.test", chains[1][0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", chains[1][1].Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", chains[1][2].Subject.String())
	assert.Equal("CN=ROOT CA G1 RSA", chains[1][3].Subject.String())
}

func TestVerifyCertificate(t *testing.T) {
	var (
		serverCert       *x509.Certificate
		intermediateCert *x509.Certificate
		rootCert         *x509.Certificate
		err              error
	)
	assert := assert.New(t)
	currentTime := time.Now()

	// CN=server-a.test (RSA)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	intermediateCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	err = x509util.VerifyCertificate(serverCert, intermediateCert, currentTime, false)
	assert.Nil(err)
	err = x509util.VerifyCertificate(intermediateCert, rootCert, currentTime, false)
	assert.Nil(err)
	err = x509util.VerifyCertificate(rootCert, nil, currentTime, false)
	assert.Nil(err)
	err = x509util.VerifyCertificate(rootCert, nil, currentTime, true)
	assert.Nil(err)

	// CN=server-a.test
	// CN=Intermediate CA A RSA (root CA certificate not found)
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	intermediateCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	err = x509util.VerifyCertificate(serverCert, intermediateCert, currentTime, false)
	assert.Nil(err)
	err = x509util.VerifyCertificate(intermediateCert, nil, currentTime, false)
	assert.Nil(err)
	err = x509util.VerifyCertificate(intermediateCert, nil, currentTime, true)
	assert.NotNil(err)
	assert.ErrorContains(err, "x509: certificate signed by unknown authority")

	// CN=server-a.test (expired)
	// CN=Intermediate CA A RSA
	// CN=ROOT CA G2 RSA
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/expired/server-a-rsa.crt")
	intermediateCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	err = x509util.VerifyCertificate(serverCert, intermediateCert, currentTime, false)
	assert.NotNil(err)
	assert.ErrorContains(err, "the certificate has expired on ")
	err = x509util.VerifyCertificate(intermediateCert, rootCert, currentTime, false)
	assert.Nil(err)

	// CN=server-a.test
	// CN=Intermediate CA A RSA (expired)
	// CN=ROOT CA G2 RSA
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	intermediateCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/expired/ca-intermediate-a-rsa.crt")
	rootCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	err = x509util.VerifyCertificate(serverCert, intermediateCert, currentTime, false)
	assert.Nil(err)
	err = x509util.VerifyCertificate(intermediateCert, rootCert, currentTime, false)
	assert.NotNil(err)
	assert.ErrorContains(err, "the certificate has expired on ")

	// CN=server-b.test
	// CN=Intermediate CA A RSA (not an issuer of CN=server-b.test)
	// CN=ROOT CA G2 RSA
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-b-rsa.crt")
	intermediateCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	rootCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	err = x509util.VerifyCertificate(serverCert, intermediateCert, currentTime, false)
	assert.NotNil(err)
	assert.ErrorContains(err, "x509: issuer name does not match subject from issuing certificate / crypto/rsa: verification error / parent certificate may not be correct issuer")
	err = x509util.VerifyCertificate(intermediateCert, rootCert, currentTime, false)
	assert.Nil(err)

	// CN=Intermediate CA A RSA (specified file not correct)
	// CN=server-a.test (RSA) (specified file not correct)
	// CN=ROOT CA G2 RSA
	serverCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	intermediateCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	rootCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/root-ca/ca-root-g2-rsa.crt")
	err = x509util.VerifyCertificate(serverCert, intermediateCert, currentTime, false)
	assert.NotNil(err)
	assert.ErrorContains(err, "x509: issuer name does not match subject from issuing certificate / x509: invalid signature: parent certificate cannot sign this kind of certificate / parent certificate may not be correct issuer")
	err = x509util.VerifyCertificate(intermediateCert, rootCert, currentTime, false)
	assert.NotNil(err)
	assert.ErrorContains(err, "x509: issuer name does not match subject from issuing certificate / crypto/rsa: verification error / parent certificate may not be correct issuer")

}

func TestKeyUsageString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("digitalSignature", x509util.KeyUsage(1).String())
	assert.Equal("contentCommitment", x509util.KeyUsage(1<<1).String())
	assert.Equal("keyEncipherment", x509util.KeyUsage(1<<2).String())
	assert.Equal("dataEncipherment", x509util.KeyUsage(1<<3).String())
	assert.Equal("keyAgreement", x509util.KeyUsage(1<<4).String())
	assert.Equal("keyCertSign", x509util.KeyUsage(1<<5).String())
	assert.Equal("cRLSign", x509util.KeyUsage(1<<6).String())
	assert.Equal("encipherOnly", x509util.KeyUsage(1<<7).String())
	assert.Equal("decipherOnly", x509util.KeyUsage(1<<8).String())
	assert.Equal("Unknown Key Usage Bit(9)", x509util.KeyUsage(1<<9).String())
}

func TestKeyUsageMessage(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("Digital Signature", x509util.KeyUsage(1).Message())
	assert.Equal("Content Commitment", x509util.KeyUsage(1<<1).Message())
	assert.Equal("Key Encipherment", x509util.KeyUsage(1<<2).Message())
	assert.Equal("Data Encipherment", x509util.KeyUsage(1<<3).Message())
	assert.Equal("Key Agreement", x509util.KeyUsage(1<<4).Message())
	assert.Equal("Certificate Sign", x509util.KeyUsage(1<<5).Message())
	assert.Equal("CRL Sign", x509util.KeyUsage(1<<6).Message())
	assert.Equal("Encipher Only", x509util.KeyUsage(1<<7).Message())
	assert.Equal("Decipher Only", x509util.KeyUsage(1<<8).Message())
	assert.Equal("Unknown Key Usage Bit(9)", x509util.KeyUsage(1<<9).Message())
}

func TestKeyUsageDecompose(t *testing.T) {
	assert := assert.New(t)

	assert.ElementsMatch([]x509util.KeyUsage{
		x509util.KeyUsageDigitalSignature,
		x509util.KeyUsageContentCommitment,
		x509util.KeyUsageKeyEncipherment,
		x509util.KeyUsageDataEncipherment,
		x509util.KeyUsageKeyAgreement,
		x509util.KeyUsageCertSign,
		x509util.KeyUsageCRLSign,
		x509util.KeyUsageEncipherOnly,
		x509util.KeyUsageDecipherOnly,
	},
		x509util.KeyUsage(1+1<<1+1<<2+1<<3+1<<4+1<<5+1<<6+1<<7+1<<8).Decompose(),
	)
}

func TestExtKeyUsageString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("any", x509util.ExtKeyUsage(0).String())
	assert.Equal("serverAuth", x509util.ExtKeyUsage(1).String())
	assert.Equal("clientAuth", x509util.ExtKeyUsage(2).String())
	assert.Equal("codeSigning", x509util.ExtKeyUsage(3).String())
	assert.Equal("emailProtection", x509util.ExtKeyUsage(4).String())
	assert.Equal("ipsecEndSystem", x509util.ExtKeyUsage(5).String())
	assert.Equal("ipsecTunnel", x509util.ExtKeyUsage(6).String())
	assert.Equal("ipsecUser", x509util.ExtKeyUsage(7).String())
	assert.Equal("timeStamping", x509util.ExtKeyUsage(8).String())
	assert.Equal("OCSPSigning", x509util.ExtKeyUsage(9).String())
	assert.Equal("microsoftServerGatedCrypto", x509util.ExtKeyUsage(10).String())
	assert.Equal("netscapeServerGatedCrypto", x509util.ExtKeyUsage(11).String())
	assert.Equal("microsoftCommercialCodeSigning", x509util.ExtKeyUsage(12).String())
	assert.Equal("microsoftKernelCodeSigning", x509util.ExtKeyUsage(13).String())
	assert.Equal("Unknown Extended Key Usage", x509util.ExtKeyUsage(14).String())
}

func TestExtKeyUsageMessage(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("Any", x509util.ExtKeyUsage(0).Message())
	assert.Equal("TLS Web Server Authentication", x509util.ExtKeyUsage(1).Message())
	assert.Equal("TLS Web Client Authentication", x509util.ExtKeyUsage(2).Message())
	assert.Equal("Code Signing", x509util.ExtKeyUsage(3).Message())
	assert.Equal("E-mail Protection", x509util.ExtKeyUsage(4).Message())
	assert.Equal("IPSec End System", x509util.ExtKeyUsage(5).Message())
	assert.Equal("IPSec Tunnel", x509util.ExtKeyUsage(6).Message())
	assert.Equal("IPSec User", x509util.ExtKeyUsage(7).Message())
	assert.Equal("Time Stamping", x509util.ExtKeyUsage(8).Message())
	assert.Equal("OCSP Signing", x509util.ExtKeyUsage(9).Message())
	assert.Equal("Microsoft Server Gated Crypto", x509util.ExtKeyUsage(10).Message())
	assert.Equal("Netscape Server Gated Crypto", x509util.ExtKeyUsage(11).Message())
	assert.Equal("Microsoft Commercial Code Signing", x509util.ExtKeyUsage(12).Message())
	assert.Equal("Microsoft Kernel Mode Code Signing", x509util.ExtKeyUsage(13).Message())
	assert.Equal("Unknown Extended Key Usage", x509util.ExtKeyUsage(14).Message())
}
