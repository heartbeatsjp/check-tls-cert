// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util_test

import (
	"crypto/x509"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestParseCertificateFiles(t *testing.T) {
	var (
		serverCertFile, chainCertFile string
		certs                         []*x509.Certificate
		err                           error
	)
	assert := assert.New(t)

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

	// valid file
	serverCertFile = "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ = x509util.ParseCertificateFiles(serverCertFile)
	assert.Equal(1, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())

	// valid file with chain certificate file
	certs, _ = x509util.ParseCertificateFiles(serverCertFile, chainCertFile)
	assert.Equal(2, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certs[1].Subject.String())

	// no EOL
	serverCertFile = "../test/testdata/pki/cert/valid/misc-no-eol.crt"
	certs, _ = x509util.ParseCertificateFiles(serverCertFile, chainCertFile)
	assert.Equal(2, len(certs))
	assert.Equal("CN=server-a.test", certs[0].Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certs[1].Subject.String())

	// Explanatory Text
	serverCertFile = "../test/testdata/pki/cert/valid/misc-explanatory-text.crt"
	certs, _ = x509util.ParseCertificateFiles(serverCertFile, chainCertFile)
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

	// valid file
	serverCertFile = "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	cert, _ = x509util.ParseCertificateFile(serverCertFile)
	assert.Equal("CN=server-a.test", cert.Subject.String())

	// no EOL
	serverCertFile = "../test/testdata/pki/cert/valid/misc-no-eol.crt"
	cert, _ = x509util.ParseCertificateFile(serverCertFile)
	assert.Equal("CN=server-a.test", cert.Subject.String())

	// Explanatory Text
	serverCertFile = "../test/testdata/pki/cert/valid/misc-explanatory-text.crt"
	cert, _ = x509util.ParseCertificateFile(serverCertFile)
	assert.Equal("CN=server-a.test", cert.Subject.String())

}

func TestVerifyValidity(t *testing.T) {
	var (
		message string
		err     error
	)
	assert := assert.New(t)

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
	message, err = x509util.VerifyValidity(cert, 0)
	assert.Nil(err)
	assert.Contains(message, "the certificate will expire in ")

	// the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	message, err = x509util.VerifyValidity(cert, 28)
	assert.Nil(err)
	assert.Contains(message, "the certificate will expire in ")

	// the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	_, err = x509util.VerifyValidity(cert, 366)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate will expire in ")

	// the certificate has expired on 2020-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(expiredCert, 0)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate has expired on ")

	// the certificate has expired on 2020-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(expiredCert, 10000)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate has expired on ")

	// the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(notYetValidCert, 0)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate is not yet valid and will be valid on ")

	// the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	_, err = x509util.VerifyValidity(notYetValidCert, 10000)
	assert.NotNil(err)
	assert.Contains(err.Error(), "the certificate is not yet valid and will be valid on ")
}

func TestGetRootCertPool(t *testing.T) {
	var (
		roots *x509.CertPool
		err   error
	)
	assert := assert.New(t)

	certFile := "../test/testdata/pki/root-ca/ca-root-g2-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	roots, err = x509util.GetRootCertPool(certs)
	assert.Nil(err)
	assert.Equal(certs[0].RawSubject, roots.Subjects()[0])
}

func TestGetIntermediateCertPool(t *testing.T) {
	var (
		intermediates *x509.CertPool
		err           error
	)
	assert := assert.New(t)

	certFile := "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	intermediates = x509util.GetIntermediateCertPool(certs)
	assert.Nil(err)
	assert.Equal(certs[0].RawSubject, intermediates.Subjects()[0])
}
