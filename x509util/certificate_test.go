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
		certs []*x509.Certificate
		err   error
	)
	assert := assert.New(t)

	nonExistentFile := "../test/testdata/pki/misc/non-existent.crt"
	_, err = x509util.ParseCertificateFiles(nonExistentFile)
	assert.NotNil(err, "file should not exist: %s", nonExistentFile)

	emptyFile := "../test/testdata/pki/misc/empty.crt"
	_, err = x509util.ParseCertificateFiles(emptyFile)
	assert.NotNil(err, "file should not be a certificate: %s", emptyFile)

	invalidFile := "../test/testdata/pki/private/server-a-rsa.key"
	_, err = x509util.ParseCertificateFiles(invalidFile)
	assert.NotNil(err, "file should not be a certificate: %s", invalidFile)

	serverCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ = x509util.ParseCertificateFiles(serverCertFile)
	assert.Equal(1, len(certs), "a number of certificates should be 1")
	assert.Equal("CN=server-a.test", certs[0].Subject.String(), "subject should match")

	chainCertFile := "../test/testdata/pki/chain/chain-a-rsa.pem"
	certs, _ = x509util.ParseCertificateFiles(serverCertFile, chainCertFile)
	assert.Equal(2, len(certs), "a number of certificates should be 2")
	assert.Equal("CN=server-a.test", certs[0].Subject.String(), "subject should match")
	assert.Equal("CN=Intermediate CA A RSA", certs[1].Subject.String(), "subject should match")
}

func TestParseCertificateFile(t *testing.T) {
	var (
		cert *x509.Certificate
		err  error
	)
	assert := assert.New(t)

	nonExistentFile := "../test/testdata/pki/misc/non-existent.crt"
	_, err = x509util.ParseCertificateFile(nonExistentFile)
	assert.NotNil(err)

	emptyFile := "../test/testdata/pki/misc/empty.crt"
	_, err = x509util.ParseCertificateFile(emptyFile)
	assert.NotNil(err)

	invalidFile := "../test/testdata/pki/private/server-a-rsa.key"
	_, err = x509util.ParseCertificateFile(invalidFile)
	assert.NotNil(err, "file should not be a certificate: %s", invalidFile)

	serverCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	cert, _ = x509util.ParseCertificateFile(serverCertFile)
	assert.Equal("CN=server-a.test", cert.Subject.String(), "subject should match")
}
