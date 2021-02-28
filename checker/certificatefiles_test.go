// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/stretchr/testify/assert"
)

func TestCheckCertificateFiles(t *testing.T) {
	var state checker.State
	assert := assert.New(t)

	nonExistentFile := "../test/testdata/pki/misc/non-existent.crt"
	emptyFile := "../test/testdata/pki/misc/empty.crt"
	serverCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	chainCertFile := "../test/testdata/pki/chain/chain-a-rsa.pem"
	rootCertFile := "../test/testdata/pki/root-ca/ca-root.pem"

	// Non-existent file
	state = checker.CheckCertificateFiles(nonExistentFile, "", "", "")
	assert.Equal(checker.CRITICAL, state.Status)

	// Empty file
	state = checker.CheckCertificateFiles(emptyFile, "", "", "")
	assert.Equal(checker.CRITICAL, state.Status)

	// Intermediate and root certificates not found
	// Returns OK because the certificate path is not validated.
	state = checker.CheckCertificateFiles(serverCertFile, "", "", "")
	assert.Equal(checker.OK, state.Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.crt", state.Data.([]checker.CertificateFileInfo)[0].Name)
	assert.Equal("CN=server-a.test", state.Data.([]checker.CertificateFileInfo)[0].CertificateInfoList[0].Certificate.Subject.String())

	// Root certificates not found
	// Returns OK because the certificate path is not validated.
	state = checker.CheckCertificateFiles(serverCertFile, chainCertFile, "", "")
	assert.Equal(checker.OK, state.Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.crt", state.Data.([]checker.CertificateFileInfo)[0].Name)
	assert.Equal("CN=server-a.test", state.Data.([]checker.CertificateFileInfo)[0].CertificateInfoList[0].Certificate.Subject.String())
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", state.Data.([]checker.CertificateFileInfo)[1].Name)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([]checker.CertificateFileInfo)[1].CertificateInfoList[0].Certificate.Subject.String())

	// OK
	state = checker.CheckCertificateFiles(serverCertFile, chainCertFile, "", rootCertFile)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.crt", state.Data.([]checker.CertificateFileInfo)[0].Name)
	assert.Equal("CN=server-a.test", state.Data.([]checker.CertificateFileInfo)[0].CertificateInfoList[0].Certificate.Subject.String())
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", state.Data.([]checker.CertificateFileInfo)[1].Name)
	assert.Equal("CN=Intermediate CA A RSA", state.Data.([]checker.CertificateFileInfo)[1].CertificateInfoList[0].Certificate.Subject.String())
	assert.Equal("../test/testdata/pki/root-ca/ca-root.pem", state.Data.([]checker.CertificateFileInfo)[2].Name)
	assert.Equal("CN=ROOT CA G1 RSA", state.Data.([]checker.CertificateFileInfo)[2].CertificateInfoList[0].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", state.Data.([]checker.CertificateFileInfo)[2].CertificateInfoList[1].Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 ECDSA", state.Data.([]checker.CertificateFileInfo)[2].CertificateInfoList[2].Certificate.Subject.String())
}
