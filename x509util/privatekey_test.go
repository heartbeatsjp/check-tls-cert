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

func TestParsePrivateKeyFile(t *testing.T) {
	var (
		privateKeyInfo x509util.PrivateKeyInfo
		err            error
	)
	assert := assert.New(t)

	nonExistentFile := "../test/testdata/pki/misc/non-existent.key"
	_, err = x509util.ParsePrivateKeyFile(nonExistentFile)
	assert.NotNil(err, "file should not exist: %s", nonExistentFile)

	emptyFile := "../test/testdata/pki/misc/empty.key"
	_, err = x509util.ParsePrivateKeyFile(emptyFile)
	assert.NotNil(err, "file should not be a private key: %s", emptyFile)

	invalidFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	_, err = x509util.ParsePrivateKeyFile(invalidFile)
	assert.NotNil(err, "file should not be a private key: %s", invalidFile)

	privateKeyFile := "../test/testdata/pki/private/server-a-rsa.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile)
	assert.Equal(x509.RSA, privateKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")

	privateKeyFile = "../test/testdata/pki/private/server-a-rsa-traditional.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile)
	assert.Equal(x509.RSA, privateKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")

	privateKeyFile = "../test/testdata/pki/private/server-a-ecdsa.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile)
	assert.Equal(x509.ECDSA, privateKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")

	privateKeyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile)
	assert.Equal(x509.ECDSA, privateKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")

	privateKeyFile = "../test/testdata/pki/private/server-a-ed25519.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile)
	assert.Equal(x509.Ed25519, privateKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")

	privateKeyFile = "../test/testdata/pki/private/server-a-ed488.key"
	_, err = x509util.ParsePrivateKeyFile(privateKeyFile)
	assert.NotNil(err, "public key algorithm should be unknown")
}
