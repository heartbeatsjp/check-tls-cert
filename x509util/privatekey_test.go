// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util_test

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestParsePrivateKeyFile(t *testing.T) {
	var (
		privateKeyFile                          string
		privateKeyInfo, decryptedPrivateKeyInfo x509util.PrivateKeyInfo
		err                                     error
	)
	assert := assert.New(t)

	password, _ := os.ReadFile("../test/testdata/pki/private/password.txt")

	/*
	 * Misc.
	 */

	privateKeyFile = "../test/testdata/pki/misc/non-existent.key"
	_, err = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.NotNil(err)

	privateKeyFile = "../test/testdata/pki/misc/empty.key"
	_, err = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.NotNil(err)

	privateKeyFile = "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	_, err = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.NotNil(err)

	/*
	 * RSA
	 */

	privateKeyFile = "../test/testdata/pki/private/server-a-rsa.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.Equal(x509.RSA, privateKeyInfo.PublicKeyAlgorithm)

	privateKeyFile = "../test/testdata/pki/private/server-a-rsa-encrypted.key"
	decryptedPrivateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, password)
	assert.Equal(x509.RSA, decryptedPrivateKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privateKeyInfo.Key, decryptedPrivateKeyInfo.Key)

	/*
	 * RSA (traditional)
	 */

	privateKeyFile = "../test/testdata/pki/private/server-a-rsa-traditional.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.Equal(x509.RSA, privateKeyInfo.PublicKeyAlgorithm)

	privateKeyFile = "../test/testdata/pki/private/server-a-rsa-traditional-encrypted.key"
	decryptedPrivateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, password)
	assert.Equal(x509.RSA, decryptedPrivateKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privateKeyInfo.Key, decryptedPrivateKeyInfo.Key)

	/*
	 * ECDSA
	 */

	privateKeyFile = "../test/testdata/pki/private/server-a-ecdsa.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.Equal(x509.ECDSA, privateKeyInfo.PublicKeyAlgorithm)

	privateKeyFile = "../test/testdata/pki/private/server-a-ecdsa-encrypted.key"
	decryptedPrivateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, password)
	assert.Equal(x509.ECDSA, decryptedPrivateKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privateKeyInfo.Key, decryptedPrivateKeyInfo.Key)

	/*
	 * ECDSA (traditional)
	 */

	privateKeyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.Equal(x509.ECDSA, privateKeyInfo.PublicKeyAlgorithm)

	privateKeyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional-encrypted.key"
	decryptedPrivateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, password)
	assert.Equal(x509.ECDSA, decryptedPrivateKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privateKeyInfo.Key, decryptedPrivateKeyInfo.Key)

	/*
	 * Ed25519
	 */

	privateKeyFile = "../test/testdata/pki/private/server-a-ed25519.key"
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.Equal(x509.Ed25519, privateKeyInfo.PublicKeyAlgorithm)

	privateKeyFile = "../test/testdata/pki/private/server-a-ed25519-encrypted.key"
	decryptedPrivateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile, password)
	assert.Equal(x509.Ed25519, decryptedPrivateKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privateKeyInfo.Key, decryptedPrivateKeyInfo.Key)

	/*
	 * Unknown Algorithm
	 */

	privateKeyFile = "../test/testdata/pki/private/server-a-ed488.key"
	_, err = x509util.ParsePrivateKeyFile(privateKeyFile, nil)
	assert.NotNil(err)

	privateKeyFile = "../test/testdata/pki/private/server-a-ed488-encrypted.key"
	_, err = x509util.ParsePrivateKeyFile(privateKeyFile, password)
	assert.NotNil(err)
}
