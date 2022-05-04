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
		privKeyFile                 string
		privKeyInfo, derPrivKeyInfo x509util.PrivateKeyInfo
		decryptedPrivKeyInfo        x509util.PrivateKeyInfo
		err                         error
	)
	assert := assert.New(t)

	password, _ := x509util.ReadPasswordFile("../test/testdata/pki/private/password.txt")

	/*
	 * Misc.
	 */

	// non-existent file
	privKeyFile = "../test/testdata/pki/misc/non-existent.key"
	_, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.NotNil(err)

	// empty file
	privKeyFile = "../test/testdata/pki/misc/empty.key"
	_, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.NotNil(err)

	// invalid format file
	privKeyFile = "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	_, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.NotNil(err)

	// no EOL
	privKeyFile = "../test/testdata/pki/private/misc-no-eol.key"
	privKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.RSA, privKeyInfo.PublicKeyAlgorithm)

	// Explanatory Text
	privKeyFile = "../test/testdata/pki/private/misc-explanatory-text.key"
	privKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.RSA, privKeyInfo.PublicKeyAlgorithm)

	/*
	 * RSA
	 */

	privKeyFile = "../test/testdata/pki/private/server-a-rsa.key"
	privKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.RSA, privKeyInfo.PublicKeyAlgorithm)

	privKeyFile = "../test/testdata/pki/private/server-a-rsa-der.key"
	derPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.RSA, privKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, derPrivKeyInfo.Key)

	privKeyFile = "../test/testdata/pki/private/server-a-rsa-encrypted.key"
	decryptedPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, password)
	assert.Nil(err)
	assert.Equal(x509.RSA, decryptedPrivKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, decryptedPrivKeyInfo.Key)

	privKeyFile = "../test/testdata/pki/chain/fullchain-a-rsa-private-key.pem"
	derPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.RSA, privKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, derPrivKeyInfo.Key)

	/*
	 * RSA (traditional)
	 */

	privKeyFile = "../test/testdata/pki/private/server-a-rsa-traditional.key"
	privKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.RSA, privKeyInfo.PublicKeyAlgorithm)

	privKeyFile = "../test/testdata/pki/private/server-a-rsa-traditional-encrypted.key"
	decryptedPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, password)
	assert.Nil(err)
	assert.Equal(x509.RSA, decryptedPrivKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, decryptedPrivKeyInfo.Key)

	/*
	 * ECDSA
	 */

	privKeyFile = "../test/testdata/pki/private/server-a-ecdsa.key"
	privKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.ECDSA, privKeyInfo.PublicKeyAlgorithm)

	privKeyFile = "../test/testdata/pki/private/server-a-ecdsa-der.key"
	derPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.ECDSA, privKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, derPrivKeyInfo.Key)

	privKeyFile = "../test/testdata/pki/private/server-a-ecdsa-encrypted.key"
	decryptedPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, password)
	assert.Nil(err)
	assert.Equal(x509.ECDSA, decryptedPrivKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, decryptedPrivKeyInfo.Key)

	/*
	 * ECDSA (traditional)
	 */

	privKeyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional.key"
	privKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.ECDSA, privKeyInfo.PublicKeyAlgorithm)

	privKeyFile = "../test/testdata/pki/private/server-a-ecdsa-traditional-encrypted.key"
	decryptedPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, password)
	assert.Nil(err)
	assert.Equal(x509.ECDSA, decryptedPrivKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, decryptedPrivKeyInfo.Key)

	/*
	 * Ed25519
	 */

	privKeyFile = "../test/testdata/pki/private/server-a-ed25519.key"
	privKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.Ed25519, privKeyInfo.PublicKeyAlgorithm)

	privKeyFile = "../test/testdata/pki/private/server-a-ed25519-der.key"
	derPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.Nil(err)
	assert.Equal(x509.Ed25519, privKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, derPrivKeyInfo.Key)

	privKeyFile = "../test/testdata/pki/private/server-a-ed25519-encrypted.key"
	decryptedPrivKeyInfo, err = x509util.ParsePrivateKeyFile(privKeyFile, password)
	assert.Nil(err)
	assert.Equal(x509.Ed25519, decryptedPrivKeyInfo.PublicKeyAlgorithm)
	assert.Equal(privKeyInfo.Key, decryptedPrivKeyInfo.Key)

	/*
	 * Unknown Algorithm
	 */

	privKeyFile = "../test/testdata/pki/private/server-a-ed488.key"
	_, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.NotNil(err)

	privKeyFile = "../test/testdata/pki/private/server-a-ed488-der.key"
	_, err = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	assert.NotNil(err)

	privKeyFile = "../test/testdata/pki/private/server-a-ed488-encrypted.key"
	_, err = x509util.ParsePrivateKeyFile(privKeyFile, password)
	assert.NotNil(err)
}
