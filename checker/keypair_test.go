// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckKeyPair(t *testing.T) {
	var state checker.State
	assert := assert.New(t)

	rsaKeyFile := "../test/testdata/pki/private/server-a-rsa.key"
	rsaPrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(rsaKeyFile)
	rsaPublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(rsaPrivateKeyInfo)

	rsaCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	rsaCerts, _ := x509util.ParseCertificateFiles(rsaCertFile)
	rsaPublicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(rsaCerts[0])

	ecdsaKeyFile := "../test/testdata/pki/private/server-a-ecdsa.key"
	ecdsaPrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(ecdsaKeyFile)
	ecdsaPublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(ecdsaPrivateKeyInfo)

	ecdsaCertFile := "../test/testdata/pki/cert/valid/server-a-ecdsa.crt"
	ecdsaCerts, _ := x509util.ParseCertificateFiles(ecdsaCertFile)
	ecdsaPublicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(ecdsaCerts[0])

	ed25519KeyFile := "../test/testdata/pki/private/server-a-ed25519.key"
	ed25519PrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(ed25519KeyFile)
	ed25519PublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(ed25519PrivateKeyInfo)

	ed25519CertFile := "../test/testdata/pki/cert/valid/server-a-ed25519.crt"
	ed25519Certs, _ := x509util.ParseCertificateFiles(ed25519CertFile)
	ed25519PublicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(ed25519Certs[0])

	invalidKeyFile := "../test/testdata/pki/private/server-b-rsa.key"
	invalidPrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(invalidKeyFile)
	invalidPublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(invalidPrivateKeyInfo)

	state = checker.CheckKeyPair(invalidPublicKeyInfoInPrivateKey, rsaPublicKeyInfo)
	assert.Equal(checker.CRITICAL, state.Status)

	state = checker.CheckKeyPair(ecdsaPublicKeyInfoInPrivateKey, rsaPublicKeyInfo)
	assert.Equal(checker.CRITICAL, state.Status)

	state = checker.CheckKeyPair(rsaPublicKeyInfoInPrivateKey, rsaPublicKeyInfo)
	assert.Equal(checker.OK, state.Status)

	state = checker.CheckKeyPair(ecdsaPublicKeyInfoInPrivateKey, ecdsaPublicKeyInfo)
	assert.Equal(checker.OK, state.Status)

	state = checker.CheckKeyPair(ed25519PublicKeyInfoInPrivateKey, ed25519PublicKeyInfo)
	assert.Equal(checker.OK, state.Status)
}
