// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util_test

import (
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestExtractPublicKey(t *testing.T) {
	assert := assert.New(t)

	privateKeyFile := "../test/testdata/pki/private/server-a-rsa.key"
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	privateKeyInfo, _ := x509util.ParsePrivateKeyFile(privateKeyFile)
	publicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(privateKeyInfo)
	publicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(certs[0])
	assert.Equal(publicKeyInfo.Key, publicKeyInfoInPrivateKey.Key)
	assert.Equal(publicKeyInfo.PublicKeyAlgorithm, publicKeyInfoInPrivateKey.PublicKeyAlgorithm)

	privateKeyFile = "../test/testdata/pki/private/server-a-ecdsa.key"
	certFile = "../test/testdata/pki/cert/valid/server-a-ecdsa.crt"
	certs, _ = x509util.ParseCertificateFiles(certFile)
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile)
	publicKeyInfoInPrivateKey, _ = x509util.ExtractPublicKeyFromPrivateKey(privateKeyInfo)
	publicKeyInfo, _ = x509util.ExtractPublicKeyFromCertificate(certs[0])
	assert.Equal(publicKeyInfo.Key, publicKeyInfoInPrivateKey.Key)
	assert.Equal(publicKeyInfo.PublicKeyAlgorithm, publicKeyInfoInPrivateKey.PublicKeyAlgorithm)

	privateKeyFile = "../test/testdata/pki/private/server-a-ed25519.key"
	certFile = "../test/testdata/pki/cert/valid/server-a-ed25519.crt"
	certs, _ = x509util.ParseCertificateFiles(certFile)
	privateKeyInfo, _ = x509util.ParsePrivateKeyFile(privateKeyFile)
	publicKeyInfoInPrivateKey, _ = x509util.ExtractPublicKeyFromPrivateKey(privateKeyInfo)
	publicKeyInfo, _ = x509util.ExtractPublicKeyFromCertificate(certs[0])
	assert.Equal(publicKeyInfo.Key, publicKeyInfoInPrivateKey.Key)
	assert.Equal(publicKeyInfo.PublicKeyAlgorithm, publicKeyInfoInPrivateKey.PublicKeyAlgorithm)
}

func TestEncode2DigitHex(t *testing.T) {
	assert := assert.New(t)

	h := x509util.Encode2DigitHex([]byte("\x01"))
	assert.Equal("01", h, "2 digit hex string should match")

	h = x509util.Encode2DigitHex([]byte("\x01\x02"))
	assert.Equal("01:02", h, "2 digit hex string should match")

	h = x509util.Encode2DigitHex([]byte("\x01\x02\xff"))
	assert.Equal("01:02:ff", h, "2 digit hex string should match")
}
