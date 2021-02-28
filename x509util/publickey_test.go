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

	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	publicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(certs[0])
	assert.Equal(certs[0].PublicKey, publicKeyInfo.Key, "public key should match")
	assert.Equal(certs[0].PublicKeyAlgorithm, publicKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")

	certFile = "../test/testdata/pki/cert/valid/server-a-ecdsa.crt"
	certs, _ = x509util.ParseCertificateFiles(certFile)
	publicKeyInfo, _ = x509util.ExtractPublicKeyFromCertificate(certs[0])
	assert.Equal(certs[0].PublicKey, publicKeyInfo.Key, "public key should match")
	assert.Equal(certs[0].PublicKeyAlgorithm, publicKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")

	certFile = "../test/testdata/pki/cert/valid/server-a-ed25519.crt"
	certs, _ = x509util.ParseCertificateFiles(certFile)
	publicKeyInfo, _ = x509util.ExtractPublicKeyFromCertificate(certs[0])
	assert.Equal(certs[0].PublicKey, publicKeyInfo.Key, "public key should match")
	assert.Equal(certs[0].PublicKeyAlgorithm, publicKeyInfo.PublicKeyAlgorithm, "public key algorithm should match")
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
