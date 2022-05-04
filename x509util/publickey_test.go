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

	privKeyFile := "../test/testdata/pki/private/server-a-rsa.pem"
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	pubKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(certs[0])
	privKeyInfo, _ := x509util.ParsePrivateKeyFile(privKeyFile, nil)
	pubKeyInfoInPrivKey, _ := x509util.ExtractPublicKeyFromPrivateKey(privKeyInfo)
	assert.NotNil(pubKeyInfoInPrivKey)
	assert.NotNil(pubKeyInfo)
	assert.Equal("Certificate", pubKeyInfo.SourceName)
	assert.Equal("Private Key", pubKeyInfoInPrivKey.SourceName)
	pubKeyInfo.SourceName = ""
	pubKeyInfoInPrivKey.SourceName = ""
	assert.EqualValues(pubKeyInfo, pubKeyInfoInPrivKey)

	privKeyFile = "../test/testdata/pki/private/server-a-ecdsa.pem"
	certFile = "../test/testdata/pki/cert/valid/server-a-ecdsa.pem"
	certs, _ = x509util.ParseCertificateFiles(certFile)
	pubKeyInfo, _ = x509util.ExtractPublicKeyFromCertificate(certs[0])
	privKeyInfo, _ = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	pubKeyInfoInPrivKey, _ = x509util.ExtractPublicKeyFromPrivateKey(privKeyInfo)
	assert.NotNil(pubKeyInfoInPrivKey)
	assert.NotNil(pubKeyInfo)
	assert.Equal("Certificate", pubKeyInfo.SourceName)
	assert.Equal("Private Key", pubKeyInfoInPrivKey.SourceName)
	pubKeyInfo.SourceName = ""
	pubKeyInfoInPrivKey.SourceName = ""
	assert.EqualValues(pubKeyInfo, pubKeyInfoInPrivKey)

	privKeyFile = "../test/testdata/pki/private/server-a-ed25519.pem"
	certFile = "../test/testdata/pki/cert/valid/server-a-ed25519.pem"
	certs, _ = x509util.ParseCertificateFiles(certFile)
	pubKeyInfo, _ = x509util.ExtractPublicKeyFromCertificate(certs[0])
	privKeyInfo, _ = x509util.ParsePrivateKeyFile(privKeyFile, nil)
	pubKeyInfoInPrivKey, _ = x509util.ExtractPublicKeyFromPrivateKey(privKeyInfo)
	assert.NotNil(pubKeyInfoInPrivKey)
	assert.NotNil(pubKeyInfo)
	assert.Equal("Certificate", pubKeyInfo.SourceName)
	assert.Equal("Private Key", pubKeyInfoInPrivKey.SourceName)
	pubKeyInfo.SourceName = ""
	pubKeyInfoInPrivKey.SourceName = ""
	assert.EqualValues(pubKeyInfo, pubKeyInfoInPrivKey)
}

func TestEncodeLowerCase2DigitHex(t *testing.T) {
	assert := assert.New(t)

	h := x509util.EncodeLowerCase2DigitHex([]byte("\x01"))
	assert.Equal("01", h, "2 digit hex string should match")

	h = x509util.EncodeLowerCase2DigitHex([]byte("\x01\x02"))
	assert.Equal("01:02", h, "2 digit hex string should match")

	h = x509util.EncodeLowerCase2DigitHex([]byte("\x01\x02\xff"))
	assert.Equal("01:02:ff", h, "2 digit hex string should match")
}

func TestEncodeUpperCase2DigitHex(t *testing.T) {
	assert := assert.New(t)

	h := x509util.EncodeUpperCase2DigitHex([]byte("\x01"))
	assert.Equal("01", h, "2 digit hex string should match")

	h = x509util.EncodeUpperCase2DigitHex([]byte("\x01\x02"))
	assert.Equal("01:02", h, "2 digit hex string should match")

	h = x509util.EncodeUpperCase2DigitHex([]byte("\x01\x02\xff"))
	assert.Equal("01:02:FF", h, "2 digit hex string should match")
}
