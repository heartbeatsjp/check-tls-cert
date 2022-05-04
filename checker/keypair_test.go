// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"strings"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestNewKeyPairChecker(t *testing.T) {
	var c checker.Checker
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	rsaKeyFile := "../test/testdata/pki/private/server-a-rsa.pem"
	rsaPrivKeyInfo, _ := x509util.ParsePrivateKeyFile(rsaKeyFile, nil)
	rsaPubKeyInfoInPrivKey, err := x509util.ExtractPublicKeyFromPrivateKey(rsaPrivKeyInfo)
	assert.Nil(err)

	rsaCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	rsaCerts, _ := x509util.ParseCertificateFiles(rsaCertFile)
	rsaPubKeyInfo, err := x509util.ExtractPublicKeyFromCertificate(rsaCerts[0])
	assert.Nil(err)

	ecdsaKeyFile := "../test/testdata/pki/private/server-a-ecdsa.pem"
	ecdsaPrivKeyInfo, _ := x509util.ParsePrivateKeyFile(ecdsaKeyFile, nil)
	ecdsaPubKeyInfoInPrivKey, err := x509util.ExtractPublicKeyFromPrivateKey(ecdsaPrivKeyInfo)
	assert.Nil(err)

	ecdsaCertFile := "../test/testdata/pki/cert/valid/server-a-ecdsa.pem"
	ecdsaCerts, _ := x509util.ParseCertificateFiles(ecdsaCertFile)
	ecdsaPubKeyInfo, err := x509util.ExtractPublicKeyFromCertificate(ecdsaCerts[0])
	assert.Nil(err)

	ed25519KeyFile := "../test/testdata/pki/private/server-a-ed25519.pem"
	ed25519PrivKeyInfo, _ := x509util.ParsePrivateKeyFile(ed25519KeyFile, nil)
	ed25519PubKeyInfoInPrivKey, err := x509util.ExtractPublicKeyFromPrivateKey(ed25519PrivKeyInfo)
	assert.Nil(err)

	ed25519CertFile := "../test/testdata/pki/cert/valid/server-a-ed25519.pem"
	ed25519Certs, _ := x509util.ParseCertificateFiles(ed25519CertFile)
	ed25519PubKeyInfo, err := x509util.ExtractPublicKeyFromCertificate(ed25519Certs[0])
	assert.Nil(err)

	invalidKeyFile := "../test/testdata/pki/private/server-b-rsa.pem"
	invalidPrivKeyInfo, _ := x509util.ParsePrivateKeyFile(invalidKeyFile, nil)
	invalidPubKeyInfoInPrivKey, err := x509util.ExtractPublicKeyFromPrivateKey(invalidPrivKeyInfo)
	assert.Nil(err)

	// CRITICAL: the private key is not paired with a certificate
	//     Private Key:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	//     Certificate:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	c = checker.NewKeyPairChecker(invalidPubKeyInfoInPrivKey, rsaPubKeyInfo)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the private key is not paired with a certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)

	// CRITICAL: the public key algorithm does not match between the private Key and the certificate
	//     Private Key:
	//         Public Key Algorithm: ECDSA
	//             Public-Key: (256 bit)
	//             pub:
	//                 04:36:ee:23:87:98:ba:57:8d:a0:dc:72:40:18:ae:
	//                 ...(omitted)
	//             NIST CURVE: P-256
	//     Certificate:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	c = checker.NewKeyPairChecker(ecdsaPubKeyInfoInPrivKey, rsaPubKeyInfo)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the public key algorithm does not match between the private Key and the certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: ECDSA
            Public-Key: (256 bit)
            pub:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)

	// OK: the private key is paired with the certificate
	//     Private Key:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	//     Certificate:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	c = checker.NewKeyPairChecker(rsaPubKeyInfoInPrivKey, rsaPubKeyInfo)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: the private key is paired with the certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)

	// OK: the private key is paired with the certificate
	//     Private Key:
	//         Public Key Algorithm: ECDSA
	//             Public-Key: (256 bit)
	//             pub:
	//                 04:36:ee:23:87:98:ba:57:8d:a0:dc:72:40:18:ae:
	//                 ...(omitted)
	//             NIST CURVE: P-256
	//     Certificate:
	//         Public Key Algorithm: ECDSA
	//             Public-Key: (256 bit)
	//             pub:
	//                 04:36:ee:23:87:98:ba:57:8d:a0:dc:72:40:18:ae:
	//                 ...(omitted)
	//             NIST CURVE: P-256
	c = checker.NewKeyPairChecker(ecdsaPubKeyInfoInPrivKey, ecdsaPubKeyInfo)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: the private key is paired with the certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: ECDSA
            Public-Key: (256 bit)
            pub:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: ECDSA
            Public-Key: (256 bit)
            pub:`)

	// OK: the private key is paired with the certificate
	//     Private Key:
	//         Public Key Algorithm: Ed25519
	//             ED25519 Public-Key:
	//             pub:
	//                 1d:84:84:80:3a:4f:0f:9a:d6:c7:77:73:8a:8d:c2:
	//                 ...(omitted)
	//     Certificate:
	//         Public Key Algorithm: Ed25519
	//             ED25519 Public-Key:
	//             pub:
	//                 1d:84:84:80:3a:4f:0f:9a:d6:c7:77:73:8a:8d:c2:
	//                 ...(omitted)
	//
	c = checker.NewKeyPairChecker(ed25519PubKeyInfoInPrivKey, ed25519PubKeyInfo)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: the private key is paired with the certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: Ed25519
            ED25519 Public-Key:
            pub:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: Ed25519
            ED25519 Public-Key:
            pub:`)

	// OK: the private key is paired with the certificate
	//     Private Key:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	//     Certificate:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	//
	//    To get the full public key, use the '-vv' option.
	checker.SetVerbose(1)
	c = checker.NewKeyPairChecker(rsaPubKeyInfoInPrivKey, rsaPubKeyInfo)

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `...(omitted)`)
	assert.Contains(w.String(), `To get the full public key, use the '-vv' option.`)

	// OK: the private key is paired with the certificate
	//     Private Key:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	//     Certificate:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...
	//             Exponent: 65537 (0x10001)
	//
	//    The public key information can be obtained with the following command:
	//        openssl pkey -in PRIVATE_KEY.pem -noout -text_pub
	//        openssl x509 -in CERTIFICATE.pem -noout -pubkey | openssl pkey -pubin -text_pub -noout
	//        openssl x509 -in CERTIFICATE.pem -noout -text
	checker.SetVerbose(2)
	c = checker.NewKeyPairChecker(rsaPubKeyInfoInPrivKey, rsaPubKeyInfo)

	w.Reset()
	c.PrintDetails()
	assert.NotContains(w.String(), `...(omitted)`)
	assert.NotContains(w.String(), `To get the full public key,`)
	assert.Contains(w.String(), `The public key information can be obtained with the following command:`)

	// OK: the private key is paired with the certificate
	//     Private Key:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	//     Certificate:
	//         Public Key Algorithm: RSA
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:df:10:ae:dc:d0:2f:c2:8d:c3:09:4a:36:c3:4c:
	//                 ...
	//             Exponent: 65537 (0x10001)
	//
	//    The public key information can be obtained with the following command:
	//        openssl pkey -in PRIVATE_KEY.pem -noout -text_pub
	//        openssl x509 -in CERTIFICATE.pem -noout -pubkey | openssl pkey -pubin -text_pub -noout
	//        openssl x509 -in CERTIFICATE.pem -noout -text
	checker.SetVerbose(3)
	c = checker.NewKeyPairChecker(rsaPubKeyInfoInPrivKey, rsaPubKeyInfo)

	w.Reset()
	c.PrintDetails()
	assert.NotContains(w.String(), `...(omitted)`)
	assert.NotContains(w.String(), `To get the full public key,`)
	assert.Contains(w.String(), `The public key information can be obtained with the following command:`)
}

func TestKeyPairChecker(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	rsaPrivKeyInfo, err := x509util.ParsePrivateKeyFile("../test/testdata/pki/private/server-a-rsa.pem", nil)
	assert.Nil(err)
	rsaPubKeyInfoInPrivKey, err := x509util.ExtractPublicKeyFromPrivateKey(rsaPrivKeyInfo)
	assert.Nil(err)
	rsaCerts, err := x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.pem")
	assert.Nil(err)
	rsaPubKeyInfo, err := x509util.ExtractPublicKeyFromCertificate(rsaCerts[0])
	assert.Nil(err)

	c := checker.NewKeyPairChecker(rsaPubKeyInfoInPrivKey, rsaPubKeyInfo)
	assert.Equal("Private Key/Certificate Pair", c.Name())
	assert.Equal(checker.OK, c.Status())
	assert.Equal("the private key is paired with the certificate", c.Message())
	assert.Equal("RSA Public-Key: (2048 bit)", c.Details().(*checker.KeyPairDetails).PrivateKey.Type)

	c.PrintName()
	assert.Equal("[Private Key/Certificate Pair]\n", w.String())

	w.Reset()
	c.PrintStatus()
	assert.Equal("OK: the private key is paired with the certificate\n", w.String())

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)
}
