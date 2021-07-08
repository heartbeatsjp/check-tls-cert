// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"strings"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckKeyPair(t *testing.T) {
	var state checker.State
	w := strings.Builder{}
	checker.SetOutput(&w)
	assert := assert.New(t)

	rsaKeyFile := "../test/testdata/pki/private/server-a-rsa.key"
	rsaPrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(rsaKeyFile, nil)
	rsaPublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(rsaPrivateKeyInfo)

	rsaCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	rsaCerts, _ := x509util.ParseCertificateFiles(rsaCertFile)
	rsaPublicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(rsaCerts[0])

	ecdsaKeyFile := "../test/testdata/pki/private/server-a-ecdsa.key"
	ecdsaPrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(ecdsaKeyFile, nil)
	ecdsaPublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(ecdsaPrivateKeyInfo)

	ecdsaCertFile := "../test/testdata/pki/cert/valid/server-a-ecdsa.crt"
	ecdsaCerts, _ := x509util.ParseCertificateFiles(ecdsaCertFile)
	ecdsaPublicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(ecdsaCerts[0])

	ed25519KeyFile := "../test/testdata/pki/private/server-a-ed25519.key"
	ed25519PrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(ed25519KeyFile, nil)
	ed25519PublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(ed25519PrivateKeyInfo)

	ed25519CertFile := "../test/testdata/pki/cert/valid/server-a-ed25519.crt"
	ed25519Certs, _ := x509util.ParseCertificateFiles(ed25519CertFile)
	ed25519PublicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(ed25519Certs[0])

	invalidKeyFile := "../test/testdata/pki/private/server-b-rsa.key"
	invalidPrivateKeyInfo, _ := x509util.ParsePrivateKeyFile(invalidKeyFile, nil)
	invalidPublicKeyInfoInPrivateKey, _ := x509util.ExtractPublicKeyFromPrivateKey(invalidPrivateKeyInfo)

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
	state = checker.CheckKeyPair(invalidPublicKeyInfoInPrivateKey, rsaPublicKeyInfo)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the private key is not paired with a certificate")

	w.Reset()
	state.PrintDetails(1, x509util.StrictDN)
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
	state = checker.CheckKeyPair(ecdsaPublicKeyInfoInPrivateKey, rsaPublicKeyInfo)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the public key algorithm does not match between the private Key and the certificate")

	w.Reset()
	state.PrintDetails(1, x509util.StrictDN)
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
	//                 00:d3:a0:10:4c:a5:90:94:3d:dd:32:21:82:d2:df:
	//                 ...(omitted)
	//             Exponent: 65537 (0x10001)
	state = checker.CheckKeyPair(rsaPublicKeyInfoInPrivateKey, rsaPublicKeyInfo)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the private key is paired with the certificate")

	w.Reset()
	state.PrintDetails(1, x509util.StrictDN)
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: RSA
            RSA Public-Key: (2048 bit)
            Modulus:`)

	w.Reset()
	state.PrintDetails(1, x509util.StrictDN)
	assert.Contains(w.String(), `To get the full public key, use the '-vv' option.`)

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `The public key information can be obtained with the following command:`)

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
	state = checker.CheckKeyPair(ecdsaPublicKeyInfoInPrivateKey, ecdsaPublicKeyInfo)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the private key is paired with the certificate")

	w.Reset()
	state.PrintDetails(1, x509util.StrictDN)
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
	state = checker.CheckKeyPair(ed25519PublicKeyInfoInPrivateKey, ed25519PublicKeyInfo)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: the private key is paired with the certificate")

	w.Reset()
	state.PrintDetails(1, x509util.StrictDN)
	assert.Contains(w.String(), `    Private Key:
        Public Key Algorithm: Ed25519
            ED25519 Public-Key:
            pub:`)
	assert.Contains(w.String(), `    Certificate:
        Public Key Algorithm: Ed25519
            ED25519 Public-Key:
            pub:`)

}
