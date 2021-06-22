// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// PublicKeyInfo describes the information of a public key.
type PublicKeyInfo struct {
	SourceName         string
	TypeLabel          string
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Key                interface{}
	KeyString          string
	Option             map[string]string
}

// ExtractPublicKeyFromCertificate extracts a public key from a certificate.
func ExtractPublicKeyFromCertificate(cert *x509.Certificate) (publicKeyInfo PublicKeyInfo, err error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		publicKey := cert.PublicKey.(*rsa.PublicKey)
		keyString := Encode2DigitHex(publicKey.N.Bytes())
		// Add a leading 00 if the top bit is set as openssl's print_labeled_bignum().
		if keyString[0] >= '8' {
			keyString = "00:" + keyString
		}
		publicKeyInfo = PublicKeyInfo{
			SourceName:         "Certificate",
			TypeLabel:          fmt.Sprintf("RSA Public-Key: (%d bit)", publicKey.Size()*8),
			PublicKeyAlgorithm: x509.RSA,
			Key:                cert.PublicKey,
			KeyString:          keyString,
			Option:             map[string]string{"Exponent": fmt.Sprintf("%d (0x%x)", publicKey.E, publicKey.E)},
		}
	case x509.ECDSA:
		publicKey := cert.PublicKey.(*ecdsa.PublicKey)
		prefix := "04:" // Supports only the uncompressed form. See also RFC 5480.
		keyString := prefix + Encode2DigitHex(publicKey.X.Bytes()) +
			":" + Encode2DigitHex(publicKey.Y.Bytes())
		publicKeyInfo = PublicKeyInfo{
			SourceName:         "Certificate",
			TypeLabel:          fmt.Sprintf("Public-Key: (%d bit)", publicKey.Curve.Params().BitSize),
			PublicKeyAlgorithm: x509.ECDSA,
			Key:                cert.PublicKey,
			KeyString:          keyString,
			Option:             map[string]string{"NIST CURVE": publicKey.Curve.Params().Name},
		}
	case x509.Ed25519:
		publicKeyInfo = PublicKeyInfo{
			SourceName:         "Certificate",
			TypeLabel:          "ED25519 Public-Key:",
			PublicKeyAlgorithm: x509.Ed25519,
			Key:                cert.PublicKey,
			KeyString:          Encode2DigitHex(cert.PublicKey.(ed25519.PublicKey)),
		}
	default:
		//lint:ignore ST1005 "Certificate" is a component name.
		err = errors.New("Certificate: unknown public key algorithm")
	}

	return
}

// ExtractPublicKeyFromPrivateKey extracts a public key from a private key.
func ExtractPublicKeyFromPrivateKey(privateKeyInfo PrivateKeyInfo) (publicKeyInfo PublicKeyInfo, err error) {
	switch privateKeyInfo.PublicKeyAlgorithm {
	case x509.RSA:
		publicKey := privateKeyInfo.Key.(*rsa.PrivateKey).PublicKey
		keyString := Encode2DigitHex(publicKey.N.Bytes())
		// Add a leading 00 if the top bit is set as openssl's print_labeled_bignum().
		if keyString[0] >= '8' {
			keyString = "00:" + keyString
		}
		publicKeyInfo = PublicKeyInfo{
			SourceName:         "Private Key",
			TypeLabel:          fmt.Sprintf("RSA Public-Key: (%d bit)", publicKey.Size()*8),
			PublicKeyAlgorithm: x509.RSA,
			Key:                &publicKey,
			KeyString:          keyString,
			Option:             map[string]string{"Exponent": fmt.Sprintf("%d (0x%x)", publicKey.E, publicKey.E)},
		}
	case x509.ECDSA:
		publicKey := privateKeyInfo.Key.(*ecdsa.PrivateKey).PublicKey
		prefix := "04:" // Supports only the uncompressed form. See also RFC 5480.
		keyString := prefix + Encode2DigitHex(publicKey.X.Bytes()) +
			":" + Encode2DigitHex(publicKey.Y.Bytes())
		publicKeyInfo = PublicKeyInfo{
			SourceName:         "Private Key",
			TypeLabel:          fmt.Sprintf("Public-Key: (%d bit)", publicKey.Curve.Params().BitSize),
			PublicKeyAlgorithm: x509.ECDSA,
			Key:                &publicKey,
			KeyString:          keyString,
			Option:             map[string]string{"NIST CURVE": publicKey.Curve.Params().Name},
		}
	case x509.Ed25519:
		publicKey := privateKeyInfo.Key.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
		publicKeyInfo = PublicKeyInfo{
			SourceName:         "Private Key",
			TypeLabel:          "ED25519 Public-Key:",
			PublicKeyAlgorithm: x509.Ed25519,
			Key:                publicKey,
			KeyString:          Encode2DigitHex(publicKey),
		}
	default:
		//lint:ignore ST1005 "Private Key" is a component name.
		err = errors.New("Private Key: unknown public key algorithm")
	}

	return
}

// Encode2DigitHex encodes bytes into two-digit hexadecimal strings separated by a colon.
func Encode2DigitHex(bytes []byte) string {
	var hexElements []string
	for _, b := range bytes {
		hexElements = append(hexElements, fmt.Sprintf("%02x", uint8(b)))
	}
	return strings.Join(hexElements, ":")
}
