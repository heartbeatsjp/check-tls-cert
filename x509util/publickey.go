// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// PublicKeyInfo describes the information of a public key.
type PublicKeyInfo struct {
	SourceName         string
	Type               string
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Key                interface{}
	KeyString          string
	Option             map[string]string
}

// ExtractPublicKeyFromCertificate extracts a public key from a certificate.
func ExtractPublicKeyFromCertificate(cert *x509.Certificate) (pubKeyInfo PublicKeyInfo, err error) {
	sourceName := "Certificate"
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		pubKey := cert.PublicKey.(*rsa.PublicKey)
		pubKeyInfo = createRSAPublicKeyInfo(sourceName, pubKey)
	case x509.ECDSA:
		pubKey := cert.PublicKey.(*ecdsa.PublicKey)
		pubKeyInfo = createECDSAPublicKeyInfo(sourceName, pubKey)
	case x509.Ed25519:
		pubKey := cert.PublicKey.(ed25519.PublicKey)
		pubKeyInfo = createEd25519PublicKeyInfo(sourceName, pubKey)
	default:
		err = fmt.Errorf("%s: unknown public key algorithm", sourceName)
	}

	return
}

// ExtractPublicKeyFromPrivateKey extracts a public key from a private key.
func ExtractPublicKeyFromPrivateKey(privKeyInfo PrivateKeyInfo) (pubKeyInfo PublicKeyInfo, err error) {
	sourceName := "Private Key"
	switch privKeyInfo.PublicKeyAlgorithm {
	case x509.RSA:
		pubKey := privKeyInfo.Key.(*rsa.PrivateKey).PublicKey
		pubKeyInfo = createRSAPublicKeyInfo(sourceName, &pubKey)
	case x509.ECDSA:
		pubKey := privKeyInfo.Key.(*ecdsa.PrivateKey).PublicKey
		pubKeyInfo = createECDSAPublicKeyInfo(sourceName, &pubKey)
	case x509.Ed25519:
		pubKey := privKeyInfo.Key.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
		pubKeyInfo = createEd25519PublicKeyInfo(sourceName, pubKey)
	default:
		err = fmt.Errorf("%s: unknown public key algorithm", sourceName)
	}

	return
}

func createRSAPublicKeyInfo(sourceName string, pubKey *rsa.PublicKey) PublicKeyInfo {
	keyString := EncodeLowerCase2DigitHex(pubKey.N.Bytes())
	// Add a leading 00 if the top bit is set as openssl's print_labeled_bignum().
	if keyString[0] >= '8' {
		keyString = "00:" + keyString
	}
	return PublicKeyInfo{
		SourceName:         sourceName,
		Type:               fmt.Sprintf("RSA Public-Key: (%d bit)", pubKey.Size()*8),
		PublicKeyAlgorithm: x509.RSA,
		Key:                pubKey,
		KeyString:          keyString,
		Option:             map[string]string{"Exponent": fmt.Sprintf("%d (0x%x)", pubKey.E, pubKey.E)},
	}
}

func createECDSAPublicKeyInfo(sourceName string, pubKey *ecdsa.PublicKey) PublicKeyInfo {
	prefix := "04:" // Supports only the uncompressed form. See also RFC 5480.
	keyString := prefix + EncodeLowerCase2DigitHex(pubKey.X.Bytes()) +
		":" + EncodeLowerCase2DigitHex(pubKey.Y.Bytes())
	return PublicKeyInfo{
		SourceName:         sourceName,
		Type:               fmt.Sprintf("Public-Key: (%d bit)", pubKey.Curve.Params().BitSize),
		PublicKeyAlgorithm: x509.ECDSA,
		Key:                pubKey,
		KeyString:          keyString,
		Option:             map[string]string{"NIST CURVE": pubKey.Curve.Params().Name},
	}
}

func createEd25519PublicKeyInfo(sourceName string, pubKey ed25519.PublicKey) PublicKeyInfo {
	return PublicKeyInfo{
		SourceName:         sourceName,
		Type:               "ED25519 Public-Key:",
		PublicKeyAlgorithm: x509.Ed25519,
		Key:                pubKey,
		KeyString:          EncodeLowerCase2DigitHex(pubKey),
	}
}

// EncodeLowerCase2DigitHex encodes bytes into lower-case two-digit hexadecimal strings separated by a colon.
func EncodeLowerCase2DigitHex(bytes []byte) string {
	var hexElements []string
	for _, b := range bytes {
		hexElements = append(hexElements, fmt.Sprintf("%02x", uint8(b)))
	}
	return strings.Join(hexElements, ":")
}

// EncodeUpperCase2DigitHex encodes bytes into upper-case two-digit hexadecimal strings separated by a colon.
func EncodeUpperCase2DigitHex(bytes []byte) string {
	var hexElements []string
	for _, b := range bytes {
		hexElements = append(hexElements, fmt.Sprintf("%02X", uint8(b)))
	}
	return strings.Join(hexElements, ":")
}
