// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// PrivateKeyInfo describes the information of a private key.
type PrivateKeyInfo struct {
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Key                interface{}
}

// ParsePrivateKeyFile parses a private key file in PEM format and returns a private key.
func ParsePrivateKeyFile(keyFile string) (privateKeyInfo PrivateKeyInfo, err error) {
	block, err := readPrivateKeyFile(keyFile)
	if err != nil {
		return
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKeyInfo, err = parsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKeyInfo, err = parseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privateKeyInfo, err = parsePKCS8PrivateKey(block.Bytes)
	default:
		// If the key file is of an unknown type, readPrivateKeyFile() will fail and it will not reach here.
		//lint:ignore ST1005 "Private Key" is a component name.
		err = errors.New("Private Key: unknown type")
	}

	return
}

func readPrivateKeyFile(keyFile string) (block *pem.Block, err error) {
	var pemData, rest []byte

	if pemData, err = os.ReadFile(keyFile); err != nil {
		return
	}

	// It uses a for loop to ignore other types in the PEM file.
	for len(pemData) > 0 {
		block, rest = pem.Decode(pemData)
		pemData = rest

		switch block.Type {
		case "RSA PRIVATE KEY":
			return
		case "EC PRIVATE KEY":
			return
		case "PRIVATE KEY":
			return
		default:
		}
	}

	//lint:ignore ST1005 "Private Key" is a component name.
	err = errors.New("Private Key: unknown type")
	return
}

func parsePKCS1PrivateKey(der []byte) (privateKeyInfo PrivateKeyInfo, err error) {
	var privateKey *rsa.PrivateKey
	if privateKey, err = x509.ParsePKCS1PrivateKey(der); err != nil {
		return
	}

	privateKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: x509.RSA,
		Key:                privateKey,
	}
	return
}

func parseECPrivateKey(der []byte) (privateKeyInfo PrivateKeyInfo, err error) {
	var privateKey *ecdsa.PrivateKey
	if privateKey, err = x509.ParseECPrivateKey(der); err != nil {
		return
	}

	privateKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: x509.ECDSA,
		Key:                privateKey,
	}
	return
}

func parsePKCS8PrivateKey(der []byte) (privateKeyInfo PrivateKeyInfo, err error) {
	var (
		privateKey interface{}
		algo       x509.PublicKeyAlgorithm
	)

	if privateKey, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		return
	}

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		algo = x509.RSA
	case *ecdsa.PrivateKey:
		algo = x509.ECDSA
	case ed25519.PrivateKey:
		algo = x509.Ed25519
	default:
		// If the public key algorithm is unknown, ParsePKCS8PrivateKey() will fail and it will not reach here.
		//lint:ignore ST1005 "Private Key" is a component name.
		err = errors.New("Private Key: unknown public key algorithm")
	}

	privateKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: algo,
		Key:                privateKey,
	}
	return
}
