// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/youmark/pkcs8"
	"golang.org/x/term"
)

// PrivateKeyInfo describes the information of a private key.
type PrivateKeyInfo struct {
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	Key                interface{}
}

// ParsePrivateKeyFile parses a private key file in PEM format and returns a private key.
func ParsePrivateKeyFile(keyFile string, password []byte) (privKeyInfo PrivateKeyInfo, err error) {
	block, isEncrypted, err := readPrivateKeyFile(keyFile)
	if err != nil {
		return
	}

	if isEncrypted {
		for len(password) == 0 {
			fmt.Printf("Enter password for %s: ", keyFile)
			password, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return
			}
			if len(password) > 0 {
				break
			}
			fmt.Println("Error: password is empty")
		}
	}

	var der = block.Bytes

	switch block.Type {
	case "RSA PRIVATE KEY":
		if isEncrypted {
			//lint:ignore SA1019 Encrypted PEM filea are still used.
			if der, err = x509.DecryptPEMBlock(block, password); err != nil {
				return
			}
		}
		privKeyInfo, err = parsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		if isEncrypted {
			//lint:ignore SA1019 Encrypted PEM filea are still used.
			if der, err = x509.DecryptPEMBlock(block, password); err != nil {
				return
			}
		}
		privKeyInfo, err = parseECPrivateKey(der)
	case "PRIVATE KEY":
		privKeyInfo, err = parsePKCS8PrivateKey(der, false, nil)
	case "ENCRYPTED PRIVATE KEY":
		privKeyInfo, err = parsePKCS8PrivateKey(der, true, password)
	default:
		// If the key file is of an unknown type, readPrivateKeyFile() will fail and it will not reach here.
		//lint:ignore ST1005 "Private Key" is a component name.
		err = errors.New("Private Key: unknown type")
	}

	return
}

func readPrivateKeyFile(keyFile string) (block *pem.Block, isEncrypted bool, err error) {
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
			//lint:ignore SA1019 Encrypted PEM files are still used.
			isEncrypted = x509.IsEncryptedPEMBlock(block)
			return
		case "EC PRIVATE KEY":
			//lint:ignore SA1019 Encrypted PEM files are still used.
			isEncrypted = x509.IsEncryptedPEMBlock(block)
			return
		case "PRIVATE KEY":
			return
		case "ENCRYPTED PRIVATE KEY":
			isEncrypted = true
			return
		default:
		}
	}

	//lint:ignore ST1005 "Private Key" is a component name.
	err = errors.New("Private Key: unknown type")
	return
}

func parsePKCS1PrivateKey(der []byte) (privKeyInfo PrivateKeyInfo, err error) {
	var privKey *rsa.PrivateKey
	if privKey, err = x509.ParsePKCS1PrivateKey(der); err != nil {
		return
	}

	privKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: x509.RSA,
		Key:                privKey,
	}
	return
}

func parseECPrivateKey(der []byte) (privKeyInfo PrivateKeyInfo, err error) {
	var privKey *ecdsa.PrivateKey
	if privKey, err = x509.ParseECPrivateKey(der); err != nil {
		return
	}

	privKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: x509.ECDSA,
		Key:                privKey,
	}
	return
}

func parsePKCS8PrivateKey(der []byte, isEncrypted bool, password []byte) (privKeyInfo PrivateKeyInfo, err error) {
	var (
		privKey interface{}
		algo    x509.PublicKeyAlgorithm
	)

	if isEncrypted {
		if privKey, err = pkcs8.ParsePKCS8PrivateKey(der, password); err != nil {
			return
		}
	} else {
		if privKey, err = x509.ParsePKCS8PrivateKey(der); err != nil {
			return
		}

	}

	switch privKey.(type) {
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

	privKeyInfo = PrivateKeyInfo{
		PublicKeyAlgorithm: algo,
		Key:                privKey,
	}
	return
}

// ReadPasswordFile reads the password from the password file.
func ReadPasswordFile(passwordFile string) ([]byte, error) {
	password, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, err
	}

	password = bytes.TrimRight(password, "\n\r")
	return password, nil
}
