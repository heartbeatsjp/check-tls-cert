// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// KeyPairChecker represents wheather a private key is paired with a certificate.
type KeyPairChecker struct {
	name    string
	status  Status
	message string
	details *KeyPairDetails
}

func NewKeyPairChecker(pubKeyInfoInPrivKey, pubKeyInfo x509util.PublicKeyInfo) *KeyPairChecker {
	const name = "Private Key/Certificate Pair"

	status := OK
	message := "the private key is paired with the certificate"

	if pubKeyInfoInPrivKey.PublicKeyAlgorithm != pubKeyInfo.PublicKeyAlgorithm {
		status = CRITICAL
		message = "the public key algorithm does not match between the private Key and the certificate"
	} else {
		isValid := false

		switch pubKeyInfoInPrivKey.PublicKeyAlgorithm {
		case x509.RSA:
			pubKeyInPrivKey := pubKeyInfoInPrivKey.Key.(*rsa.PublicKey)
			if pubKeyInPrivKey.Equal(pubKeyInfo.Key) {
				isValid = true
			}
		case x509.ECDSA:
			pubKeyInfoInPrivKey := pubKeyInfoInPrivKey.Key.(*ecdsa.PublicKey)
			if pubKeyInfoInPrivKey.Equal(pubKeyInfo.Key) {
				isValid = true
			}
		case x509.Ed25519:
			pubKeyInPrivKey := pubKeyInfoInPrivKey.Key.(ed25519.PublicKey)
			if pubKeyInPrivKey.Equal(pubKeyInfo.Key) {
				isValid = true
			}
		default:
		}

		if !isValid {
			status = CRITICAL
			message = "the private key is not paired with a certificate"
		}
	}

	details := NewKeyPairDetails(pubKeyInfoInPrivKey, pubKeyInfo)

	return &KeyPairChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *KeyPairChecker) Name() string {
	return c.name
}

func (c *KeyPairChecker) Status() Status {
	return c.status
}

func (c *KeyPairChecker) Message() string {
	return c.message
}

func (c *KeyPairChecker) Details() interface{} {
	return c.details
}

func (c *KeyPairChecker) PrintName() {
	printCheckerName(c)
}

func (c *KeyPairChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *KeyPairChecker) PrintDetails() {
	printIndentedLine(4, "%s:", c.details.PrivateKey.Name)
	printPublicKey(4, c.details.PrivateKey)

	printIndentedLine(4, "%s:", c.details.Certificate.Name)
	printPublicKey(4, c.details.Certificate)

	printIndentedLine(4, "")
	if verbose == 1 {
		printIndentedLine(4, "To get the full public key, use the '-vv' option.")
	}
	if verbose >= 2 {
		printIndentedLine(4, "The public key information can be obtained with the following command:")
		printIndentedLine(4, "    openssl pkey -in PRIVATE_KEY.pem -noout -text_pub")
		printIndentedLine(4, "    openssl x509 -in CERTIFICATE.pem -noout -pubkey | openssl pkey -pubin -text_pub -noout")
		printIndentedLine(4, "    openssl x509 -in CERTIFICATE.pem -noout -text")
	}
}

type KeyPairDetails struct {
	PrivateKey  *publicKeyInfo `json:"privateKey"`
	Certificate *publicKeyInfo `json:"certificate"`
}

func NewKeyPairDetails(pubKeyInfoInPrivKey, pubKeyInfo x509util.PublicKeyInfo) *KeyPairDetails {
	omit := true
	if verbose > 1 {
		omit = false
	}
	return &KeyPairDetails{
		PrivateKey:  getPublicKeyInfo(pubKeyInfoInPrivKey, omit),
		Certificate: getPublicKeyInfo(pubKeyInfo, omit),
	}
}
