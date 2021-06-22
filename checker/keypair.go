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

// CheckKeyPair checks wheather a private key is paired with a certificate.
func CheckKeyPair(publicKeyInfoInPrivateKey x509util.PublicKeyInfo, publicKeyInfo x509util.PublicKeyInfo) State {
	const name = "Private Key/Certificate Pair"

	printDetails := func(verbose int, dnType x509util.DNType) {
		for _, info := range []x509util.PublicKeyInfo{publicKeyInfoInPrivateKey, publicKeyInfo} {
			printDetailsLine("%s:", info.SourceName)
			printDetailsLine("    Public Key Algorithm: %s", info.PublicKeyAlgorithm.String())

			printDetailsLine("        %s", info.TypeLabel)

			publicKeyTypeName := "pub"
			if info.PublicKeyAlgorithm == x509.RSA {
				publicKeyTypeName = "Modulus"
			}
			printDetailsLine("        %s:", publicKeyTypeName)

			if verbose < 2 {
				printDetailsLine("            %s", info.KeyString[:45])
				printDetailsLine("            ...(omitted)")
			} else if verbose >= 2 {
				const length = 45
				var line string
				for i := 0; i < len(info.KeyString); i = i + length {
					if i+length < len(info.KeyString) {
						line = info.KeyString[i : i+length]

					} else {
						line = info.KeyString[i:]
					}
					printDetailsLine("            %s", line)
				}
			}

			for key, value := range info.Option {
				printDetailsLine("        %s: %s", key, value)
			}
		}

		printDetailsLine("")
		if verbose == 2 {
			printDetailsLine("To get the full public key, use the '-vvv' option.")
		}
		if verbose >= 3 {
			printDetailsLine("The public key information can be obtained with the following command:")
			printDetailsLine("    openssl pkey -in PRIVATE_KEY.pem -noout -text_pub")
			printDetailsLine("    openssl x509 -in CERTIFICATE.pem -noout -pubkey | openssl pkey -pubin -text_pub -noout")
			printDetailsLine("    openssl x509 -in CERTIFICATE.pem -noout -text")
		}
	}

	if publicKeyInfoInPrivateKey.PublicKeyAlgorithm != publicKeyInfo.PublicKeyAlgorithm {
		state := State{
			Name:         name,
			Status:       CRITICAL,
			Message:      "the public key algorithm does not match between the private Key and the certificate",
			PrintDetails: printDetails,
		}
		return state
	}

	isValid := false

	switch publicKeyInfoInPrivateKey.PublicKeyAlgorithm {
	case x509.RSA:
		publicKeyInPrivateKey := publicKeyInfoInPrivateKey.Key.(*rsa.PublicKey)
		if publicKeyInPrivateKey.Equal(publicKeyInfo.Key) {
			isValid = true
		}
	case x509.ECDSA:
		publicKeyInfoInPrivateKey := publicKeyInfoInPrivateKey.Key.(*ecdsa.PublicKey)
		if publicKeyInfoInPrivateKey.Equal(publicKeyInfo.Key) {
			isValid = true
		}
	case x509.Ed25519:
		publicKeyInPrivateKey := publicKeyInfoInPrivateKey.Key.(ed25519.PublicKey)
		if publicKeyInPrivateKey.Equal(publicKeyInfo.Key) {
			isValid = true
		}
	default:
	}

	if !isValid {
		state := State{
			Name:         name,
			Status:       CRITICAL,
			Message:      "the private key is not paired with a certificate",
			PrintDetails: printDetails,
		}
		return state
	}

	state := State{
		Name:         name,
		Status:       OK,
		Message:      "the private key is paired with the certificate",
		Data:         publicKeyInfo,
		PrintDetails: printDetails,
	}
	return state
}
