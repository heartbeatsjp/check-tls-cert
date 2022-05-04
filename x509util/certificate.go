// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// ParseCertificateFiles parses certifcate files in PEM format and returns certificates.
func ParseCertificateFiles(certFiles ...string) (certs []*x509.Certificate, err error) {
	for _, certFile := range certFiles {
		if certFile == "" {
			continue
		}

		data, err := os.ReadFile(certFile)
		if err != nil {
			return nil, err
		}

		if ContainsPEMCertificate(data) {
			// PEM format
			c, err := parsePEMCertificates(data)
			if err == nil {
				certs = append(certs, c...)
			}
		} else if ContainsPEMPrivateKey(data) {
			// Skip
		} else {
			// DER format
			c, err := x509.ParseCertificate(data)
			if err == nil {
				certs = append(certs, c)
			}
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates")
	}

	return certs, nil
}

// ParseCertificateFile parses a certifcate file in PEM format and returns the first certificate.
func ParseCertificateFile(certFile string) (cert *x509.Certificate, err error) {
	certs, err := ParseCertificateFiles(certFile)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	return certs[0], nil
}

func parsePEMCertificates(data []byte) (certs []*x509.Certificate, err error) {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		data = rest
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// GetRootCertPool retrieves the root certificate pool.
// If root certificates are provided, return a certificate pool for them.
// If root certificates are not provided, return the system certificate pool.
func GetRootCertPool(rootCerts []*x509.Certificate, enableSSLCertDir bool) (*x509.CertPool, error) {
	var (
		roots *x509.CertPool
		err   error
	)

	if len(rootCerts) > 0 {
		roots = x509.NewCertPool()
		for _, cert := range rootCerts {
			roots.AddCert(cert)
		}
	} else {
		if !enableSSLCertDir {
			os.Setenv("SSL_CERT_DIR", ":")
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
	}

	return roots, nil
}

// GetIntermediateCertPool retrieves an intermediate certificate pool.
func GetIntermediateCertPool(intermediateCerts []*x509.Certificate) *x509.CertPool {
	intermediates := x509.NewCertPool()
	for _, cert := range intermediateCerts {
		intermediates.AddCert(cert)
	}
	return intermediates
}

// BuildCertificateChains builds certificate chains.
func BuildCertificateChains(certs []*x509.Certificate, rootCertPool *x509.CertPool, currentTime time.Time) (chains [][]*x509.Certificate) {
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	opts := x509.VerifyOptions{
		Roots:       rootCertPool,
		CurrentTime: currentTime,
	}

	// If a valid root certificate is found, build a chain with it.
	for i := 0; i < len(certs); i++ {
		candidateChains, err := certs[i].Verify(opts)
		if err != nil {
			continue
		}

		for _, candidateChain := range candidateChains {
			if len(candidateChain) != 2 {
				continue
			}

			candidateRootCert := candidateChain[1]

			if !bytes.Equal(candidateRootCert.RawIssuer, candidateRootCert.RawSubject) {
				continue
			}

			var chain []*x509.Certificate
			chain = append(chain, certs[:i+1]...)
			chain = append(chain, candidateRootCert)
			chains = append(chains, chain)
		}
	}

	// If no valid root certificate is found, a chain without any root certificate is returned.
	if len(chains) == 0 {
		chains = append(chains, certs)
	}

	return chains
}

const timeFormat = "2006-01-02 15:04:05 -0700"

// VerifyValidity verifies the validity of the certificate.
func VerifyValidity(cert *x509.Certificate, days int, currentTime time.Time) (message string, err error) {
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	expirationDays := int(math.Ceil(cert.NotAfter.Sub(currentTime).Hours() / 24))

	switch {
	case cert.NotBefore.After(currentTime):
		err = fmt.Errorf("the certificate is not yet valid and will be valid on %s", cert.NotBefore.Local().Format(timeFormat))
	case cert.NotAfter.Before(currentTime):
		err = fmt.Errorf("the certificate has expired on %s", cert.NotAfter.Local().Format(timeFormat))
	case cert.NotAfter.Before(currentTime.AddDate(0, 0, days)):
		err = fmt.Errorf("the certificate will expire in %d days on %s", expirationDays, cert.NotAfter.Local().Format(timeFormat))
	default:
		message = fmt.Sprintf("the certificate will expire in %d days on %s", expirationDays, cert.NotAfter.Local().Format(timeFormat))
	}
	return
}

// VerifyCertificate verifies a certificate using the parent certificate.
func VerifyCertificate(cert *x509.Certificate, parent *x509.Certificate, currentTime time.Time, forceParentToCheck bool) error {
	var messages []string

	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	if len(cert.Raw) == 0 {
		messages = append(messages, "certificate parse error")
	}

	if len(cert.UnhandledCriticalExtensions) > 0 {
		messages = append(messages, x509.UnhandledCriticalExtension{}.Error())
	}

	if parent == nil {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.BasicConstraintsValid && cert.IsCA {
			// Since the certificate is a self-signed root certificate, the signature check should not fail.
			if err := cert.CheckSignatureFrom(cert); err != nil {
				// Workaround for SHA-1 signatures.
				// If an error occurs due to a SHA-1 signature, ignore it.
				var ignoreError = false
				switch e := err.(type) {
				case x509.InsecureAlgorithmError:
					if x509.SignatureAlgorithm(e) == x509.SHA1WithRSA || x509.SignatureAlgorithm(e) == x509.ECDSAWithSHA1 {
						ignoreError = true
					}
				}
				if !ignoreError {
					messages = append(messages, err.Error())
				}
			}
		} else {
			if forceParentToCheck {
				// Since the certificate is not a root certificate, it must be signed by a known authority.
				messages = append(messages, x509.UnknownAuthorityError{Cert: cert}.Error())
			}
		}
	} else {
		if len(parent.Raw) == 0 {
			messages = append(messages, "parent certificate parse error")
		}

		if !bytes.Equal(cert.RawIssuer, parent.RawSubject) {
			err := x509.CertificateInvalidError{Cert: cert, Reason: x509.NameMismatch, Detail: ""}
			messages = append(messages, err.Error())
		}

		if err := cert.CheckSignatureFrom(parent); err != nil {
			messages = append(messages, err.Error()+" / parent certificate may not be correct issuer")
		}
	}

	if _, err := VerifyValidity(cert, 0, currentTime); err != nil {
		messages = append(messages, err.Error())
	}

	if len(messages) > 0 {
		return errors.New(strings.Join(messages, " / "))
	}

	return nil
}

// KeyUsage represents the set of actions that are valid for a given key. It's
// a bitmap of the KeyUsage* constants.
//
// See also: x509.KeyUsage
type KeyUsage int

const (
	// Key Usage: digitalSignature (Bit 0)
	KeyUsageDigitalSignature KeyUsage = 1 << iota

	// Key Usage: contentCommitment (Bit 1)
	KeyUsageContentCommitment

	// Key Usage: keyEncipherment (Bit 2)
	KeyUsageKeyEncipherment

	// Key Usage: dataEncipherment (Bit 3)
	KeyUsageDataEncipherment

	// Key Usage: keyAgreement (Bit 4)
	KeyUsageKeyAgreement

	// Key Usage: keyCertSign (Bit 5)
	KeyUsageCertSign

	// Key Usage: cRLSign (Bit 6)
	KeyUsageCRLSign

	// Key Usage: encipherOnly (Bit 7)
	KeyUsageEncipherOnly

	// Key Usage: decipherOnly (Bit 8)
	KeyUsageDecipherOnly
)

func (u KeyUsage) String() string {
	switch u {
	case KeyUsageDigitalSignature:
		return "digitalSignature"
	case KeyUsageContentCommitment:
		return "contentCommitment"
	case KeyUsageKeyEncipherment:
		return "keyEncipherment"
	case KeyUsageDataEncipherment:
		return "dataEncipherment"
	case KeyUsageKeyAgreement:
		return "keyAgreement"
	case KeyUsageCertSign:
		return "keyCertSign"
	case KeyUsageCRLSign:
		return "cRLSign"
	case KeyUsageEncipherOnly:
		return "encipherOnly"
	case KeyUsageDecipherOnly:
		return "decipherOnly"
	}
	return fmt.Sprintf("Unknown Key Usage Bit(%s)", strconv.FormatFloat(math.Floor(math.Log2(float64(u))), 'g', -1, 64))
}

func (u KeyUsage) Message() string {
	switch u {
	case KeyUsageDigitalSignature:
		return "Digital Signature"
	case KeyUsageContentCommitment:
		return "Content Commitment"
	case KeyUsageKeyEncipherment:
		return "Key Encipherment"
	case KeyUsageDataEncipherment:
		return "Data Encipherment"
	case KeyUsageKeyAgreement:
		return "Key Agreement"
	case KeyUsageCertSign:
		return "Certificate Sign"
	case KeyUsageCRLSign:
		return "CRL Sign"
	case KeyUsageEncipherOnly:
		return "Encipher Only"
	case KeyUsageDecipherOnly:
		return "Decipher Only"
	}
	return fmt.Sprintf("Unknown Key Usage Bit(%s)", strconv.FormatFloat(math.Floor(math.Log2(float64(u))), 'g', -1, 64))
}

func (u KeyUsage) Decompose() []KeyUsage {
	var keyUsages []KeyUsage
	for i := KeyUsage(1); i <= KeyUsageDecipherOnly; i = i * 2 {
		if (u & i) != 0 {
			keyUsages = append(keyUsages, i)
		}
	}
	return keyUsages
}

// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
//
// See also: x509.ExtKeyUsage
type ExtKeyUsage int

const (
	// Extended Key Usage: anyExtendedKeyUsage (id-ce-extKeyUsage 0)
	ExtKeyUsageAny ExtKeyUsage = iota

	// Extended Key Usage: id-kp-serverAuth (id-kp 1)
	ExtKeyUsageServerAuth

	// Extended Key Usage: id-kp-clientAuth (id-kp 2)
	ExtKeyUsageClientAuth

	// Extended Key Usage: id-kp-codeSigning (id-kp 3)
	ExtKeyUsageCodeSigning

	// Extended Key Usage: id-kp-emailProtection (id-kp 4)
	ExtKeyUsageEmailProtection

	// Extended Key Usage: id-kp-ipsecEndSystem (id-kp 5)
	ExtKeyUsageIPSECEndSystem

	// Extended Key Usage: id-kp-ipsecTunnel (id-kp 6)
	ExtKeyUsageIPSECTunnel

	// Extended Key Usage: id-kp-ipsecUser (id-kp 7)
	ExtKeyUsageIPSECUser

	// Extended Key Usage: id-kp-timeStamping (id-kp 8)
	ExtKeyUsageTimeStamping

	// Extended Key Usage: id-kp-OCSPSigning (id-kp 9)
	ExtKeyUsageOCSPSigning

	// Extended Key Usage: Microsoft Server Gated Crypto (OID 1.3.6.1.4.1.311.10.3.3)
	ExtKeyUsageMicrosoftServerGatedCrypto

	// Extended Key Usage: Netscape Server Gated Crypto (OID 2.16.840.1.113730.4.1)
	ExtKeyUsageNetscapeServerGatedCrypto

	// Extended Key Usage: SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID (OID 1.3.6.1.4.1.311.2.1.22)
	ExtKeyUsageMicrosoftCommercialCodeSigning

	// Extended Key Usage: Kernel Mode Code Signing (OID 1.3.6.1.4.1.311.61.1.1)
	ExtKeyUsageMicrosoftKernelCodeSigning
)

func (u ExtKeyUsage) String() string {
	switch u {
	case ExtKeyUsageAny:
		return "any"
	case ExtKeyUsageServerAuth:
		return "serverAuth"
	case ExtKeyUsageClientAuth:
		return "clientAuth"
	case ExtKeyUsageCodeSigning:
		return "codeSigning"
	case ExtKeyUsageEmailProtection:
		return "emailProtection"
	case ExtKeyUsageIPSECEndSystem:
		return "ipsecEndSystem"
	case ExtKeyUsageIPSECTunnel:
		return "ipsecTunnel"
	case ExtKeyUsageIPSECUser:
		return "ipsecUser"
	case ExtKeyUsageTimeStamping:
		return "timeStamping"
	case ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case ExtKeyUsageMicrosoftServerGatedCrypto:
		return "microsoftServerGatedCrypto"
	case ExtKeyUsageNetscapeServerGatedCrypto:
		return "netscapeServerGatedCrypto"
	case ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "microsoftCommercialCodeSigning"
	case ExtKeyUsageMicrosoftKernelCodeSigning:
		return "microsoftKernelCodeSigning"
	}
	return "Unknown Extended Key Usage"
}

func (u ExtKeyUsage) Message() string {
	switch u {
	case ExtKeyUsageAny:
		return "Any"
	case ExtKeyUsageServerAuth:
		return "TLS Web Server Authentication"
	case ExtKeyUsageClientAuth:
		return "TLS Web Client Authentication"
	case ExtKeyUsageCodeSigning:
		return "Code Signing"
	case ExtKeyUsageEmailProtection:
		return "E-mail Protection"
	case ExtKeyUsageIPSECEndSystem:
		return "IPSec End System"
	case ExtKeyUsageIPSECTunnel:
		return "IPSec Tunnel"
	case ExtKeyUsageIPSECUser:
		return "IPSec User"
	case ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	case ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft Server Gated Crypto"
	case ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape Server Gated Crypto"
	case ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "Microsoft Commercial Code Signing"
	case ExtKeyUsageMicrosoftKernelCodeSigning:
		return "Microsoft Kernel Mode Code Signing"
	}
	return "Unknown Extended Key Usage"
}
