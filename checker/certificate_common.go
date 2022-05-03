// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

const publicKeyLineLength = 45

type CertificateInfo struct {
	CommonName   string `json:"commonName"`
	Status       Status `json:"-"`
	StatusString string `json:"status"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	Expiration   string `json:"expiration"`
	Message      string `json:"message,omitempty"`
	Error        string `json:"error,omitempty"`
}

func NewCertificateInfo(cert *x509.Certificate, parent *x509.Certificate, forceParentToCheck bool) CertificateInfo {
	status := OK
	var msg, errmsg string

	err := x509util.VerifyCertificate(cert, parent, currentTime, forceParentToCheck)
	if err != nil {
		status = ERROR
		errmsg = err.Error()
	}

	return CertificateInfo{
		CommonName:   cert.Subject.CommonName,
		Status:       status,
		StatusString: status.String(),
		Subject:      x509util.DistinguishedName(cert.Subject, dnType),
		Issuer:       x509util.DistinguishedName(cert.Issuer, dnType),
		Expiration:   cert.NotAfter.Local().Format(timeFormat),
		Message:      msg,
		Error:        errmsg,
	}
}

type CertificateDetails struct {
	Issuer                     string                      `json:"issuer"`
	Subject                    string                      `json:"subject"`
	SubjectAltName             []subjectAltName            `json:"subjectAltName,omitempty"`
	Validity                   validity                    `json:"validity"`
	Version                    string                      `json:"version,omitempty"`
	SerialNumber               string                      `json:"serialNumber,omitempty"`
	SignatureAlgorithm         string                      `json:"signatureAlgorithm,omitempty"`
	SubjectPublicKeyInfo       *publicKeyInfo              `json:"subjectPublicKeyInfo,omitempty"`
	AuthorityKeyIdentifier     string                      `json:"authorityKeyIdentifier,omitempty"`
	SubjectKeyIdentifier       string                      `json:"subjectKeyIdentifier,omitempty"`
	KeyUsage                   []string                    `json:"keyUsage,omitempty"`
	ExtKeyUsage                []string                    `json:"extendedKeyUsage,omitempty"`
	BasicConstraints           *basicConstraints           `json:"basicConstraints,omitempty"`
	CRLDistributionPoints      []string                    `json:"cRLDistributionPoints,omitempty"`
	AuthorityInformationAccess *authorityInformationAccess `json:"authorityInformationAccess,omitempty"`
}

type subjectAltName struct {
	DNS       string `json:"dns,omitempty"`
	IPAddress string `json:"iPAddress,omitempty"`
	Email     string `json:"email,omitempty"`
	URI       string `json:"uri,omitempty"`
}

type validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type publicKeyInfo struct {
	Name               string `json:"-"`
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm,omitempty"`
	Type               string `json:"type,omitempty"`
	Modulus            string `json:"modulus,omitempty"`
	Exponent           string `json:"exponent,omitempty"`
	Pub                string `json:"pub,omitempty"`
	NISTCurve          string `json:"nISTCurve,omitempty"`
}

type authorityInformationAccess struct {
	OCSP      []string `json:"oCSP,omitempty"`
	CAIssuers []string `json:"cAIssuers,omitempty"`
}

type basicConstraints struct {
	CA                bool   `json:"cA"`
	PathLenConstraint string `json:"pathLenConstraint,omitempty"`
}

func NewCertificateDetails(cert *x509.Certificate) *CertificateDetails {
	var (
		sans           []subjectAltName
		version        string
		serialNumber   string
		sigAlgo        string
		subjPubKeyInfo *publicKeyInfo
		authKeyId      string
		subjKeyId      string
		keyUsage       []string
		extKeyUsage    []string
		authInfoAccess *authorityInformationAccess
		bc             *basicConstraints
	)

	sans = getSubjectAltNames(cert)

	if verbose > 1 {
		var omit bool
		if verbose == 2 {
			omit = true
		}
		version = fmt.Sprintf("%d", cert.Version)
		serialNumber = x509util.EncodeUpperCase2DigitHex(cert.SerialNumber.Bytes())
		sigAlgo = strings.Replace(cert.SignatureAlgorithm.String(), "-", "With", 1)
		pubKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(cert)
		subjPubKeyInfo = getPublicKeyInfo(pubKeyInfo, omit)
		authKeyId = x509util.EncodeUpperCase2DigitHex(cert.AuthorityKeyId)
		subjKeyId = x509util.EncodeUpperCase2DigitHex(cert.SubjectKeyId)

		for _, u := range x509util.KeyUsage(cert.KeyUsage).Decompose() {
			keyUsage = append(keyUsage, fmt.Sprintf("%s (%s)", u.Message(), u.String()))
		}
		for _, u := range cert.ExtKeyUsage {
			extKeyUsage = append(extKeyUsage, fmt.Sprintf("%s (%s)", x509util.ExtKeyUsage(u).Message(), x509util.ExtKeyUsage(u).String()))
		}

		if cert.BasicConstraintsValid {
			var pathLen string
			if (cert.MaxPathLenZero && cert.MaxPathLen == 0) || cert.MaxPathLen > 0 {
				pathLen = strconv.Itoa(cert.MaxPathLen)
			}
			bc = &basicConstraints{
				CA:                cert.IsCA,
				PathLenConstraint: pathLen,
			}
		}

		if cert.OCSPServer != nil && cert.IssuingCertificateURL != nil {
			authInfoAccess = &authorityInformationAccess{
				OCSP:      cert.OCSPServer,
				CAIssuers: cert.IssuingCertificateURL,
			}
		}
	}

	return &CertificateDetails{
		Issuer:         x509util.DistinguishedName(cert.Issuer, dnType),
		Subject:        x509util.DistinguishedName(cert.Subject, dnType),
		SubjectAltName: sans,
		Validity: validity{
			NotBefore: cert.NotBefore.Format(timeFormat),
			NotAfter:  cert.NotAfter.Format(timeFormat),
		},
		Version:                    version,
		SerialNumber:               serialNumber,
		SignatureAlgorithm:         sigAlgo,
		SubjectPublicKeyInfo:       subjPubKeyInfo,
		AuthorityKeyIdentifier:     authKeyId,
		SubjectKeyIdentifier:       subjKeyId,
		KeyUsage:                   keyUsage,
		ExtKeyUsage:                extKeyUsage,
		CRLDistributionPoints:      cert.CRLDistributionPoints,
		BasicConstraints:           bc,
		AuthorityInformationAccess: authInfoAccess,
	}
}

func getSubjectAltNames(cert *x509.Certificate) []subjectAltName {
	var sans []subjectAltName

	for _, dNSName := range cert.DNSNames {
		sans = append(sans, subjectAltName{DNS: dNSName})
	}
	for _, iPAddress := range cert.IPAddresses {
		sans = append(sans, subjectAltName{IPAddress: iPAddress.String()})
	}
	for _, rfc822Name := range cert.EmailAddresses {
		sans = append(sans, subjectAltName{Email: rfc822Name})
	}
	for _, uri := range cert.URIs {
		sans = append(sans, subjectAltName{URI: uri.String()})
	}
	return sans
}

func getPublicKeyInfo(pubKeyInfo x509util.PublicKeyInfo, omit bool) *publicKeyInfo {
	var (
		keyString string
		modulus   string
		exponent  string
		pub       string
		nISTCurve string
	)

	if omit && len(pubKeyInfo.KeyString) > publicKeyLineLength {
		keyString = pubKeyInfo.KeyString[:publicKeyLineLength] + "...(omitted)"
	} else {
		keyString = pubKeyInfo.KeyString
	}

	switch pubKeyInfo.PublicKeyAlgorithm {
	case x509.RSA:
		modulus = keyString
		exponent = pubKeyInfo.Option["Exponent"]
	case x509.ECDSA:
		pub = keyString
		nISTCurve = pubKeyInfo.Option["NIST CURVE"]
	case x509.Ed25519:
		pub = keyString
	}

	return &publicKeyInfo{
		Name:               pubKeyInfo.SourceName,
		PublicKeyAlgorithm: pubKeyInfo.PublicKeyAlgorithm.String(),
		Type:               pubKeyInfo.Type,
		Modulus:            modulus,
		Exponent:           exponent,
		Pub:                pub,
		NISTCurve:          nISTCurve,
	}
}

func createPublicKeyStringLines(keyString string) []string {
	var lines []string
	for i := 0; i < len(keyString); i = i + publicKeyLineLength {
		var line string
		if i+publicKeyLineLength < len(keyString) {
			line = keyString[i : i+publicKeyLineLength]
		} else {
			line = keyString[i:]
		}
		lines = append(lines, line)
	}
	return lines
}

func printCertificate(indent int, details *CertificateDetails) {
	printKeyValueIfExists(indent, "Issuer ", details.Issuer)
	printKeyValueIfExists(indent, "Subject", details.Subject)
	printSubjectAltName(indent, details.SubjectAltName)
	printKey(indent, "Validity")
	printKeyValueIfExists(indent+4, "Not Before", details.Validity.NotBefore)
	printKeyValueIfExists(indent+4, "Not After ", details.Validity.NotAfter)

	if verbose > 1 {
		printKeyValueIfExists(indent, "Version", details.Version)
		printKeyValuesIfExists(indent, "Serial Number", []string{details.SerialNumber})
		printKeyValueIfExists(indent, "Signature Algorithm", details.SignatureAlgorithm)

		printKey(indent, "Subject Public Key Info")
		printPublicKey(indent, details.SubjectPublicKeyInfo)

		printKeyValuesIfExists(indent, "Authority Key Identifier", []string{details.AuthorityKeyIdentifier})
		printKeyValuesIfExists(indent, "Subject Key Identifier", []string{details.SubjectKeyIdentifier})
		printKeyValuesIfExists(indent, "Key Usage", details.KeyUsage)
		printKeyValuesIfExists(indent, "Extended Key Usage", details.ExtKeyUsage)

		if details.BasicConstraints != nil {
			printKey(indent, "Basic Constraints")
			printKeyValueIfExists(indent+4, "CA", strconv.FormatBool(details.BasicConstraints.CA))
			printKeyValueIfExists(indent+4, "pathlen", details.BasicConstraints.PathLenConstraint)
		}

		printKeyValuesIfExists(indent, "CRL Distribution Points", details.CRLDistributionPoints)

		if details.AuthorityInformationAccess != nil {
			printKey(indent, "Authority Information Access")
			printKeyValueIfExists(indent+4, "OCSP", strings.Join(details.AuthorityInformationAccess.OCSP, ", "))
			printKeyValueIfExists(indent+4, "CA Issuers", strings.Join(details.AuthorityInformationAccess.CAIssuers, ", "))
		}
	}
}

func printSubjectAltName(indent int, sans []subjectAltName) {
	if len(sans) == 0 {
		return
	}

	printKey(indent, "Subject Alternative Name")
	for _, item := range sans {
		printKeyValueIfExists(indent+4, "DNS", item.DNS)
		printKeyValueIfExists(indent+4, "IP Address", item.IPAddress)
		printKeyValueIfExists(indent+4, "email", item.Email)
		printKeyValueIfExists(indent+4, "URI", item.URI)
	}
}

func printPublicKey(indent int, pubKeyInfo *publicKeyInfo) {
	printKeyValueIfExists(indent+4, "Public Key Algorithm", pubKeyInfo.PublicKeyAlgorithm)
	printIndentedLine(indent+8, pubKeyInfo.Type)
	printKeyValuesIfExists(indent+8, "Modulus", createPublicKeyStringLines(pubKeyInfo.Modulus))
	printKeyValuesIfExists(indent+8, "pub", createPublicKeyStringLines(pubKeyInfo.Pub))
	printKeyValueIfExists(indent+8, "Exponent", pubKeyInfo.Exponent)
	printKeyValueIfExists(indent+8, "NIST Curve", pubKeyInfo.NISTCurve)
}
