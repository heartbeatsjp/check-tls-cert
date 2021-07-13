// Copyright 2011, 2021 The Go Authors and HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package is a modification of the crypto.x509.pkix package.
// See also:
//     https://golang.org/src/crypto/x509/pkix/pkix.go

package x509util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

// DNType is a type of a Distinguished Name.
type DNType int

// DNType name
const (
	// strict format (RFC 4514)
	StrictDN = DNType(iota)

	// loose format with space
	LooseDN

	// OpenSSL format
	OpenSSLDN
)

// DistinguishedName converts Distinguished Name to the specified type.
func DistinguishedName(dn pkix.Name, dnType DNType) string {
	var converted string
	switch dnType {
	case StrictDN:
		converted = dn.String()
	case LooseDN:
		converted = toLooseDN(dn)
	case OpenSSLDN:
		converted = toOpenSSLDN(dn)
	default:
		converted = dn.String()
	}
	return converted
}

var attributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}

func toLooseDN(dn pkix.Name) string {
	r := dn.ToRDNSequence()
	s := ""
	for i := 0; i < len(r); i++ {
		rdn := r[len(r)-1-i]
		if i > 0 {
			s += ", "
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}

			oidString := tv.Type.String()
			typeName, ok := attributeTypeNames[oidString]
			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					s += oidString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}

				typeName = oidString
			}

			valueString := fmt.Sprint(tv.Value)
			escaped := make([]rune, 0, len(valueString))

			for k, c := range valueString {
				escape := false

				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escape = true

				case ' ':
					escape = k == 0 || k == len(valueString)-1

				case '#':
					escape = k == 0
				}

				if escape {
					escaped = append(escaped, '\\', c)
				} else {
					escaped = append(escaped, c)
				}
			}

			s += typeName + "=" + string(escaped)
		}
	}

	return s
}

func toOpenSSLDN(dn pkix.Name) string {
	r := dn.ToRDNSequence()
	s := ""
	for i := 0; i < len(r); i++ {
		rdn := r[i]
		if i > 0 {
			s += ", "
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}

			oidString := tv.Type.String()
			typeName, ok := attributeTypeNames[oidString]
			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					s += oidString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}

				typeName = oidString
			}

			valueString := fmt.Sprint(tv.Value)
			escaped := make([]rune, 0, len(valueString))

			for k, c := range valueString {
				escape := false

				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escape = true

				case ' ':
					escape = k == 0 || k == len(valueString)-1

				case '#':
					escape = k == 0
				}

				if escape {
					escaped = append(escaped, '\\', c)
				} else {
					escaped = append(escaped, c)
				}
			}

			s += typeName + " = " + string(escaped)
		}
	}

	return s
}
