// Copyright 2021-2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import "bytes"

func ContainsPEMCertificate(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----"))
}

func ContainsPEMPrivateKey(data []byte) bool {
	pemTypes := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
	}

	for _, t := range pemTypes {
		if bytes.Contains(data, []byte(t)) {
			return true
		}
	}
	return false
}
