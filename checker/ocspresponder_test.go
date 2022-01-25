// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckOCSPResponder(t *testing.T) {
	var (
		state checker.State
	)
	w := strings.Builder{}
	checker.SetOutput(&w)
	assert := assert.New(t)

	hostname := "www.google.com"
	tlsConfig := tls.Config{
		ServerName:             hostname,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}

	dialer := net.Dialer{Timeout: time.Second * time.Duration(5)}
	conn, _ := tls.DialWithDialer(&dialer, "tcp4", hostname+":443", &tlsConfig)
	defer conn.Close()
	connectionState := conn.ConnectionState()
	certs := connectionState.PeerCertificates
	targetCert := certs[0]
	issuer := certs[1]
	intermediateCerts := certs[2:]

	// Response status: good
	// OK: certificate is valid
	//     OCSP Response Data:
	//         OCSP Response Status: success (0x0)
	//         Cert Status: good
	//         Produced At: 2021-06-28 06:39:00 +0000 UTC
	//         This Update: 2021-06-27 06:39:22 +0000 UTC
	//         Next Update: 2021-06-29 06:39:22 +0000 UTC
	//     Certificate:
	//         Issuer : CN=Intermediate CA A RSA
	//         Subject: CN=Intermediate CA A RSA OCSP Responder
	//         Validity:
	//             Not Before: 2021-06-28 06:23:10 +0000 UTC
	//             Not After : 2022-06-28 06:23:10 +0000 UTC
	//         Subject Public Key Info:
	//             Public Key Algorithm: RSA
	//                 RSA Public-Key: (2048 bit)
	//                 Modulus:
	//                     00:fe:6b:e6:fc:5a:21:e3:34:74:24:cc:73:fb:d4:
	//                     ...(omitted)
	//                 Exponent: 65537 (0x10001)
	state = checker.CheckOCSPResponder(targetCert, issuer, intermediateCerts, nil)
	assert.Equal(checker.OK, state.Status)
	assert.Equal("certificate is valid", state.Message)

	w.Reset()
	state.Print()
	assert.Equal(w.String(), "OK: certificate is valid\n")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `    OCSP Response Data:
        OCSP Response Status: successful (0x0)
        Cert Status: good
`)

}
