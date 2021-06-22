// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util_test

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestDistinguishedName(t *testing.T) {
	assert := assert.New(t)

	dn := pkix.Name{
		CommonName:   "server-a.test",
		Organization: []string{"Example"},
	}

	assert.Equal("CN=server-a.test,O=Example", x509util.DistinguishedName(dn, x509util.StrictDN))
	assert.Equal("CN=server-a.test, O=Example", x509util.DistinguishedName(dn, x509util.LooseDN))
	assert.Equal("O = Example, CN = server-a.test", x509util.DistinguishedName(dn, x509util.OpenSSLDN))
	assert.Equal("CN=server-a.test,O=Example", x509util.DistinguishedName(dn, -1))
}
