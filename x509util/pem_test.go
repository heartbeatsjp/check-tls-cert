// Copyright 2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util_test

import (
	"os"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestContainsPEMCertificate(t *testing.T) {
	var (
		data []byte
		err  error
	)
	assert := assert.New(t)

	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	assert.Nil(err)
	assert.True(x509util.ContainsPEMCertificate(data))

	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.der")
	assert.Nil(err)
	assert.False(x509util.ContainsPEMCertificate(data))

	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.key")
	assert.Nil(err)
	assert.False(x509util.ContainsPEMCertificate(data))

	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.der")
	assert.Nil(err)
	assert.False(x509util.ContainsPEMCertificate(data))
}

func TestContainsPEMPrivateKey(t *testing.T) {
	var (
		data []byte
		err  error
	)
	assert := assert.New(t)

	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-traditional.key")
	assert.Nil(err)
	assert.True(x509util.ContainsPEMPrivateKey(data))

	data, err = os.ReadFile("../test/testdata/pki/private/server-a-ecdsa-traditional.key")
	assert.Nil(err)
	assert.True(x509util.ContainsPEMPrivateKey(data))

	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.key")
	assert.Nil(err)
	assert.True(x509util.ContainsPEMPrivateKey(data))

	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa-encrypted.key")
	assert.Nil(err)
	assert.True(x509util.ContainsPEMPrivateKey(data))

	data, err = os.ReadFile("../test/testdata/pki/private/server-a-rsa.der")
	assert.Nil(err)
	assert.False(x509util.ContainsPEMPrivateKey(data))

	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	assert.Nil(err)
	assert.False(x509util.ContainsPEMPrivateKey(data))

	data, err = os.ReadFile("../test/testdata/pki/cert/valid/server-a-rsa.der")
	assert.Nil(err)
	assert.False(x509util.ContainsPEMPrivateKey(data))
}
