// Copyright 2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"os"
	"strings"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/stretchr/testify/assert"
)

func TestOutput(t *testing.T) {
	assert := assert.New(t)

	checker.SetOutput(os.Stdout)
	assert.Equal(os.Stdout, checker.GetOutput())
}

func TestPrint(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	checker.Print("TEST")
	assert.Equal("TEST", w.String())
}

func TestPrintf(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	checker.Printf("TEST")
	assert.Equal("TEST", w.String())
}

func TestPrintln(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	checker.Println("TEST")
	assert.Equal("TEST\n", w.String())
}
