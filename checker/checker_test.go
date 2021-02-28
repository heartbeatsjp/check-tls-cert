// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/stretchr/testify/assert"
)

func TestStatusCode(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(0, checker.OK.Code())
	assert.Equal(1, checker.WARNING.Code())
	assert.Equal(2, checker.CRITICAL.Code())
	assert.Equal(3, checker.UNKNOWN.Code())
}

func TestStatusString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("OK", checker.OK.String())
	assert.Equal("WARNING", checker.WARNING.String())
	assert.Equal("CRITICAL", checker.CRITICAL.String())
	assert.Equal("UNKNOWN", checker.UNKNOWN.String())
}

func TestStateCode(t *testing.T) {
	assert := assert.New(t)

	okState := checker.State{Status: checker.OK, Message: "ok message"}
	warningState := checker.State{Status: checker.WARNING, Message: "warning message"}
	criticalState := checker.State{Status: checker.CRITICAL, Message: "critical message"}
	unknownState := checker.State{Status: checker.UNKNOWN, Message: "unknown message"}

	assert.Equal(0, okState.Code())
	assert.Equal(1, warningState.Code())
	assert.Equal(2, criticalState.Code())
	assert.Equal(3, unknownState.Code())
}

func TestStateString(t *testing.T) {
	assert := assert.New(t)

	okState := checker.State{Status: checker.OK, Message: "ok message"}
	warningState := checker.State{Status: checker.WARNING, Message: "warning message"}
	criticalState := checker.State{Status: checker.CRITICAL, Message: "critical message"}
	unknownState := checker.State{Status: checker.UNKNOWN, Message: "unknown message"}

	assert.Equal("OK: ok message", okState.String())
	assert.Equal("WARNING: warning message", warningState.String())
	assert.Equal("CRITICAL: critical message", criticalState.String())
	assert.Equal("UNKNOWN: unknown message", unknownState.String())
}

func TestStateListSummarize(t *testing.T) {
	var (
		stateList    checker.StateList
		summaryState checker.State
	)

	assert := assert.New(t)

	okState := checker.State{Status: checker.OK, Message: "ok message"}
	warningState := checker.State{Status: checker.WARNING, Message: "warning message"}
	criticalState := checker.State{Status: checker.CRITICAL, Message: "critical message"}
	unknownState := checker.State{Status: checker.UNKNOWN, Message: "unknown message"}

	stateList = checker.StateList{okState, okState, okState, okState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.OK, summaryState.Status)
	assert.Equal("all checks have been passed", summaryState.Message)

	stateList = checker.StateList{okState, warningState, okState, okState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.WARNING, summaryState.Status)
	assert.Equal("warning message", summaryState.Message)

	stateList = checker.StateList{okState, criticalState, okState, okState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.CRITICAL, summaryState.Status)
	assert.Equal("critical message", summaryState.Message)

	stateList = checker.StateList{okState, unknownState, okState, okState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.UNKNOWN, summaryState.Status)
	assert.Equal("unknown message", summaryState.Message)

	stateList = checker.StateList{okState, warningState, criticalState, okState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.CRITICAL, summaryState.Status)
	assert.Equal("warning message / critical message", summaryState.Message)

	stateList = checker.StateList{okState, criticalState, warningState, okState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.CRITICAL, summaryState.Status)
	assert.Equal("critical message / warning message", summaryState.Message)

	stateList = checker.StateList{okState, criticalState, warningState, unknownState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.UNKNOWN, summaryState.Status)
	assert.Equal("critical message / warning message / unknown message", summaryState.Message)

	stateList = checker.StateList{unknownState, criticalState, warningState, okState}
	summaryState = stateList.Summarize()
	assert.Equal(checker.UNKNOWN, summaryState.Status)
	assert.Equal("unknown message / critical message / warning message", summaryState.Message)
}

func TestStateListCode(t *testing.T) {
	var stateList checker.StateList

	assert := assert.New(t)

	okState := checker.State{Status: checker.OK, Message: "ok message"}
	warningState := checker.State{Status: checker.WARNING, Message: "warning message"}
	criticalState := checker.State{Status: checker.CRITICAL, Message: "critical message"}
	unknownState := checker.State{Status: checker.UNKNOWN, Message: "unknown message"}

	stateList = checker.StateList{okState, okState, okState, okState}
	assert.Equal(0, stateList.Code())

	stateList = checker.StateList{okState, warningState, okState, okState}
	assert.Equal(1, stateList.Code())

	stateList = checker.StateList{okState, criticalState, okState, okState}
	assert.Equal(2, stateList.Code())

	stateList = checker.StateList{okState, unknownState, okState, okState}
	assert.Equal(3, stateList.Code())

	stateList = checker.StateList{okState, warningState, criticalState, okState}
	assert.Equal(2, stateList.Code())

	stateList = checker.StateList{okState, criticalState, warningState, okState}
	assert.Equal(2, stateList.Code())

	stateList = checker.StateList{okState, criticalState, warningState, unknownState}
	assert.Equal(3, stateList.Code())

	stateList = checker.StateList{unknownState, criticalState, warningState, okState}
	assert.Equal(3, stateList.Code())
}
