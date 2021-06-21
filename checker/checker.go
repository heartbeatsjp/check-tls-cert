// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/mattn/go-colorable"
	"github.com/ttkzw/go-color"
)

// Status is a status code for monitoring.
type Status int

// Status Code
const (
	OK = Status(iota)
	WARNING
	CRITICAL
	UNKNOWN
	INFO  // for internal statuses
	ERROR // for internal statuses
)

var statusString = [...]string{
	OK:       "OK",
	WARNING:  "WARNING",
	CRITICAL: "CRITICAL",
	UNKNOWN:  "UNKNOWN",
	INFO:     "INFO",  // for internal statuses
	ERROR:    "ERROR", // for internal statuses
}

var stdout = colorable.NewColorableStdout()

// Code returns a status code.
func (s Status) Code() int {
	return int(s)
}

// String returns a status string.
func (s Status) String() string {
	i := int(s)
	if 0 <= i && i < len(statusString) {
		return statusString[i]
	}
	return strconv.Itoa(i)
}

// ColorString returns a status string with color.
func (s Status) ColorString() string {
	i := int(s)
	if 0 <= i && i < len(statusString) {
		var c color.Color

		switch s {
		case OK:
			c = color.Green
		case WARNING:
			c = color.Yellow
		case CRITICAL:
			c = color.Red
		case UNKNOWN:
			c = color.Orange
		case INFO:
			c = color.Orange
		case ERROR:
			c = color.Red
		}

		return c.Colorize(statusString[i])
	}
	return strconv.Itoa(i)
}

// State describes a state information.
type State struct {
	Name         string
	Status       Status
	Message      string
	Data         interface{} // Used for testing purposes.
	PrintDetails func(int, x509util.DNType)
}

// Code returns a status code.
func (s State) Code() int {
	return s.Status.Code()
}

// String returns a state string.
func (s State) String() string {
	return fmt.Sprintf("%s: %s", s.Status.String(), s.Message)
}

// Print prints a status message.
func (s State) Print() {
	printf("%s: %s\n", s.Status.ColorString(), s.Message)
}

// PrintName prints a checker name.
func (s State) PrintName() {
	println(color.Orange.Colorize(fmt.Sprintf("[%s]", s.Name)))
}

// StateList is the list of results.
type StateList []State

// Print prints results.
func (list *StateList) Print(verbose int, dnType x509util.DNType) {
	summaryState := list.Summarize()
	printf("%s: %s\n", summaryState.Status.String(), summaryState.Message)
	if verbose == 0 {
		return
	}
	println()

	for _, state := range *list {
		state.PrintName()
		state.Print()
		if verbose > 0 {
			state.PrintDetails(verbose, dnType)
		}
		println("")
	}

	summaryState.PrintName()
	summaryState.Print()

	println()
	switch verbose {
	case 1:
		println("To get more detailed information, use the '-vv' option.")
	case 2:
		println("To get more detailed information, use the '-vvv' option.")
	}
}

// Code returns a status code.
func (list *StateList) Code() int {
	state := list.Summarize()
	return state.Code()
}

// Summarize summarize the list of State.
func (list *StateList) Summarize() State {
	var messages []string

	summaryState := State{
		Name:   "Summary",
		Status: OK,
	}

	for _, state := range *list {
		switch state.Status {
		case CRITICAL:
			if summaryState.Status != CRITICAL && summaryState.Status != UNKNOWN {
				summaryState.Status = state.Status
			}
			messages = append(messages, state.Message)
		case WARNING:
			if summaryState.Status != WARNING && summaryState.Status != CRITICAL && summaryState.Status != UNKNOWN {
				summaryState.Status = state.Status
			}
			messages = append(messages, state.Message)
		case UNKNOWN:
			summaryState.Status = state.Status
			messages = append(messages, state.Message)
		default:
		}
	}

	if summaryState.Status == OK {
		summaryState.Message = "all checks have been passed"
	} else {
		summaryState.Message = strings.Join(messages, " / ")
	}

	return summaryState
}

func printDetailsLine(format string, a ...interface{}) {
	const indentString = "    "
	print(indentString)
	printf(format, a...)
	printf("\n")
}

func print(a ...interface{}) (n int, err error) {
	return fmt.Fprint(stdout, a...)
}

func printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(stdout, format, a...)
}

func println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(stdout, a...)
}
