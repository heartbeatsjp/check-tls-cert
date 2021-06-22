// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/ttkzw/go-color"
)

// output is an io.Writer. It's os.Stdout by default.
var output io.Writer

func init() {
	output = os.Stdout
}

// SetOutput sets the output.
func SetOutput(w io.Writer) {
	output = w
}

// GetOutput gets the output.
func GetOutput() io.Writer {
	return output
}

// Print formats using the default formats for its operands and writes to the specified output.
// Spaces are added between operands when neither is a string.
// It returns the number of bytes written and any write error encountered.
func Print(a ...interface{}) (n int, err error) {
	return fmt.Fprint(output, a...)
}

// Printf formats according to a format specifier and writes to the specified output.
// It returns the number of bytes written and any write error encountered.
func Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(output, format, a...)
}

// Println formats using the default formats for its operands and writes to the specified output.
// Spaces are always added between operands and a newline is appended.
// It returns the number of bytes written and any write error encountered.
func Println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(output, a...)
}

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
	Printf("%s: %s\n", s.Status.ColorString(), s.Message)
}

// PrintName prints a checker name.
func (s State) PrintName() {
	Println(color.Orange.Colorize(fmt.Sprintf("[%s]", s.Name)))
}

// StateList is the list of results.
type StateList []State

// Print prints results.
func (list *StateList) Print(verbose int, dnType x509util.DNType) {
	summaryState := list.Summarize()
	Printf("%s: %s\n", summaryState.Status.String(), summaryState.Message)
	if verbose == 0 {
		return
	}
	Println()

	for _, state := range *list {
		state.PrintName()
		state.Print()
		if verbose > 0 {
			state.PrintDetails(verbose, dnType)
		}
		Println("")
	}

	summaryState.PrintName()
	summaryState.Print()

	Println()
	switch verbose {
	case 1:
		Println("To get more detailed information, use the '-vv' option.")
	case 2:
		Println("To get more detailed information, use the '-vvv' option.")
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
	Print(indentString)
	Printf(format, a...)
	Printf("\n")
}
