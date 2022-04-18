// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/ttkzw/go-color"
)

// verbose is a verbose mode.
var verbose int

// SetVerbose sets a verbose mode.
func SetVerbose(v int) {
	verbose = v
}

// GetVerbose gets a verbose mode.
func GetVerbose() int {
	return verbose
}

// dnType is a Distinguished Name type.
var dnType x509util.DNType

// SetDNType sets a Distinguished Name type.
func SetDNType(t x509util.DNType) {
	dnType = t
}

// GetDNType gets a Distinguished Name type.
func GetDNType() x509util.DNType {
	return dnType
}

// currentTime is a current time.
var currentTime time.Time

// SetCurrentTime sets a current time.
func SetCurrentTime(t time.Time) {
	currentTime = t
}

// GetCurrentTime gets a current time.
func GetCurrentTime() time.Time {
	return currentTime
}

type Checker interface {
	Name() string
	Status() Status
	Message() string
	Details() interface{}
	PrintName()
	PrintStatus()
	PrintDetails()
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
			c = color.Chartreuse
		case ERROR:
			c = color.Red
		}

		return c.Colorize(statusString[i])
	}
	return strconv.Itoa(i)
}

// OutputFormat is a output format.
type OutputFormat int

const (
	// Default output format
	DefaultFormat = OutputFormat(iota)

	// JSON output format
	JSONFormat
)

func printCheckerName(c Checker) {
	Println(color.Orange.Colorize(fmt.Sprintf("[%s]", c.Name())))
}

func printCheckerStatus(c Checker) {
	Printf("%s: %s\n", c.Status().ColorString(), c.Message())
}

type Result struct {
	summary  *Summary
	checkers []Checker
}

func NewResult(summary *Summary, list []Checker) *Result {
	return &Result{
		summary:  summary,
		checkers: list,
	}
}

func (r *Result) Print() {
	Printf("%s: %s\n", r.summary.Status().String(), r.summary.Message())
	if verbose == 0 {
		return
	}
	Println()

	for _, c := range r.checkers {
		c.PrintName()
		c.PrintStatus()
		if verbose > 0 {
			c.PrintDetails()
		}
		Println("")
	}

	r.summary.PrintName()
	r.summary.PrintStatus()

	Println()
	switch verbose {
	case 1:
		Println("To get more detailed information, use the '-vv' option.")
	case 2:
		Println("To get more detailed information, use the '-vvv' option.")
	}
}

type JSONableResult struct {
	Metadata jsonableMetadata `json:"metadata"`
	Result   jsonableResult   `json:"result,omitempty"`
}

type jsonableMetadata struct {
	Name      string `json:"name"`
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
	Status    int    `json:"status"`
}

type jsonableResult struct {
	Summary  *jsonableChecker   `json:"summary"`
	Checkers []*jsonableChecker `json:"checkers,omitempty"`
}

type jsonableChecker struct {
	Name    string      `json:"name"`
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Details interface{} `json:"details,omitempty"`
}

func (r *Result) PrintJSON() {
	var summary *jsonableChecker
	var checkers []*jsonableChecker
	if verbose > 0 {
		for _, c := range r.checkers {
			jc := &jsonableChecker{
				Name:    c.Name(),
				Status:  c.Status().String(),
				Message: c.Message(),
				Details: c.Details(),
			}
			checkers = append(checkers, jc)
		}
	}
	summary = &jsonableChecker{
		Name:    r.summary.Name(),
		Status:  r.summary.Status().String(),
		Message: r.summary.Message(),
	}

	jr := JSONableResult{
		Metadata: jsonableMetadata{
			Name:      "check-tls-cert",
			Timestamp: time.Now().Format(time.RFC3339),
			Command:   strings.Join(os.Args, " "),
			Status:    r.summary.Status().Code(),
		},
		Result: jsonableResult{
			Summary:  summary,
			Checkers: checkers,
		},
	}
	b, _ := json.MarshalIndent(jr, "", "  ")
	Println(string(b))
}
