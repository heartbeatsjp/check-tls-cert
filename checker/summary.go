// Copyright 2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"strings"
)

type Summary struct {
	name    string
	status  Status
	message string
}

func NewSummary(list []Checker) *Summary {
	const name = "Summary"

	var messages []string

	status := OK
	message := "all checks have been passed"

	for _, c := range list {
		switch c.Status() {
		case CRITICAL:
			if status != CRITICAL && status != UNKNOWN {
				status = c.Status()
			}
			messages = append(messages, c.Message())
		case WARNING:
			if status != WARNING && status != CRITICAL && status != UNKNOWN {
				status = c.Status()
			}
			messages = append(messages, c.Message())
		case UNKNOWN:
			status = c.Status()
			messages = append(messages, c.Message())
		default:
		}
	}

	if status != OK {
		message = strings.Join(messages, " / ")
	}

	return &Summary{
		name:    name,
		status:  status,
		message: message,
	}
}

func NewErrorSummary(err error) *Summary {
	const name = "Summary"

	return &Summary{
		name:    name,
		status:  UNKNOWN,
		message: err.Error(),
	}
}

func (s *Summary) Name() string {
	return s.name
}

func (s *Summary) Status() Status {
	return s.status
}

func (s *Summary) Message() string {
	return s.message
}

func (s *Summary) Details() interface{} {
	return nil
}

func (s *Summary) PrintName() {
	printCheckerName(s)
}

func (s *Summary) PrintStatus() {
	printCheckerStatus(s)
}

func (s *Summary) PrintDetails() {
	// print nothing
}
