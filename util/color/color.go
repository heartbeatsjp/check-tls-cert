// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package color

import (
	"fmt"
	"os"

	"github.com/mattn/go-isatty"
)

// Color is a color for output.
type Color int

// Color name
const (
	Reset = Color(iota)
	Black
	Gray
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
	Orange
)

var colorEscapeSequences = [...]string{
	Reset:   "\x1b[0m",
	Black:   "\x1b[1;30m",
	Gray:    "\x1b[1;90m",
	Red:     "\x1b[1;91m",
	Green:   "\x1b[1;92m",
	Yellow:  "\x1b[1;93m",
	Blue:    "\x1b[1;94m",
	Magenta: "\x1b[1;95m",
	Cyan:    "\x1b[1;96m",
	White:   "\x1b[1;97m",
	Orange:  "\x1b[1;38;5;202m",
}

func (c Color) escapeSequence() string {
	if 0 <= c && int(c) < len(colorEscapeSequences) {
		return colorEscapeSequences[c]
	}
	return colorEscapeSequences[0]
}

// Colorize colorizes strings.
func (c Color) Colorize(str string) string {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		return fmt.Sprintf("%s%s%s", c.escapeSequence(), str, Reset.escapeSequence())
	}
	return str
}
