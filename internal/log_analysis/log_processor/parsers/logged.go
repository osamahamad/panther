package parsers

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"reflect"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// WithLogger logs errors and results of a log parser.
// Parser errors are logged at ERROR level.
// Parser results are logged at DEBUG level.
// Swaps loggers if `parser` argument already has logger.
// Removes logging if `parser` argument already has logger and `logger` is `nil`.
// Returns `parser` argument untouched if `logger` is `nil`.
func WithLogger(parser pantherlog.LogParser, logger *zap.Logger) pantherlog.LogParser {
	// Switch logger
	if logged, ok := parser.(*loggedParser); ok {
		if logger == nil {
			return logged.LogParser
		}
		return logged
	}

	// Return parser untouched if no logger is provided
	if logger == nil {
		return parser
	}

	// Use the inner parser for the error message
	inner := parser
	if m, ok := parser.(*Metered); ok {
		inner = m.Parser()
	}
	typeName := reflect.Indirect(reflect.ValueOf(inner)).Type().String()
	return &loggedParser{
		LogParser:    parser,
		failMessage:  fmt.Sprintf(`%s.ParseLog() failed`, typeName),
		debugMessage: fmt.Sprintf(`%s.ParseLog() results`, typeName),
		logger:       logger,
	}
}

type loggedParser struct {
	pantherlog.LogParser
	logger       *zap.Logger
	failMessage  string
	debugMessage string
}

func (p *loggedParser) ParseLog(log string) ([]*pantherlog.Result, error) {
	results, err := p.LogParser.ParseLog(log)
	if err != nil {
		p.logger.Error(p.failMessage, zap.Error(err))
	} else {
		p.logger.Debug(p.debugMessage, zap.Any(`results`, results))
	}
	return results, err
}
