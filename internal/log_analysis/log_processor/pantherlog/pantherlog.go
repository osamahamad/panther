// Package pantherlog defines types and functions to parse logs for Panther
package pantherlog

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
	"context"
	"io"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

// LogType describes a log type.
// It provides a method to create a new parser and a schema struct to derive tables from.
// LogTypes can be grouped in a `Registry` to have an index of available log types.
type LogType struct {
	Name        string
	Description string
	// A struct value that matches the JSON in the results returned by the LogParser.
	Schema interface{}
	// Factory for new LogParser instances that return results for this log type.
	NewParser func() LogParser
	// Optional definition of a specific method to split a log file into chunks to be processed.
	// If no value is provided `ScanLogLines()` is used.
	NewScanner        func(r io.Reader) LogScanner
	glueTableMetadata *awsglue.GlueTableMetadata
}

// LogParser is the interface to be used for log entry parsers.
type LogParser interface {
	ParseLog(log string) ([]*Result, error)
}

func (t *LogType) GlueTableMetadata() *awsglue.GlueTableMetadata {
	return t.glueTableMetadata
}

// LogHandler is the interface for processing an io.Reader to produce Results
type LogHandler interface {
	// Results should return a channel with the processed results
	Results() <-chan *Result
	// Run should read until EOF, context.Done() or another parse error occurs.
	Run(ctx context.Context) error
}

// Handler produces a LogHandler that processes the input io.Reader using the log type defined parser
func (t *LogType) Handler(r io.Reader) LogHandler {
	return ComposeHandler(t.Scanner(r), t.Parser())
}

func ComposeHandler(scanner LogScanner, parser LogParser) LogHandler {
	return &logHandler{
		results: make(chan *Result),
		parser:  parser,
		scanner: scanner,
	}
}

// Parser returns a new LogParser instance for this log type
func (t *LogType) Parser() LogParser {
	return t.NewParser()
}

// Scanner returns a new LogScanner instance for this log type
func (t *LogType) Scanner(r io.Reader) LogScanner {
	if t.NewScanner != nil {
		return t.NewScanner(r)
	}
	return ScanLogLines(r)
}

// Check verifies a log type is valid
func (t *LogType) Check() error {
	if t == nil {
		return errors.Errorf("nil log type entry")
	}
	if t.Name == "" {
		return errors.Errorf("missing entry log type")
	}
	if t.Description == "" {
		return errors.Errorf("missing description for log type %q", t.Name)
	}

	t.glueTableMetadata = awsglue.NewGlueTableMetadata(models.LogData, t.Name, t.Description, awsglue.GlueTableHourly, t.Schema)

	return checkLogEntrySchema(t.Name, t.Schema)
}

func checkLogEntrySchema(logType string, schema interface{}) error {
	if schema == nil {
		return errors.Errorf("nil schema for log type %q", logType)
	}
	data, err := jsoniter.Marshal(schema)
	if err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	var fields map[string]interface{}
	if err := jsoniter.Unmarshal(data, &fields); err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	// TODO: [parsers] Use reflect to check provided schema struct for required panther fields
	return nil
}

type logHandler struct {
	results chan *Result
	parser  LogParser
	scanner LogScanner
	ctx     context.Context
}

// Run should start reading log entries from a reader and produce results to the channel.
// It should end with ctx.Err() if the context ends before completion.
func (h *logHandler) Run(ctx context.Context) error {
	if h.ctx != nil {
		return errors.New("already running")
	}
	// Notify consumers that the processing is over
	defer close(h.results)
	if ctx == nil {
		ctx = context.Background()
	}
	done := ctx.Done()
	for {
		log, err := h.scanner.ScanLog()
		if err != nil {
			// EOF ends the goroutine without errors
			if err == io.EOF {
				return nil
			}
			return err
		}
		results, err := h.parser.ParseLog(log)
		if err != nil {
			return err
		}
		for _, result := range results {
			select {
			case <-done:
				return ctx.Err()
			case h.results <- result:
			}
		}
	}
}

// Results returns the results from parsing the input io.Reader
func (h *logHandler) Results() <-chan *Result {
	return h.results
}
