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
	"bufio"
	"io"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
)

// LogScanner handles splitting of files into chunks (lines, json values, other) to hand over to a `LogParser`
// Implementations should read parseable chunks of the underlying reader and return an io.EOF when the they finish.
// Any read or parse errors should also be returned when they occur.
type LogScanner interface {
	ScanLog() (string, error)
}

// ScanLogLines is the default LogScanner splitting the input `io.Reader` into lines.
func ScanLogLines(r io.Reader) LogScanner {
	if r, ok := r.(*bufio.Reader); ok {
		return &logScannerLines{
			r: r,
		}
	}
	return &logScannerLines{
		r: bufio.NewReader(r),
	}
}

type logScannerLines struct {
	r         *bufio.Reader
	numLines  int64
	totalSize int64
}

func (s *logScannerLines) ScanLog() (string, error) {
	b := strings.Builder{}
	if s.numLines != 0 {
		// Pre-allocate to average line size
		size := s.totalSize / s.numLines
		b.Grow(int(size))
	}
	for {
		line, isPrefix, err := s.r.ReadLine()
		s.totalSize += int64(len(line))
		b.Write(line)
		if err != nil {
			return b.String(), err
		}
		if isPrefix {
			continue
		}
		s.numLines++
		return b.String(), nil
	}
}

// ScanLogJSON scans JSON values from an `io.Reader` regardless of whitespace formatting.
func ScanLogJSON(r io.Reader) LogScanner {
	// WARNING: It is VERY IMPORTANT to pass a buffer here. jsoniter has a bug with endless loop.
	iter := jsoniter.ConfigFastest.BorrowIterator(make([]byte, 8192))
	iter.Reset(r)
	return &logScannerJSON{
		iter: iter,
	}
}

type logScannerJSON struct {
	iter *jsoniter.Iterator
}

func (s *logScannerJSON) ScanLog() (string, error) {
	if err := s.iter.Error; err != nil {
		return "", err
	}
	msg := s.iter.SkipAndReturnBytes()
	if err := s.iter.Error; err != nil {
		return "", err
	}
	return string(msg), nil
}

// ScanLogJSONArray scans a JSON value in the input `io.Reader` and extracts each array element.
// Note that the output json strings retain whitespace in the input.
// If the value at `path` is not an array , an error is returned by every call to `ScanLog()`
// Each call to `ScanLog` will return the next array element and then `io.EOF`.
func ScanLogJSONArray(r io.Reader, path ...string) LogScanner {
	// WARNING: It is VERY IMPORTANT to pass a buffer here. jsoniter has a bug with endless loop.
	iter := jsoniter.ConfigFastest.BorrowIterator(make([]byte, 8192))
	iter.Reset(r)
	if len(path) > 0 {
		jsonutil.Seek(iter, path...)
	}
	if iter.Error == nil {
		switch iter.WhatIsNext() {
		case jsoniter.ArrayValue:
		case jsoniter.NilValue:
			iter.Pool().ReturnIterator(iter)
			return &logScannerJSONArray{}
		default:
			iter.ReportError(`ScanArray`, `non array JSON value`)
		}
	}
	return &logScannerJSONArray{
		iter: iter,
	}
}

type logScannerJSONArray struct {
	iter *jsoniter.Iterator
}

func (s *logScannerJSONArray) ScanLog() (string, error) {
	iter := s.iter
	if iter == nil {
		return "", io.EOF
	}
	if err := iter.Error; err != nil {
		return "", err
	}
	if iter.ReadArray() {
		msg := iter.SkipAndReturnBytes()
		if err := iter.Error; err != nil {
			return "", err
		}
		return string(msg), nil
	}
	iter.Pool().ReturnIterator(iter)
	s.iter = nil
	return "", io.EOF
}
