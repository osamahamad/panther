package jsonutil

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
	"strconv"

	jsoniter "github.com/json-iterator/go"
)

// Seek seeks a path in the JSON value at the current iterator position.
func Seek(iter *jsoniter.Iterator, path ...string) int {
	var next string
	var depth int
	for len(path) > 0 {
		depth++
		next, path = path[0], path[1:]
		switch iter.WhatIsNext() {
		case jsoniter.ObjectValue:
			if !seekKey(iter, next) {
				return keyNotFound(iter, next)
			}
		case jsoniter.ArrayValue:
			n, err := strconv.Atoi(next)
			if err != nil {
				return keyNotFound(iter, next)
			}
			if !seekIndex(iter, n) {
				return keyNotFound(iter, next)
			}
		default:
			return keyNotFound(iter, next)
		}
	}
	return depth
}

// seekKey seeks a key in the JSON object at the current iterator position.
func seekKey(iter *jsoniter.Iterator, key string) bool {
	for next := iter.ReadObject(); next != ""; next = iter.ReadObject() {
		if next == key {
			return true
		}
		iter.Skip()
	}
	return false
}

// seekIndex seeks an element at index in the JSON arrat at the current iterator position.
func seekIndex(iter *jsoniter.Iterator, index int) bool {
	for i := 0; i < index; i++ {
		if !iter.ReadArray() {
			return false
		}
		iter.Skip()
	}
	return iter.ReadArray()
}

func keyNotFound(iter *jsoniter.Iterator, key string) int {
	if iter.Error == nil {
		msg := fmt.Sprintf(`key %q not found`, key)
		iter.ReportError(`SeekPath`, msg)
	}
	return -1
}
