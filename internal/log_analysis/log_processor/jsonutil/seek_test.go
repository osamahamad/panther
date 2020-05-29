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
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestSeek(t *testing.T) {
	{
		input := `
{"Results":[{"foo":"bar"}]}
{"Results":null}`
		iter := jsoniter.ConfigFastest.BorrowIterator([]byte(input))
		depth := Seek(iter, "Results", "0", "foo")
		require.NoError(t, iter.Error)
		require.Equal(t, depth, 3)
		require.Equal(t, "bar", iter.ReadString())
	}
}
