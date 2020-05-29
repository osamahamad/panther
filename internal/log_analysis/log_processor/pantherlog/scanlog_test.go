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
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanLogJSONArray(t *testing.T) {
	{
		input := `{"Results":[{"foo":"bar"},{"bar":"baz"},{"baz":"foo"}]}`

		r := strings.NewReader(input)
		scan := ScanLogJSONArray(r, "Results")

		{
			r, err := scan.ScanLog()
			require.NoError(t, err)
			require.Equal(t, `{"foo":"bar"}`, r)
		}
		{
			r, err := scan.ScanLog()
			require.NoError(t, err)
			require.Equal(t, `{"bar":"baz"}`, r)
		}
		{
			r, err := scan.ScanLog()
			require.NoError(t, err)
			require.Equal(t, `{"baz":"foo"}`, r)
		}
		{
			r, err := scan.ScanLog()
			require.Equal(t, io.EOF, err)
			require.Equal(t, ``, r)
		}
	}
}
