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

import React from 'react';
import useUrlParams from 'Hooks/useUrlParams';

function useRequestParamsWithInfiniteScroll<AvailableParams>() {
  const { urlParams, updateUrlParams } = useUrlParams<Partial<AvailableParams>>();

  // This is our typical function that updates the parameters with the addition of resetting the
  // page to `1`. The only time where we don't wanna do that, is when changing pages. In this
  // scenario, we want to change the params but not reset the page.
  const updateRequestParams = React.useCallback(
    (newParams: Partial<AvailableParams>) => {
      updateUrlParams({ ...urlParams, ...newParams });
    },
    [urlParams]
  );

  // This is a similar function like the above but instead of updating the existing params with the
  // new parameters, it clears all the parameters and just sets the parameters passed as an argument
  const setRequestParams = React.useCallback(
    (newParams: Partial<AvailableParams>) => {
      updateUrlParams({ ...newParams });
    },
    [urlParams]
  );

  return React.useMemo(
    () => ({
      requestParams: urlParams,
      updateRequestParams,
      setRequestParams,
    }),
    [urlParams]
  );
}
export default useRequestParamsWithInfiniteScroll;