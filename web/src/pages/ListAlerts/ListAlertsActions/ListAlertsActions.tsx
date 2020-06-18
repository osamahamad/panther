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
import { SeverityEnum, ListAlertsInput } from 'Generated/schema';
import GenerateFiltersGroup from 'Components/utils/GenerateFiltersGroup';
import { capitalize, formatTime } from 'Helpers/utils';
import FormikTextInput from 'Components/fields/TextInput';
import FormikCombobox from 'Components/fields/ComboBox';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { Box, Button, Card, Flex, Icon } from 'pouncejs';
import CreateButton from 'Pages/ListPolicies/CreateButton';
import ErrorBoundary from 'Components/ErrorBoundary';
import isEmpty from 'lodash-es/isEmpty';
import isNumber from 'lodash-es/isNumber';
import pick from 'lodash-es/pick';

const severityOptions = Object.values(SeverityEnum);

export const filters = {
  nameContains: {
    component: FormikTextInput,
    props: {
      label: 'Title contains',
      placeholder: 'Enter an alert title...',
    },
  },
  severity: {
    component: FormikCombobox,
    props: {
      label: 'Severity',
      items: ['', ...severityOptions],
      itemToString: (severity: SeverityEnum | '') =>
        severity === '' ? 'All' : capitalize(severity.toLowerCase()),
      inputProps: {
        placeholder: 'Choose a severity...',
      },
    },
  },
  ruleId: {
    component: FormikTextInput,
    props: {
      label: 'Rule ID',
      placeholder: 'Enter a rule ID...',
    },
  },
  eventCountMin: {
    component: FormikTextInput,
    props: {
      label: 'Event count (min)',
      placeholder: 'Enter number...',
      type: 'number',
      min: 0,
    },
  },
  eventCountMax: {
    component: FormikTextInput,
    props: {
      label: 'Event count (max)',
      placeholder: 'Enter number...',
      type: 'number',
      min: 0,
    },
  },
  createdAtAfter: {
    component: FormikTextInput,
    props: {
      label: 'Created After',
      placeholder: 'YYYY-MM-DDTHH:mm:ss',
      type: 'datetime-local',
      step: 1,
    },
  },
  createdAtBefore: {
    component: FormikTextInput,
    props: {
      label: 'Created Before',
      placeholder: 'YYYY-MM-DDTHH:mm:ss',
      type: 'datetime-local',
      step: 1,
    },
  },
};

export type ListAlertsFiltersValues = Pick<
  ListAlertsInput,
  | 'severity'
  | 'ruleId'
  | 'eventCountMin'
  | 'eventCountMax'
  | 'nameContains'
  | 'createdAtAfter'
  | 'createdAtBefore'
>;

type ListAlertsActionsProps = {
  showActions: boolean;
};

// Keys that we know will use a date string format
const dateKeys = ['createdAtAfter', 'createdAtBefore'];

// Creates a datetime formatter to use based on the dayjs format
const createFormat = (format: string): any => formatTime(format);
const postFormatter = createFormat('YYYY-MM-DDTHH:mm:ss[Z]');
const preFormatter = createFormat('YYYY-MM-DDTHH:mm:ss');

// Checks every key in an object for date-like values and converts them to a desired format
const sanitizeDates = (formatter: any, utcIn?: boolean, utcOut?: boolean) => (
  parms: Partial<any>
) =>
  Object.entries(parms).reduce((acc, [k, v]) => {
    if (dateKeys.includes(k) && Date.parse(v)) {
      acc[k] = formatter(v, utcIn, utcOut);
      return acc;
    }
    acc[k] = v;
    return acc;
  }, {});

// These are needed to marshal UTC timestamps in the format the backend requires
// Create a formatter for date form field submit (local) -> URL parameter (UTC)
const postProcessDate = sanitizeDates(postFormatter, false, true);
// Create a formatter for URL parameter (UTC) -> date form field (local)
const preProcessDate = sanitizeDates(preFormatter, true, false);

const ListAlertsActions: React.FC<ListAlertsActionsProps> = ({ showActions }) => {
  const [areFiltersVisible, setFiltersVisibility] = React.useState(false);
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListAlertsInput
  >();

  // Get all of the keys we can filter by
  const filterKeys = Object.keys(filters) as (keyof ListAlertsInput)[];
  // Define a partial which will filter out URL params against our keys
  const filterValid = (key: keyof ListAlertsInput) =>
    !isEmpty(requestParams[key]) || isNumber(requestParams[key]);
  // Get the number of valid filters present in the URL params
  const filtersCount = filterKeys.filter(filterValid).length;

  // If there is at least one filter set visibility to true
  // -or- if there's an override
  React.useEffect(() => {
    if (filtersCount > 0 || showActions) {
      setFiltersVisibility(true);
    }
  }, [filtersCount, showActions]);

  // The initial filter values for when the filters component first renders. If you see down below,
  // we mount and unmount it depending on whether it's visible or not
  const initialFilterValues = React.useMemo(
    () => preProcessDate(pick(requestParams, filterKeys) as ListAlertsFiltersValues),
    [requestParams]
  );

  return (
    <Box>
      <Flex justify="flex-end" mb={6}>
        <Box position="relative" mr={5}>
          <Button
            size="large"
            variant="default"
            onClick={() => setFiltersVisibility(!areFiltersVisible)}
          >
            <Flex>
              <Icon type="filter" size="small" mr={3} />
              Filter Options {filtersCount ? `(${filtersCount})` : ''}
            </Flex>
          </Button>
        </Box>
        <CreateButton />
      </Flex>
      {areFiltersVisible && (
        <ErrorBoundary>
          <Card p={6} mb={6}>
            <GenerateFiltersGroup<ListAlertsFiltersValues>
              filters={filters}
              onCancel={() => setFiltersVisibility(false)}
              onSubmit={newParams => updateRequestParams(postProcessDate(newParams))}
              initialValues={initialFilterValues}
            />
          </Card>
        </ErrorBoundary>
      )}
    </Box>
  );
};

export default React.memo(ListAlertsActions);
