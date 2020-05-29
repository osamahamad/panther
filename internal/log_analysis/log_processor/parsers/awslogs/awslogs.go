package awslogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

var (
	LogTypeAWSALB = pantherlog.LogType{
		Name:        TypeALB,
		Description: ALBDesc,
		Schema:      ALB{},
		NewParser:   parsers.AdapterFactory(&ALBParser{}),
	}
	LogTypeAuroraMySQLAudit = pantherlog.LogType{
		Name:        TypeAuroraMySQLAudit,
		Description: AuroraMySQLAuditDesc,
		Schema:      AuroraMySQLAudit{},
		NewParser:   parsers.AdapterFactory(&AuroraMySQLAuditParser{}),
	}
	LogTypeCloudTrail = pantherlog.LogType{
		Name:        TypeCloudTrail,
		Description: CloudTrailDesc,
		Schema:      CloudTrail{},
		NewParser:   parsers.AdapterFactory(&CloudTrailParser{}),
		NewScanner:  NewCloudTrailLogScanner,
	}
)

func init() {
	// Register custom meta factory for AWS logs
	pantherlog.MustRegisterMetaPrefix("AWS", metaFactory)

	pantherlog.MustRegister(
		LogTypeAWSALB,
		LogTypeAuroraMySQLAudit,
		LogTypeCloudTrail,
	)
}
