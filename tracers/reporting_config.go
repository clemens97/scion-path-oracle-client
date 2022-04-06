package tracers

import (
	"time"
)

type ReportingConfig struct {
	// ReportOnPathChange to submit connection stats when the path changed. A path change always invalidates the
	// prior collected stats.
	ReportOnPathChange bool
	// ReportingInterval for continuous reporting of connection stats to the oracle. 0 to disable continuous reporting.
	ReportingInterval time.Duration
	// MinIntervalForReport allows to filter out reports representing stats of too little time.
	MinIntervalForReport time.Duration
}
