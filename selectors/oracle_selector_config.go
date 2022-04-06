package selectors

import "time"

type OracleSelectorConfig struct {
	// FetchScoresInterval is the time interval after Path Scorings are fetched from the Path Oracle
	// and our current path choice is reevaluated.
	// To fetch scores only once (on initialisation) specify 0.
	FetchScoresInterval time.Duration
}
