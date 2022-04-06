package selectors

import (
	oracle "github.com/clemens97/scion-path-oracle"
	"github.com/clemens97/scion-path-oracle/server"
	"github.com/clemens97/scion-path-oracle/services"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/go/lib/addr"
	"go.uber.org/zap"
	"oclient"
	"sort"
	"sync"
	"time"
)

// ThroughputPathSelector selects the path with the best throughput according to a path oracle
type ThroughputPathSelector struct {
	mutex  sync.Mutex
	logger *zap.SugaredLogger
	pc     chan<- *pan.Path

	config       OracleSelectorConfig
	oracleClient oclient.OracleClient
	oracleTicker *time.Ticker
	oracleScores map[oracle.PathFingerprint]float64

	paths    []*pan.Path
	remoteIA addr.IA
}

func NewThroughputPathSelector(config OracleSelectorConfig, logger *zap.SugaredLogger) *ThroughputPathSelector {
	return &ThroughputPathSelector{oracleClient: oclient.NewOracleClient(), logger: logger, config: config}
}

func (s *ThroughputPathSelector) Path() *pan.Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.paths) < 1 {
		s.logger.Infow("no paths present")
		return nil
	}
	// s.logger.Debugw("using path", "fingerprint", s.paths[0].Fingerprint)
	return s.paths[0]
}

func (s *ThroughputPathSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.logger.Debugw("Initialize", "remote", remote, "local", local)
	s.remoteIA = addr.IA{I: remote.IA.I, A: remote.IA.A}

	s.paths = paths
	scores, _ := s.refreshOracleScores()
	s.oracleScores = scores
	s.rank()
	if len(s.paths) > 0 {
		s.logger.Infow("selected initial path for con", "fp", s.paths[0].Fingerprint)
		// consumer (tracer) not ready yet, so sent first path async
		go func() {
			s.pc <- s.paths[0]
		}()
	}

	if s.config.FetchScoresInterval <= 0 {
		return
	}

	s.oracleTicker = time.NewTicker(s.config.FetchScoresInterval)
	go func() {
		for {
			select {
			case <-s.oracleTicker.C:
				if len(s.paths) < 2 {
					// no paths to decide between, no need to fetch oracle score
					return
				}

				scs, err := s.refreshOracleScores()
				if err != nil {
					return
				}

				s.oracleScores = scs
				s.mutex.Lock()
				if len(s.paths) == 0 {
					return
				}
				curBestFp := s.paths[0].Fingerprint
				s.rank()
				// path changed
				if newBestFp := s.paths[0].Fingerprint; newBestFp != curBestFp {
					s.logger.Infow("changed path on new oracle scores", "previousFp", curBestFp, "newFp", s.paths[0].Fingerprint)
					s.pc <- s.paths[0]
				}
				s.mutex.Unlock()
			}
		}
	}()
}

func (s *ThroughputPathSelector) rank() {
	// sort by oracle score (DESC), paths with the same oracle score are sorted by number of hops (ASC)
	sort.Slice(s.paths, func(i, j int) bool {
		sI, okI := s.oracleScores[oracle.PathFingerprint(s.paths[i].Fingerprint)]
		sJ, okJ := s.oracleScores[oracle.PathFingerprint(s.paths[j].Fingerprint)]
		if !okI {
			sI = 0
		}
		if !okJ {
			sJ = 0
		}
		if sI == sJ {
			return len(s.paths[i].Metadata.Interfaces) < len(s.paths[j].Metadata.Interfaces)
		}
		return sI > sJ
	})
}

func (s *ThroughputPathSelector) refreshOracleScores() (map[oracle.PathFingerprint]float64, error) {
	scores := make(map[oracle.PathFingerprint]float64)

	q := map[string][]services.ServiceName{s.remoteIA.String(): {"throughput"}}
	scoringRes, err := s.oracleClient.FetchScores(server.ScoringQuery{Queries: q})
	if err != nil {
		s.logger.Errorw("error fetching scores from oracle", "error", err)
		return scores, err
	}

	for _, e := range scoringRes[s.remoteIA] {
		if bwScore, ok := e.Scores["throughput"]; ok {
			scores[e.Fingerprint] = bwScore
		}
	}

	s.logger.Infow("successfully fetched scores from oracle", "scores", scores)
	return scores, nil
}

func (s *ThroughputPathSelector) Refresh(paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.logger.Debugw("Refresh")

	if len(paths) == 0 && len(s.paths) == 0 {
		// no new paths submitted and no paths prior to refresh
		return
	}
	if len(paths) == 0 && len(s.paths) >= 1 {
		// no paths submitted but there were paths prior to refresh
		s.paths = paths
		s.pc <- nil
		return
	}

	// rerank path and check for path change
	bestFp := s.paths[0].Fingerprint
	s.paths = paths
	s.rank()
	newBestFp := s.paths[0].Fingerprint
	if bestFp != newBestFp {
		s.logger.Infow("changed path on refresh", "previousFp", bestFp, "newFp", newBestFp)
		s.pc <- s.paths[0]
	}
}

func (s *ThroughputPathSelector) PathDown(fp pan.PathFingerprint, pi pan.PathInterface) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.logger.Debugw("PathDown", "fingerprint", fp, "interface", pi)

	if len(s.paths) == 0 {
		return
	}

	bestFp := s.paths[0].Fingerprint
	remaining := make([]*pan.Path, len(s.paths))
	for _, p := range s.paths {
		if isInterfaceOnPath(*p, pi) || p.Fingerprint == fp {
			continue
		}
		remaining = append(remaining, p)
	}
	s.paths = remaining
	if bestFp != s.paths[0].Fingerprint {
		s.logger.Infow("changed path on pathdown", "previousFp", bestFp, "newFp", s.paths[0].Fingerprint)
		s.pc <- s.paths[0]
	}
}

func (s *ThroughputPathSelector) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.logger.Debugw("Close")
	if s.oracleTicker != nil {
		s.oracleTicker.Stop()
	}
	return nil
}

func (s *ThroughputPathSelector) SetPathChan(pc chan<- *pan.Path) {
	s.pc = pc
}
