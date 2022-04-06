package selectors

import (
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
	"math/rand"
	"sort"
	"sync"
)

type ShortestPathSelector struct {
	mutex  sync.Mutex
	paths  []*pan.Path
	pc     chan<- *pan.Path
	Logger *zap.SugaredLogger
}

func (s *ShortestPathSelector) SetPathChan(pc chan<- *pan.Path) {
	s.pc = pc
}

func (s *ShortestPathSelector) Path() *pan.Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.selectedPath()
}

func (s *ShortestPathSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Logger.Debugw("Initialize", "remote", remote, "local", local)
	s.paths = paths
	s.rankPaths()
	go func() {
		s.pc <- s.selectedPath()
	}()
}

func (s *ShortestPathSelector) Refresh(paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// we do not want to switch paths (for now)

	//s.logger.Debugw("refresh")
	//s.paths = paths
	//s.rankPaths()
}

func (s *ShortestPathSelector) PathDown(fp pan.PathFingerprint, pi pan.PathInterface) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Logger.Debugw("PathDown", "fingerprint", fp, "interface", pi)

	// we do not want to switch paths (for now)

	//if isInterfaceOnPath(*s.paths[0], pi) || fp == s.paths[0].Fingerprint {
	//	s.logger.Debugw("switching path")
	//	s.paths = s.paths[1:]
	//}
}

func (s *ShortestPathSelector) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Logger.Debugw("close")
	return nil
}

func (s *ShortestPathSelector) rankPaths() {
	rand.Shuffle(len(s.paths), func(i, j int) {
		s.paths[i], s.paths[j] = s.paths[j], s.paths[i]
	})
	sort.Slice(s.paths, func(i, j int) bool {
		return len(s.paths[i].Metadata.Interfaces) < len(s.paths[j].Metadata.Interfaces)
	})

	s.Logger.Debugw("done ranking paths",
		"amount", len(s.paths), "best_fp", s.paths[0].Fingerprint, "hops_shortest_path", len(s.paths[0].Metadata.Interfaces))
}

func (s *ShortestPathSelector) selectedPath() *pan.Path {
	if len(s.paths) < 1 {
		return nil
	}
	return s.paths[0]
}
