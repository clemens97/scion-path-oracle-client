package selectors

import (
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
	"math/rand"
	"sync"
)

type RandomPathSelector struct {
	mutex  sync.Mutex
	paths  []*pan.Path
	pc     chan<- *pan.Path
	Logger *zap.SugaredLogger
}

func (s *RandomPathSelector) SetPathChan(pc chan<- *pan.Path) {
	s.pc = pc
}

func (s *RandomPathSelector) Path() *pan.Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.selectedPath()
}

func (s *RandomPathSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Logger.Debugw("Initialize", "remote", remote, "local", local)
	s.paths = paths
	s.shufflePaths()
	go func() {
		s.pc <- s.selectedPath()
	}()
}

func (s *RandomPathSelector) Refresh(paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Logger.Debugw("refresh")

	// we do not want to switch paths (for now)
	//s.paths = paths
	//s.shufflePaths()
}

func (s *RandomPathSelector) PathDown(fp pan.PathFingerprint, pi pan.PathInterface) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Logger.Debugw("PathDown", "fingerprint", fp, "interface", pi)

	// we do not want to switch paths (for now)
	//if isInterfaceOnPath(*s.paths[0], pi) || fp == s.paths[0].Fingerprint {
	//	s.logger.Debugw("switching path")
	//	s.paths = s.paths[1:]
	//}
}

func (s *RandomPathSelector) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Logger.Debugw("close")
	return nil
}

func (s *RandomPathSelector) shufflePaths() {
	rand.Shuffle(len(s.paths), func(i, j int) {
		s.paths[i], s.paths[j] = s.paths[j], s.paths[i]
	})
	s.Logger.Debugw("done shuffling paths", "amount", len(s.paths), "best_fp", s.paths[0].Fingerprint)
}

func (s *RandomPathSelector) selectedPath() *pan.Path {
	if len(s.paths) < 1 {
		return nil
	}
	return s.paths[0]
}
