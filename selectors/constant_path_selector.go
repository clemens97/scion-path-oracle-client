package selectors

import (
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
	"os"
	"sync"
)

type ConstantPathSelector struct {
	mutex         sync.Mutex
	paths         []*pan.Path
	selectedPathI int

	pc     chan<- *pan.Path
	Logger *zap.SugaredLogger
}

func (s *ConstantPathSelector) SetPathChan(pc chan<- *pan.Path) {
	s.pc = pc
}

func (s *ConstantPathSelector) Path() *pan.Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.selectedPath()
}

func (s *ConstantPathSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Logger.Debugw("Initialize", "remote", remote, "local", local)

	s.paths = paths
	s.selectedPathI = s.findPath()

	if s.selectedPathI < 0 {
		s.Logger.Fatalw("could not find requested path")
	}
	s.Logger.Debugw("found path", "fp", s.selectedPath().Fingerprint)
	go func() {
		s.pc <- s.selectedPath()
	}()
}

func (s *ConstantPathSelector) Refresh(paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Logger.Debugw("Refresh")

	s.paths = paths
	s.selectedPathI = s.findPath()

	if s.selectedPathI < 0 {
		s.Logger.Fatalw("could not find requested path")
	}
}

func (s *ConstantPathSelector) PathDown(fp pan.PathFingerprint, pi pan.PathInterface) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Logger.Debugw("PathDown", "fingerprint", fp, "interface", pi)
	p := s.selectedPath()
	if fp != p.Fingerprint && isInterfaceOnPath(*p, pi) {
		s.Logger.Fatalw("selected path down")
	}
}

func (s *ConstantPathSelector) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.Logger.Debugw("close")
	return nil
}

func (s *ConstantPathSelector) selectedPath() *pan.Path {
	if len(s.paths) < 1 {
		return nil
	}
	return s.paths[s.selectedPathI]
}

func (s *ConstantPathSelector) findPath() int {
	pathFpToUse := os.Getenv("PATH_FP")
	for i, p := range s.paths {
		if string(p.Fingerprint) == pathFpToUse {
			return i
		}
	}
	return -1
}
