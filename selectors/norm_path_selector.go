package selectors

import (
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
)

// NormSelector sorts paths by their amount of hops and selects a
// (folded normal distributed) random one
type NormSelector struct {
	mutex    sync.Mutex
	paths    []*pan.Path
	pc       chan<- *pan.Path
	selected int
	div      float64
	Logger   *zap.SugaredLogger
}

func (n *NormSelector) SetPathChan(pc chan<- *pan.Path) {
	n.pc = pc
}

func (n *NormSelector) Path() *pan.Path {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.selected < 0 || n.selected >= len(n.paths) {
		return nil
	}
	return n.paths[n.selected]
}

func (n *NormSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	n.mutex.Lock()
	n.selected = -1
	n.getDiv()
	n.paths = paths
	n.selectPath()
	n.Logger.Debugw("Initialize", "remote", remote, "local", local, "div", n.div, "amount_paths", len(paths))
	n.mutex.Unlock()

	go func() {
		n.pc <- n.Path()
	}()
}

func (n *NormSelector) Refresh(paths []*pan.Path) {
	n.mutex.Lock()
	n.Logger.Debugw("Refresh")

	n.selected = -1
	n.paths = paths
	n.selectPath()
	n.mutex.Unlock()

	n.pc <- n.Path()
}

func (n *NormSelector) PathDown(fp pan.PathFingerprint, pi pan.PathInterface) {
	n.mutex.Lock()
	n.Logger.Debugw("PathDown", "fingerprint", fp, "interface", pi)

	remaining := make([]*pan.Path, len(n.paths))
	for _, p := range n.paths {
		if isInterfaceOnPath(*p, pi) || p.Fingerprint == fp {
			continue
		}
		remaining = append(remaining, p)
	}

	n.selected = -1
	n.paths = remaining
	n.selectPath()
	n.mutex.Unlock()

	n.pc <- n.Path()
}

func (n *NormSelector) Close() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.Logger.Debugw("close")
	return nil
}

func (n *NormSelector) getDiv() {
	div, err := strconv.ParseFloat(os.Getenv("NORM_VARIANCE_DIVIDER"), 64)
	if err != nil {
		div = 2.
	}
	n.div = div
}

func (n *NormSelector) selectPath() {
	rand.Shuffle(len(n.paths), func(i, j int) {
		n.paths[i], n.paths[j] = n.paths[j], n.paths[i]
	})
	sort.Slice(n.paths, func(i, j int) bool {
		return len(n.paths[i].Metadata.Interfaces) < len(n.paths[j].Metadata.Interfaces)
	})

	cnt := float64(len(n.paths))
	dev := cnt / n.div

	norm := cnt
	for norm >= cnt {
		norm = math.Abs(rand.NormFloat64() * dev)
	}

	n.selected = int(math.Floor(norm))
}
