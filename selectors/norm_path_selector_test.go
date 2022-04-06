package selectors

import (
	"fmt"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
	"testing"
)

func TestNormSelector(t *testing.T) {
	t.Setenv("NORM_VARIANCE_DIVIDER", "4")
	selector := NormSelector{Logger: zap.S()}
	selector.paths = []*pan.Path{
		{Fingerprint: "a", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}}}},
		{Fingerprint: "b", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}}}},
		{Fingerprint: "c", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}}}},
		{Fingerprint: "d", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}}}},
		{Fingerprint: "e", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}, {}}}},
		{Fingerprint: "f", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}, {}, {}, {}}}},
		{Fingerprint: "g", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}, {}, {}, {}, {}}}},
		{Fingerprint: "h", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}, {}, {}, {}, {}, {}}}},
		{Fingerprint: "i", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}, {}, {}, {}, {}, {}, {}}}},
	}
	selector.getDiv()
	res := make([]int, 0)
	dev := make([]int, len(selector.paths))
	for i := 0; i < 1000; i++ {
		selector.selectPath()
		res = append(res, selector.selected)
		dev[selector.selected]++
	}

	fmt.Sprintf("test")
}
