package selectors

import (
	oracle "github.com/clemens97/scion-path-oracle"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRankScores(t *testing.T) {
	paths := []*pan.Path{
		{Fingerprint: "a", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}}}},
		{Fingerprint: "b", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}}}},
		{Fingerprint: "c", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}}}},
		{Fingerprint: "d", Metadata: &pan.PathMetadata{Interfaces: []pan.PathInterface{{}, {}}}},
	}
	scores := map[oracle.PathFingerprint]float64{
		"a": 1, "b": 1, "c": 2, "d": 2,
	}

	selector := ThroughputPathSelector{paths: paths, oracleScores: scores}
	selector.rank()

	assert.Equal(t, pan.PathFingerprint("c"), selector.paths[0].Fingerprint)
	assert.Equal(t, pan.PathFingerprint("d"), selector.paths[1].Fingerprint)
	assert.Equal(t, pan.PathFingerprint("a"), selector.paths[2].Fingerprint)
	assert.Equal(t, pan.PathFingerprint("b"), selector.paths[3].Fingerprint)
}
