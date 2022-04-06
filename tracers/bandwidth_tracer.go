package tracers

import (
	"context"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
	"net"
)

type BandwidthTracer struct {
	Logger *zap.SugaredLogger
	// SampleInterval is the time we collect connection metrics until we report them to the path oracle
	// and start a new sample.
	ReportingConfig  ReportingConfig
	CsvWritingConfig CsvWritingConfig

	PathChan chan *pan.Path
}

func (t BandwidthTracer) TracerForConnection(ctx context.Context, p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	ct := &BandwidthConnectionTracer{
		reportingConfig: t.ReportingConfig,
		csvStatsWriter:  New(t.CsvWritingConfig, t.Logger),
		logger:          t.Logger.With("odcid", odcid)}
	ct.SetPathChan(t.PathChan)
	return ct
}

func (t BandwidthTracer) SentPacket(addr net.Addr, header *logging.Header, count logging.ByteCount, frames []logging.Frame) {
}

func (t BandwidthTracer) DroppedPacket(addr net.Addr, packetType logging.PacketType, count logging.ByteCount, reason logging.PacketDropReason) {
}
