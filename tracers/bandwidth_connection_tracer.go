package tracers

import (
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/go/lib/addr"
	"go.uber.org/zap"
	"net"
	path_oracle_client "oclient"
	"sync"
	"time"
)

type BandwidthConnectionTracer struct {
	lock            sync.Mutex
	logger          *zap.SugaredLogger
	csvStatsWriter  CsvStatsWriter
	reportingConfig ReportingConfig

	intervalStats intervalStats
	lifetimeStats lifetimeStats

	pathChan      chan *pan.Path
	activePath    *pan.Path
	local, remote pan.UDPAddr

	intervalTicker *time.Ticker
	oracleClient   path_oracle_client.OracleClient
}

func (b *BandwidthConnectionTracer) SetPathChan(pathC chan *pan.Path) {
	b.pathChan = pathC
}

func (b *BandwidthConnectionTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.remote = remote.(pan.UDPAddr)
	b.local = local.(pan.UDPAddr)

	b.intervalStats.begin = time.Now()
	b.intervalStats.bytesSent = 0
	b.lifetimeStats.begin = b.intervalStats.begin
	b.lifetimeStats.bytesSent = 0

	b.oracleClient = path_oracle_client.NewOracleClient()
	if b.reportingConfig.ReportingInterval > 0 {
		b.intervalTicker = time.NewTicker(b.reportingConfig.ReportingInterval)
		go func() {
			for {
				select {
				case <-b.intervalTicker.C:
					b.logger.Debugw("ticker")
					b.FinishInterval("continuously reporting", true)
				}
			}
		}()
	}

	go func() {
		for {
			select {
			case path := <-b.pathChan:
				b.logger.Debugw("got path", "fp", path.Fingerprint)
				b.activePath = path
				if b.reportingConfig.ReportOnPathChange && b.lifetimeStats.pathChanges > 0 {
					b.FinishInterval("path changed", true)
				}
				b.intervalStats.fingerprint = string(path.Fingerprint)
				b.lifetimeStats.fingerprints = append(b.lifetimeStats.fingerprints, string(path.Fingerprint))
				b.lifetimeStats.pathChanges++
			}
		}
	}()
}

func (b *BandwidthConnectionTracer) NegotiatedVersion(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
}

func (b *BandwidthConnectionTracer) ClosedConnection(err error) {
}

func (b *BandwidthConnectionTracer) SentTransportParameters(parameters *logging.TransportParameters) {
}

func (b *BandwidthConnectionTracer) ReceivedTransportParameters(parameters *logging.TransportParameters) {
}

func (b *BandwidthConnectionTracer) RestoredTransportParameters(parameters *logging.TransportParameters) {
}

func (b *BandwidthConnectionTracer) SentPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.intervalStats.bytesSent += size
	b.lifetimeStats.bytesSent += size
}

func (b *BandwidthConnectionTracer) ReceivedVersionNegotiationPacket(header *logging.Header, numbers []logging.VersionNumber) {
}

func (b *BandwidthConnectionTracer) ReceivedRetry(header *logging.Header) {
}

func (b *BandwidthConnectionTracer) ReceivedPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, frames []logging.Frame) {
}

func (b *BandwidthConnectionTracer) BufferedPacket(packetType logging.PacketType) {
}

func (b *BandwidthConnectionTracer) DroppedPacket(packetType logging.PacketType, count logging.ByteCount, reason logging.PacketDropReason) {
}

func (b *BandwidthConnectionTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
}

func (b *BandwidthConnectionTracer) AcknowledgedPacket(level logging.EncryptionLevel, number logging.PacketNumber) {
}

func (b *BandwidthConnectionTracer) LostPacket(level logging.EncryptionLevel, number logging.PacketNumber, reason logging.PacketLossReason) {
}

func (b *BandwidthConnectionTracer) UpdatedCongestionState(state logging.CongestionState) {
}

func (b *BandwidthConnectionTracer) UpdatedPTOCount(value uint32) {
}

func (b *BandwidthConnectionTracer) UpdatedKeyFromTLS(level logging.EncryptionLevel, perspective logging.Perspective) {
}

func (b *BandwidthConnectionTracer) UpdatedKey(generation logging.KeyPhase, remote bool) {
}

func (b *BandwidthConnectionTracer) DroppedEncryptionLevel(level logging.EncryptionLevel) {
}

func (b *BandwidthConnectionTracer) DroppedKey(generation logging.KeyPhase) {
}

func (b *BandwidthConnectionTracer) SetLossTimer(timerType logging.TimerType, level logging.EncryptionLevel, time time.Time) {
}

func (b *BandwidthConnectionTracer) LossTimerExpired(timerType logging.TimerType, level logging.EncryptionLevel) {
}

func (b *BandwidthConnectionTracer) LossTimerCanceled() {
}

func (b *BandwidthConnectionTracer) Close() {
	b.lock.Lock()
	b.lifetimeStats.end = time.Now()
	b.csvStatsWriter.OnConnectionClose(b.lifetimeStats)
	b.lock.Unlock()

	b.FinishInterval("connection closed", false)
	b.csvStatsWriter.Close()
}

func (b *BandwidthConnectionTracer) Debug(name, msg string) {
}

func (b *BandwidthConnectionTracer) FinishInterval(trigger string, async bool) {
	b.lock.Lock()
	log := b.logger.With("trigger", trigger)
	now := time.Now()
	b.intervalStats.end = now
	st := b.intervalStats
	dur := st.end.Sub(st.begin)
	b.intervalStats = intervalStats{begin: now, fingerprint: st.fingerprint}
	b.lock.Unlock()

	b.csvStatsWriter.OnIntervalElapsed(st)
	if dur < b.reportingConfig.MinIntervalForReport {
		log.Debugw("skipping report because of report dur < min interval dur",
			"report_dur (s)", dur.Seconds(), "min_dur (s)", b.reportingConfig.MinIntervalForReport.Seconds())
		return
	}

	report := st.ToOracleReport()
	report.DstIA = addr.IA(b.remote.IA)
	report.SrcIA = addr.IA(b.local.IA)

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func(log *zap.SugaredLogger, wg *sync.WaitGroup) {
		err := b.oracleClient.ReportStats(report)
		if err != nil {
			log.Warnw("error reporting stats to path oracle", "error", err, "trigger", trigger)
		} else {
			log.Infow("successfully reported stats to oracle", "report", report, "trigger", trigger)
		}
		wg.Done()
	}(log, &wg)

	if !async {
		wg.Wait()
	}
}
