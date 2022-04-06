package tracers

import (
	"encoding/csv"
	"fmt"
	oracle "github.com/clemens97/scion-path-oracle"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/scionproto/scion/go/lib/addr"
	"go.uber.org/zap"
	"os"
	"strings"
	"time"
)

const timeFormat = "2006-01-02T15:04:05-0700"

var intervalStatsCsvHeader = []string{"begin", "end", "begin_unx", "end_unx", "fingerprint", "bytes_sent", "throughput"}

type intervalStats struct {
	begin, end  time.Time
	bytesSent   logging.ByteCount
	fingerprint string
	closeReason string
	reported    bool
}

func (i intervalStats) ToCsvRow() []string {
	return []string{
		i.begin.Format(timeFormat),
		i.end.Format(timeFormat),
		fmt.Sprintf("%d", i.begin.Unix()),
		fmt.Sprintf("%d", i.end.Unix()),
		i.fingerprint,
		fmt.Sprintf("%d", i.bytesSent),
		fmt.Sprintf("%.0f", i.Throughput()),
	}
}

func (i intervalStats) ToOracleReport() oracle.Report {
	return oracle.Report{
		Metadata: oracle.Metadata{
			Application: "quic_sender",
			Duration:    i.end.Sub(i.begin).Seconds(),
			Properties: oracle.MetadataProperties{
				"protocols":             []string{"SCION", "UDP", "QUIC"},
				"taps-capacity-profile": "capacity-seeking",
			},
		},
		Properties: oracle.MonitoredProperties{
			"throughput": i.Throughput(),
		},
		SrcIA:  addr.IA{},
		DstIA:  addr.IA{},
		PathFp: oracle.PathFingerprint(i.fingerprint),
	}
}

func (i intervalStats) Throughput() float64 {
	return float64(i.bytesSent) / i.end.Sub(i.begin).Seconds()
}

type lifetimeStats struct {
	begin, end   time.Time
	bytesSent    logging.ByteCount
	fingerprints []string
	pathChanges  int
}

func (i lifetimeStats) ToCsvRow() []string {
	return []string{
		i.begin.Format(timeFormat),
		i.end.Format(timeFormat),
		fmt.Sprintf("%d", i.begin.Unix()),
		fmt.Sprintf("%d", i.end.Unix()),
		strings.Join(i.fingerprints, " - "),
		fmt.Sprintf("%d", i.bytesSent),
		fmt.Sprintf("%.0f", i.Throughput()),
	}
}

func (i lifetimeStats) Throughput() float64 {
	return float64(i.bytesSent) / i.end.Sub(i.begin).Seconds()
}

type CsvWritingConfig struct {
	SummaryFile, IntervalFile string
}

type CsvStatsWriter struct {
	summaryFile, intervalFile     *os.File
	summaryWriter, intervalWriter *csv.Writer
}

func New(config CsvWritingConfig, logger *zap.SugaredLogger) CsvStatsWriter {
	openFile := func(fileName string) (*os.File, error) {
		if len(fileName) < 1 {
			return nil, nil
		}
		return os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	}

	sF, err := openFile(config.SummaryFile)
	if err != nil {
		logger.Warnw("could not open summary file", "filename", config.SummaryFile, "error", err)
	}
	iF, err := openFile(config.IntervalFile)
	if err != nil {
		logger.Warnw("could not open interval file", "filename", config.IntervalFile, "error", err)
	}

	c := CsvStatsWriter{summaryFile: sF, intervalFile: iF}
	if c.summaryFile != nil {
		c.summaryWriter = csv.NewWriter(c.summaryFile)
	}
	if c.intervalFile != nil {
		c.intervalWriter = csv.NewWriter(c.intervalFile)
		c.intervalWriter.Write(intervalStatsCsvHeader)
	}
	return c
}

func (c *CsvStatsWriter) OnIntervalElapsed(stats intervalStats) {
	if c.intervalWriter == nil {
		return
	}
	c.intervalWriter.Write(stats.ToCsvRow())
}

func (c *CsvStatsWriter) OnConnectionClose(stats lifetimeStats) {
	if c.summaryWriter == nil {
		return
	}
	c.summaryWriter.Write(stats.ToCsvRow())
}

func (c *CsvStatsWriter) Close() {
	if c.intervalWriter != nil {
		c.intervalWriter.Flush()
	}
	if c.summaryWriter != nil {
		c.summaryWriter.Flush()
	}
	if c.intervalFile != nil {
		c.intervalFile.Close()
	}
	if c.summaryFile != nil {
		c.summaryFile.Close()
	}
}
