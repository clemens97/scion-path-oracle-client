package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"github.com/lucas-clemente/quic-go"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"go.uber.org/zap"
	"inet.af/netaddr"
	"io"
	"oclient"
	"oclient/selectors"
	"oclient/tracers"
	"sync"
	"time"
)

func main() {
	var (
		remoteAddr, selectorName string
		disableMTUDiscovery      bool
		sendingDur               time.Duration
		reportingConfig          tracers.ReportingConfig
		oracleSelectorConfig     selectors.OracleSelectorConfig
		csvWritingConfig         tracers.CsvWritingConfig
	)

	flag.StringVar(&remoteAddr, "remote", "", "remote address, where data will be send to")
	flag.StringVar(&selectorName, "selector", "", "selector which will be used for path selection")
	flag.BoolVar(&disableMTUDiscovery, "disableMTUDiscovery", true, "disable QUICs path MTU discovery")
	flag.DurationVar(&sendingDur, "sendingDur", 2*time.Minute, "duration in which data will be uploaded")

	flag.DurationVar(&reportingConfig.MinIntervalForReport, "rMinInterval", 0, "report connection stats collected representing a minimum period of time")
	flag.DurationVar(&reportingConfig.ReportingInterval, "rInterval", 5*time.Minute, "continuous reporting of connection stats to the oracle - 0 to disable")
	flag.BoolVar(&reportingConfig.ReportOnPathChange, "rOnPathChange", true, "report connection stats to oracle when the path changed")
	flag.DurationVar(&oracleSelectorConfig.FetchScoresInterval, "fInterval", 10*time.Minute, "[oracle selector only] interval after path scorings are refetched")

	flag.StringVar(&csvWritingConfig.SummaryFile, "summaryFile", "", "csv file to write a connection lifetime stats to")
	flag.StringVar(&csvWritingConfig.IntervalFile, "intervalFile", "", "csv file to write a interval connection stats to")
	flag.Parse()

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	slogger := logger.Sugar()

	selector := getSelector(selectorName, slogger, oracleSelectorConfig)
	remote, err := pan.ParseUDPAddr(remoteAddr)
	if err != nil {
		slogger.Fatalw("error parsing remote address", "error", err, "remote_address", remoteAddr)
	}

	slogger.Infow("starting",
		"remote", remote,
		"selector", selectorName,
		"sendingDur", sendingDur,
		"reportingConfig", reportingConfig,
		"csvWritingConfig", csvWritingConfig,
		"disableMTUDiscovery", disableMTUDiscovery)
	_, _, err = runSender(slogger, remote, selector, sendingDur, reportingConfig, csvWritingConfig, disableMTUDiscovery)
	if err != nil {
		slogger.Fatalw("error running sender", "error", err)
	}
}

func runSender(logger *zap.SugaredLogger, remote pan.UDPAddr, selector pan.Selector, dur time.Duration,
	rConf tracers.ReportingConfig, csvConf tracers.CsvWritingConfig, disableMTUDiscovery bool) (time.Duration, int64, error) {

	pathChan := make(chan *pan.Path)
	bwTracer := tracers.BandwidthTracer{
		ReportingConfig:  rConf,
		Logger:           logger.With("tracers", "BandwidthTracer"),
		CsvWritingConfig: csvConf,
		PathChan:         pathChan}

	if pb, ok := selector.(oclient.PathPublisher); ok {
		pb.SetPathChan(pathChan)
	}

	con, err := pan.DialQUIC(context.Background(), netaddr.IPPort{}, remote, nil, selector, "", &tls.Config{
		//Certificates: quicutil.MustGenerateSelfSignedCert(),
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-test", "panapi-quic-test"},
	}, &quic.Config{
		Tracer:                  bwTracer,
		DisablePathMTUDiscovery: disableMTUDiscovery,
	})
	if err != nil {
		return 0, 0, err
	}

	logger.Debugw("successfully dialed", "local", con.LocalAddr(), "remote", con.RemoteAddr())

	stream, err := con.OpenStream() //Sync(context.Background())
	if err != nil {
		return 0, 0, err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		time.Sleep(dur)
		con.CloseWithError(0, "")
		wg.Done()
	}()

	startWrite := time.Now()
	n, err := io.Copy(stream, rand.Reader)

	if qerr, ok := err.(*quic.ApplicationError); err == nil || (ok && (*qerr).ErrorCode == 0) {
		wg.Wait()
		return time.Since(startWrite), n, nil
	}
	return time.Since(startWrite), 0, err
}

func getSelector(selector string, logger *zap.SugaredLogger, config selectors.OracleSelectorConfig) pan.Selector {
	switch selector {
	case "random":
		return &selectors.RandomPathSelector{Logger: logger.With("selector", selector)}
	case "shortest":
		return &selectors.ShortestPathSelector{Logger: logger.With("selector", selector)}
	case "oracle":
		return selectors.NewThroughputPathSelector(config, logger.With("selector", selector))
	case "norm":
		return &selectors.NormSelector{Logger: logger.With("selector", selector)}
	case "ping":
		return &pan.PingingSelector{
			Interval: 2 * time.Second,
			Timeout:  time.Second}
	case "constant":
		return &selectors.ConstantPathSelector{Logger: logger.With("constant", selector)}
	case "default":
		return pan.NewDefaultSelector()
	default:
		return pan.NewDefaultSelector()
	}
}
