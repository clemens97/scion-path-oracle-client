package main

import (
	"context"
	"crypto/tls"
	"flag"
	"github.com/lucas-clemente/quic-go"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"go.uber.org/zap"
	"inet.af/netaddr"
	"io"
	"io/ioutil"
)

func main() {
	var (
		listenAddr string
	)
	flag.StringVar(&listenAddr, "local", "", "e.g. 1.2.3.4:1337")
	flag.Parse()

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	slogger := logger.Sugar()

	listen, err := netaddr.ParseIPPort(listenAddr)
	if err != nil {
		slogger.Fatalw("error parsing local address", "error", err, "local_address", listenAddr)
	}

	err = runReceiver(slogger, listen)
	if err != nil {
		slogger.Errorw("error running receiver", "error", err)
	}
}

func runReceiver(logger *zap.SugaredLogger, local netaddr.IPPort) error {
	listen, err := pan.ListenQUIC(context.Background(), local, nil, &tls.Config{
		Certificates: quicutil.MustGenerateSelfSignedCert(),
		//InsecureSkipVerify: true,
		NextProtos: []string{"quic-test"},
	}, nil)

	if err != nil {
		return err
	}

	logger.Infow("started listening", "local", listen.Addr())

	for {
		session, err := listen.Accept(context.Background())
		if err != nil {
			logger.Infow("error accepted session", "error", err)
			continue
		}
		logger.Infow("accepted session", "remote", session.RemoteAddr())

		go func() {
			stream, err := session.AcceptStream(context.Background())
			if err != nil {
				logger.Errorw("error accepting stream", "error", err.Error())
				return
			}
			n, err := io.Copy(ioutil.Discard, stream)
			if err != nil {
				if qerr, ok := err.(*quic.ApplicationError); ok && (*qerr).ErrorCode != 0 {
					logger.Errorw("error receiving data", "error", err.Error())
					return
				}
			}

			logger.Infow("successfully received data", "from", session.RemoteAddr(), "bytes", n)
		}()
	}
}
