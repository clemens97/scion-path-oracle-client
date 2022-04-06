package oclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/clemens97/scion-path-oracle"
	"github.com/clemens97/scion-path-oracle/server"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"github.com/scionproto/scion/go/lib/addr"
	"net/http"
	"os"
)

const (
	reportingURLTemplate = "http://%s/reports/%d/%d/%s/"
	scoringURLTemplate   = "http://%s/scorings/"
)

const jsonContentType = "application/json"

type OracleClient struct {
	httpc *http.Client
}

func NewOracleClient() OracleClient {
	return OracleClient{httpc: &http.Client{Transport: shttp.DefaultTransport}}
}

func (c *OracleClient) FetchScores(query server.ScoringQuery) (server.ScoringResponse, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	res, err := c.httpc.Post(scoringURL(), jsonContentType, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New("path oracle returned non 2xx status code:" + res.Status)
	}

	var scoringRes server.ScoringResponse
	if err := json.NewDecoder(res.Body).Decode(&scoringRes); err != nil {
		return nil, err
	}
	return scoringRes, nil
}

func (c *OracleClient) ReportStats(report oracle.Report) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = c.httpc.Post(reportingURL(report.DstIA, report.PathFp), jsonContentType, bytes.NewReader(body))
	return err
}

func reportingURL(dst addr.IA, fp oracle.PathFingerprint) string {
	return fmt.Sprintf(reportingURLTemplate, pathOracleLocation(), dst.I, dst.A, fp)
}

func scoringURL() string {
	return fmt.Sprintf(scoringURLTemplate, pathOracleLocation())
}

func pathOracleLocation() string {
	return os.Getenv("PATH_ORACLE")
}

// PathPublisher publish path updates to a PathSubscriber.
type PathPublisher interface {
	SetPathChan(chan<- *pan.Path)
}

// PathSubscriber are notified by the PathPublisher when the path of a connection changed.
type PathSubscriber interface {
	SetPathChan(<-chan *pan.Path)
}
