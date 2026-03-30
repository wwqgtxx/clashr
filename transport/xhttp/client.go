package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/transport/gun"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/tls"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

type PacketUpConn struct {
	ctx       context.Context
	cfg       *Config
	host      string
	sessionID string
	transport http.RoundTripper
	writeMu   sync.Mutex
	seq       uint64
	reader    io.ReadCloser
	gun.NetAddr

	// deadlines
	deadline *time.Timer
}

func (c *PacketUpConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *PacketUpConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	u := url.URL{
		Scheme: "https",
		Host:   c.host,
		Path:   c.cfg.NormalizedPath(),
	}

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return 0, err
	}

	seqStr := strconv.FormatUint(c.seq, 10)
	c.seq++

	if err := c.cfg.FillPacketRequest(req, c.sessionID, seqStr, b); err != nil {
		return 0, err
	}
	req.Host = c.host

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return len(b), nil
}

func (c *PacketUpConn) Close() error {
	var err error
	if c.reader != nil {
		err = c.reader.Close()
	}
	forceCloseAllConnections(c.transport)
	return err
}

func (c *PacketUpConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *PacketUpConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *PacketUpConn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		if c.deadline != nil {
			c.deadline.Stop()
			c.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if c.deadline != nil {
		c.deadline.Reset(d)
		return nil
	}
	c.deadline = time.AfterFunc(d, func() {
		c.Close()
	})
	return nil
}

func DialStreamOne(
	ctx context.Context,
	cfg *Config,
	dialRaw DialRawFunc,
	wrapTLS WrapTLSFunc,
) (net.Conn, error) {
	requestURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}

	transport := &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapTLS(ctx, raw, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		},
	}

	pr, pw := io.Pipe()

	conn := &Conn{
		writer: pw,
	}

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			conn.SetLocalAddr(connInfo.Conn.LocalAddr())
			conn.SetRemoteAddr(connInfo.Conn.RemoteAddr())
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(contextutils.WithoutCancel(ctx), trace), http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	req.Host = cfg.Host

	if err := cfg.FillStreamRequest(req); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		forceCloseAllConnections(transport)
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		forceCloseAllConnections(transport)
		return nil, fmt.Errorf("xhttp stream-one bad status: %s", resp.Status)
	}
	conn.reader = resp.Body
	conn.onClose = func() {
		_ = resp.Body.Close()
		_ = pr.Close()
		forceCloseAllConnections(transport)
	}

	return conn, nil
}

func DialPacketUp(
	ctx context.Context,
	cfg *Config,
	dialRaw DialRawFunc,
	wrapTLS WrapTLSFunc,
) (net.Conn, error) {
	transport := &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string, _ *tls.Config) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapTLS(ctx, raw, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		},
	}

	sessionID := newSessionID()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}

	conn := &PacketUpConn{
		ctx:       contextutils.WithoutCancel(ctx),
		cfg:       cfg,
		host:      cfg.Host,
		sessionID: sessionID,
		transport: transport,
		seq:       0,
	}

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			conn.SetLocalAddr(connInfo.Conn.LocalAddr())
			conn.SetRemoteAddr(connInfo.Conn.RemoteAddr())
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(conn.ctx, trace), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if err := cfg.FillDownloadRequest(req, sessionID); err != nil {
		return nil, err
	}
	req.Host = cfg.Host

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		forceCloseAllConnections(transport)
		return nil, fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status)
	}
	conn.reader = resp.Body

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
