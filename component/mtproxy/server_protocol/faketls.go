package server_protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/mtproxy/common"
	"github.com/metacubex/mihomo/component/mtproxy/tlstypes"
)

const (
	cloakLastActivityTimeout = 5 * time.Second
	cloakMaxTimeout          = 30 * time.Second
	TimeSkew                 = 5 * time.Second
	TimeFromBoot             = 24 * 60 * 60
	FakeTLSFirstByte         = 0x16
)

var (
	errBadDigest = errors.New("bad digest")
	//errBadTime   = errors.New("bad time")

	FakeTLSStartBytes = []byte{
		0x16,
		0x03,
		0x01,
	}
)

type fakeTLSServerProtocol struct {
	normalServerProtocol
	cloakHost string
	cloakPort string
}

func (c *fakeTLSServerProtocol) Handshake(socket net.Conn) (net.Conn, error) {
	rewinded := NewRewind(socket)
	bufferedReader := bufio.NewReader(rewinded)

	for _, expected := range FakeTLSStartBytes {
		if actual, err := bufferedReader.ReadByte(); err != nil || actual != expected {
			rewinded.Rewind()
			c.CloakHost(rewinded)

			return nil, errors.New("failed first bytes of tls handshake")
		}
	}

	var tlsHandshakeLen uint16
	if err := binary.Read(bufferedReader, binary.BigEndian, &tlsHandshakeLen); err != nil || tlsHandshakeLen < 512 {
		rewinded.Rewind()
		c.CloakHost(rewinded)

		return nil, errors.New("failed tls handshake length")
	}

	rewinded.Rewind()
	rewinded = NewRewind(rewinded)

	if err := c.tlsHandshake(rewinded); err != nil {
		rewinded.Rewind()
		c.CloakHost(rewinded)

		return nil, fmt.Errorf("failed tls handshake: %w", err)
	}

	conn := NewFakeTLS(socket)

	conn, err := c.normalServerProtocol.Handshake(conn)
	if err != nil {
		return nil, err
	}

	return conn, err
}

func (c *fakeTLSServerProtocol) tlsHandshake(conn net.Conn) error {
	helloRecord, err := tlstypes.ReadRecord(conn)
	if err != nil {
		return fmt.Errorf("cannot read initial record: %w", err)
	}

	buf := &bytes.Buffer{}
	helloRecord.Data.WriteBytes(buf)

	clientHello, err := tlstypes.ParseClientHello(buf.Bytes(), c.secret)
	if err != nil {
		return fmt.Errorf("cannot parse client hello: %w", err)
	}

	digest := clientHello.Digest()
	for i := 0; i < len(digest)-4; i++ {
		if digest[i] != 0 {
			return errBadDigest
		}
	}

	//timestamp := int64(binary.LittleEndian.Uint32(digest[len(digest)-4:]))
	//createdAt := time.Unix(timestamp, 0)
	//timeDiff := time.Since(createdAt)

	//if (timeDiff > TimeSkew || timeDiff < -TimeSkew) && timestamp > TimeFromBoot {
	//	return errBadTime
	//}

	serverHello := tlstypes.NewServerHello(clientHello)
	serverHelloPacket := serverHello.WelcomePacket()

	if _, err := conn.Write(serverHelloPacket); err != nil {
		return fmt.Errorf("cannot send welcome packet: %w", err)
	}

	return nil
}

func (c *fakeTLSServerProtocol) CloakHost(clientConn net.Conn) {
	if c.cloakPort == "0" {
		_ = clientConn.Close()
		return
	}
	addr := net.JoinHostPort(c.cloakHost, c.cloakPort)

	hostConn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}

	cloak(clientConn, hostConn)
}

func MakeFakeTLSServerProtocol(secret []byte, secretMode common.SecretMode, cloakHost string, cloakPort string) common.ServerProtocol {
	return &fakeTLSServerProtocol{
		normalServerProtocol: normalServerProtocol{
			secret:     secret,
			secretMode: secretMode,
		},
		cloakHost: cloakHost,
		cloakPort: cloakPort,
	}
}

func cloak(one, another net.Conn) {
	defer func() {
		one.Close()
		another.Close()
	}()

	channelPing := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	one = NewPing(ctx, one, channelPing)
	another = NewPing(ctx, another, channelPing)
	wg := &sync.WaitGroup{}

	wg.Add(2)

	go cloakPipe(one, another, wg)

	go cloakPipe(another, one, wg)

	go func() {
		wg.Wait()
		cancel()
	}()

	go func() {
		lastActivityTimer := time.NewTimer(cloakLastActivityTimeout)
		defer lastActivityTimer.Stop()

		maxTimer := time.NewTimer(cloakMaxTimeout)
		defer maxTimer.Stop()

		for {
			select {
			case <-channelPing:
				lastActivityTimer.Stop()
				lastActivityTimer = time.NewTimer(cloakLastActivityTimeout)
			case <-ctx.Done():
				return
			case <-lastActivityTimer.C:
				cancel()

				return
			case <-maxTimer.C:
				cancel()

				return
			}
		}
	}()

	<-ctx.Done()
}

func cloakPipe(one io.Writer, another io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()

	io.Copy(one, another)
}

type wrapperPing struct {
	net.Conn
	ctx         context.Context
	channelPing chan<- struct{}
}

func (w *wrapperPing) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if err == nil {
		select {
		case <-w.ctx.Done():
		case w.channelPing <- struct{}{}:
		}
	}

	return n, err
}

func (w *wrapperPing) Write(p []byte) (int, error) {
	n, err := w.Conn.Write(p)
	if err == nil {
		select {
		case <-w.ctx.Done():
		case w.channelPing <- struct{}{}:
		}
	}

	return n, err
}

func (w *wrapperPing) Close() error {
	return w.Conn.Close()
}

func NewPing(ctx context.Context, parent net.Conn, channelPing chan<- struct{}) net.Conn {
	return &wrapperPing{
		Conn:        parent,
		ctx:         ctx,
		channelPing: channelPing,
	}
}

type ReadWriteCloseRewinder interface {
	net.Conn
	Rewind()
}

type wrapperRewind struct {
	net.Conn
	activeReader io.Reader
	buf          bytes.Buffer
	mutex        sync.Mutex
}

func (w *wrapperRewind) Write(p []byte) (int, error) {
	return w.Conn.Write(p)
}

func (w *wrapperRewind) Read(p []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	return w.activeReader.Read(p)
}

func (w *wrapperRewind) Close() error {
	w.buf.Reset()

	return w.Conn.Close()
}

func (w *wrapperRewind) Rewind() {
	w.mutex.Lock()
	w.activeReader = io.MultiReader(&w.buf, w.Conn)
	w.mutex.Unlock()
}

func NewRewind(parent net.Conn) ReadWriteCloseRewinder {
	rv := &wrapperRewind{
		Conn: parent,
	}
	rv.activeReader = io.TeeReader(parent, &rv.buf)

	return rv
}

type wrapperFakeTLS struct {
	net.Conn
	buf bytes.Buffer
}

func (w *wrapperFakeTLS) flush(p []byte) (int, error) {
	if w.buf.Len() > len(p) {
		return w.buf.Read(p)
	}

	sizeToReturn := w.buf.Len()
	copy(p, w.buf.Bytes())
	w.buf.Reset()

	return sizeToReturn, nil
}

func (w *wrapperFakeTLS) read() ([]byte, error) {
	for {
		rec, err := tlstypes.ReadRecord(w.Conn)
		if err != nil {
			return nil, err
		}

		switch rec.Type {
		case tlstypes.RecordTypeChangeCipherSpec:
		case tlstypes.RecordTypeApplicationData:
			buf := &bytes.Buffer{}
			rec.Data.WriteBytes(buf)

			return buf.Bytes(), nil
		case tlstypes.RecordTypeHandshake:
			return nil, errors.New("unsupported record type handshake")
		default:
			return nil, fmt.Errorf("unsupported record type %v", rec.Type)
		}
	}
}

func (w *wrapperFakeTLS) Read(p []byte) (int, error) {
	if w.buf.Len() > 0 {
		return w.flush(p)
	}

	res, err := w.read()
	if err != nil {
		return 0, err
	}

	w.buf.Write(res)

	return w.flush(p)
}

func (w *wrapperFakeTLS) Write(p []byte) (int, error) {
	sum := 0
	buf := bytes.Buffer{}

	for _, v := range tlstypes.MakeRecords(p) {
		buf.Reset()
		v.WriteBytes(&buf)

		_, err := buf.WriteTo(w.Conn)
		if err != nil {
			return sum, err
		}

		sum += v.Data.Len()
	}

	return sum, nil
}

func NewFakeTLS(socket net.Conn) net.Conn {
	return &wrapperFakeTLS{
		Conn: socket,
	}
}
