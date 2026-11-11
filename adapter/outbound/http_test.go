package outbound

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/require"
)

func TestHTTPConnectPreservesBufferedPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	serverResult := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err == nil {
			_ = req.Body.Close()
			_, err = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\nhello")
		}
		serverResult <- err
	}()
	proxy := &Http{Headers: make(http.Header)}
	conn, err := proxy.StreamConnContext(ctx, client, &C.Metadata{Host: "example.com", DstPort: 443})
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	payload := make([]byte, 5)
	_, err = io.ReadFull(conn, payload)
	require.NoError(t, err)
	require.Equal(t, "hello", string(payload))
	require.NoError(t, <-serverResult)
}
