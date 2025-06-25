package obfs

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/pool"

	"github.com/metacubex/randv2"
)

func init() {
	register("http_simple", newHTTPSimple, 0)
}

type httpObfs struct {
	*Base
	post bool
}

func newHTTPSimple(b *Base) Obfs {
	return &httpObfs{Base: b}
}

type httpConn struct {
	net.Conn
	*httpObfs
	hasSentHeader bool
	hasRecvHeader bool
	buf           []byte
}

func (h *httpObfs) StreamConn(c net.Conn) net.Conn {
	return &httpConn{Conn: c, httpObfs: h}
}

func (c *httpConn) Read(b []byte) (int, error) {
	if c.buf != nil {
		n := copy(b, c.buf)
		if n == len(c.buf) {
			c.buf = nil
		} else {
			c.buf = c.buf[n:]
		}
		return n, nil
	}

	if c.hasRecvHeader {
		return c.Conn.Read(b)
	}

	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	pos := bytes.Index(buf[:n], []byte("\r\n\r\n"))
	if pos == -1 {
		return 0, io.EOF
	}
	c.hasRecvHeader = true
	dataLength := n - pos - 4
	n = copy(b, buf[4+pos:n])
	if dataLength > n {
		c.buf = append(c.buf, buf[4+pos+n:4+pos+dataLength]...)
	}
	return n, nil
}

func (c *httpConn) Write(b []byte) (int, error) {
	if c.hasSentHeader {
		return c.Conn.Write(b)
	}
	// 30: head length
	headLength := c.IVSize + 30

	bLength := len(b)
	headDataLength := bLength
	if bLength-headLength > 64 {
		headDataLength = headLength + randv2.IntN(65)
	}
	headData := b[:headDataLength]
	b = b[headDataLength:]

	var body string
	host := c.Host
	if len(c.Param) > 0 {
		pos := strings.Index(c.Param, "#")
		if pos != -1 {
			body = strings.ReplaceAll(c.Param[pos+1:], "\n", "\r\n")
			body = strings.ReplaceAll(body, "\\n", "\r\n")
			host = c.Param[:pos]
		} else {
			host = c.Param
		}
	}
	hosts := strings.Split(host, ",")
	host = hosts[randv2.IntN(len(hosts))]

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	if c.post {
		buf.WriteString("POST /")
	} else {
		buf.WriteString("GET /")
	}
	packURLEncodedHeadData(buf, headData)
	buf.WriteString(" HTTP/1.1\r\nHost: " + host)
	if c.Port != 80 {
		buf.WriteString(":" + strconv.Itoa(c.Port))
	}
	buf.WriteString("\r\n")
	if len(body) > 0 {
		buf.WriteString(body + "\r\n\r\n")
	} else {
		buf.WriteString("User-Agent: ")
		buf.WriteString(userAgent[randv2.IntN(len(userAgent))])
		buf.WriteString("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n")
		if c.post {
			packBoundary(buf)
		}
		buf.WriteString("DNT: 1\r\nConnection: keep-alive\r\n\r\n")
	}
	buf.Write(b)
	_, err := c.Conn.Write(buf.Bytes())
	if err != nil {
		return 0, err
	}
	c.hasSentHeader = true
	return bLength, nil
}

func packURLEncodedHeadData(buf *bytes.Buffer, data []byte) {
	dataLength := len(data)
	for i := 0; i < dataLength; i++ {
		buf.WriteRune('%')
		buf.WriteString(hex.EncodeToString(data[i : i+1]))
	}
}

func packBoundary(buf *bytes.Buffer) {
	buf.WriteString("Content-Type: multipart/form-data; boundary=")
	set := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 32; i++ {
		buf.WriteByte(set[randv2.IntN(62)])
	}
	buf.WriteString("\r\n")
}

var userAgent = []string{
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
	"Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
	"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
}
