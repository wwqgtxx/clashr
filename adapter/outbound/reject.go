package outbound

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type Reject struct {
	*Base
}

type RejectOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (r *Reject) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	return NewConn(nopConn{}, r), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (r *Reject) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := r.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	return newPacketConn(nopPacketConn{}, r), nil
}

func (r *Reject) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if !metadata.Resolved() {
		metadata.DstIP = netip.IPv4Unspecified()
	}
	return nil
}

func NewRejectWithOption(option RejectOption) *Reject {
	return &Reject{
		Base: NewBase(BaseOption{
			Name: option.Name,
			Type: C.Reject,
			UDP:  true,
		}),
	}
}

func NewReject() *Reject {
	return &Reject{
		Base: NewBase(BaseOption{
			Name:   "REJECT",
			Type:   C.Reject,
			UDP:    true,
			Prefer: C.DualStack,
		}),
	}
}

func NewPass() *Reject {
	return &Reject{
		Base: NewBase(BaseOption{
			Name:   "PASS",
			Type:   C.Pass,
			UDP:    true,
			Prefer: C.DualStack,
		}),
	}
}

type nopConn struct{}

func (rw nopConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

func (rw nopConn) Write(b []byte) (int, error) {
	return 0, io.EOF
}

func (rw nopConn) Close() error                     { return nil }
func (rw nopConn) LocalAddr() net.Addr              { return nil }
func (rw nopConn) RemoteAddr() net.Addr             { return nil }
func (rw nopConn) SetDeadline(time.Time) error      { return nil }
func (rw nopConn) SetReadDeadline(time.Time) error  { return nil }
func (rw nopConn) SetWriteDeadline(time.Time) error { return nil }

var udpAddrIPv4Unspecified = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

type nopPacketConn struct{}

func (npc nopPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) { return len(b), nil }
func (npc nopPacketConn) ReadFrom(b []byte) (int, net.Addr, error)           { return 0, nil, io.EOF }
func (npc nopPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, io.EOF
}
func (npc nopPacketConn) Close() error { return nil }
func (npc nopPacketConn) LocalAddr() net.Addr {
	return udpAddrIPv4Unspecified
}
func (npc nopPacketConn) SetDeadline(time.Time) error      { return nil }
func (npc nopPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (npc nopPacketConn) SetWriteDeadline(time.Time) error { return nil }
