package dhcp

import (
	"net"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	mac, _ := net.ParseMAC("52:54:00:12:34:56")
	p := packet{op: opRequest, xid: 0xdeadbeef, flags: 0x8000, chaddr: mac, options: map[byte][]byte{
		optMsgType:   {msgRequest},
		optRequested: net.IPv4(10, 0, 2, 15).To4(),
		optParams:    {optSubnet, optRouter, optDNS},
	}}
	b := encode(p, optionOrder)
	if len(b) < 300 || b[0] != opRequest {
		t.Fatalf("encoded %d bytes", len(b))
	}
	q, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if q.xid != p.xid || q.flags != 0x8000 || q.chaddr.String() != mac.String() || q.msgType() != msgRequest {
		t.Fatalf("decoded %+v", q)
	}
	if !net.IP(q.options[optRequested]).Equal(net.IPv4(10, 0, 2, 15)) {
		t.Error("requested address lost")
	}
}

func TestLeaseFromAck(t *testing.T) {
	ack := packet{op: opReply, yiaddr: net.IPv4(192, 168, 1, 50).To4(), options: map[byte][]byte{
		optMsgType:   {msgAck},
		optSubnet:    {255, 255, 255, 0},
		optRouter:    {192, 168, 1, 1},
		optDNS:       {1, 1, 1, 1, 9, 9, 9, 9},
		optServerID:  {192, 168, 1, 1},
		optLeaseTime: {0, 0, 0x0e, 0x10},
	}}
	l, err := leaseFrom(ack)
	if err != nil {
		t.Fatal(err)
	}
	ones, _ := l.Mask.Size()
	if !l.IP.Equal(net.IPv4(192, 168, 1, 50)) || ones != 24 || !l.Router.Equal(net.IPv4(192, 168, 1, 1)) || len(l.DNS) != 2 || l.Seconds != 3600 {
		t.Fatalf("lease %+v", l)
	}
	if _, err := leaseFrom(packet{yiaddr: net.IPv4zero.To4()}); err == nil {
		t.Error("an empty offer must be refused")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := decode(make([]byte, 100)); err == nil {
		t.Error("short packet accepted")
	}
	b := encode(packet{op: opReply, chaddr: make([]byte, 6), options: map[byte][]byte{}}, nil)
	b[240] = optDNS
	b[241] = 200
	if _, err := decode(b[:250]); err == nil {
		t.Error("truncated option accepted")
	}
}
