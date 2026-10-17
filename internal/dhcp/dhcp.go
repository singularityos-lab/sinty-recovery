// Package dhcp obtains an IPv4 lease for one interface and configures it:
// address, default route and name servers. Recovery needs exactly that much
// networking to download an image, so it does it itself instead of shipping a
// separate DHCP client.
package dhcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	opRequest = 1
	opReply   = 2

	msgDiscover = 1
	msgOffer    = 2
	msgRequest  = 3
	msgAck      = 5
	msgNak      = 6

	optSubnet    = 1
	optRouter    = 3
	optDNS       = 6
	optRequested = 50
	optLeaseTime = 51
	optMsgType   = 53
	optServerID  = 54
	optParams    = 55
	optEnd       = 255
	optPad       = 0
)

var magicCookie = []byte{99, 130, 83, 99}

// Lease is what the server granted.
type Lease struct {
	IP      net.IP
	Mask    net.IPMask
	Router  net.IP
	DNS     []net.IP
	Server  net.IP
	Seconds uint32
}

type packet struct {
	op      byte
	xid     uint32
	flags   uint16
	ciaddr  net.IP
	yiaddr  net.IP
	chaddr  net.HardwareAddr
	options map[byte][]byte
}

func encode(p packet, order []byte) []byte {
	b := make([]byte, 240)
	b[0] = p.op
	b[1] = 1
	b[2] = byte(len(p.chaddr))
	binary.BigEndian.PutUint32(b[4:], p.xid)
	binary.BigEndian.PutUint16(b[10:], p.flags)
	if p.ciaddr != nil {
		copy(b[12:16], p.ciaddr.To4())
	}
	if p.yiaddr != nil {
		copy(b[16:20], p.yiaddr.To4())
	}
	copy(b[28:44], p.chaddr)
	copy(b[236:240], magicCookie)
	for _, code := range order {
		v, ok := p.options[code]
		if !ok {
			continue
		}
		b = append(b, code, byte(len(v)))
		b = append(b, v...)
	}
	b = append(b, optEnd)
	for len(b) < 300 {
		b = append(b, optPad)
	}
	return b
}

func decode(b []byte) (packet, error) {
	if len(b) < 240 || !bytes.Equal(b[236:240], magicCookie) {
		return packet{}, errors.New("not a DHCP packet")
	}
	hlen := int(b[2])
	if hlen > 16 {
		return packet{}, errors.New("bad hardware address length")
	}
	p := packet{
		op:      b[0],
		xid:     binary.BigEndian.Uint32(b[4:]),
		flags:   binary.BigEndian.Uint16(b[10:]),
		ciaddr:  net.IP(append([]byte(nil), b[12:16]...)),
		yiaddr:  net.IP(append([]byte(nil), b[16:20]...)),
		chaddr:  net.HardwareAddr(append([]byte(nil), b[28:28+hlen]...)),
		options: map[byte][]byte{},
	}
	for i := 240; i < len(b); {
		code := b[i]
		if code == optEnd {
			break
		}
		if code == optPad {
			i++
			continue
		}
		if i+1 >= len(b) || i+2+int(b[i+1]) > len(b) {
			return packet{}, errors.New("truncated DHCP option")
		}
		n := int(b[i+1])
		p.options[code] = append(p.options[code], b[i+2:i+2+n]...)
		i += 2 + n
	}
	return p, nil
}

func (p packet) msgType() byte {
	if v := p.options[optMsgType]; len(v) == 1 {
		return v[0]
	}
	return 0
}

func ipList(v []byte) []net.IP {
	var out []net.IP
	for i := 0; i+4 <= len(v); i += 4 {
		out = append(out, net.IP(append([]byte(nil), v[i:i+4]...)))
	}
	return out
}

func leaseFrom(p packet) (*Lease, error) {
	l := &Lease{IP: p.yiaddr}
	if l.IP.To4() == nil || l.IP.Equal(net.IPv4zero) {
		return nil, errors.New("the server offered no address")
	}
	if v := p.options[optSubnet]; len(v) == 4 {
		l.Mask = net.IPMask(append([]byte(nil), v...))
	} else {
		l.Mask = l.IP.DefaultMask()
	}
	if r := ipList(p.options[optRouter]); len(r) > 0 {
		l.Router = r[0]
	}
	l.DNS = ipList(p.options[optDNS])
	if s := ipList(p.options[optServerID]); len(s) > 0 {
		l.Server = s[0]
	}
	if v := p.options[optLeaseTime]; len(v) == 4 {
		l.Seconds = binary.BigEndian.Uint32(v)
	}
	return l, nil
}

var optionOrder = []byte{optMsgType, optRequested, optServerID, optParams}

// Acquire runs DISCOVER, OFFER, REQUEST, ACK on iface and returns the lease.
// Replies are asked to be broadcast, since the interface has no address yet.
func Acquire(ctx context.Context, iface string) (*Lease, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	conn, err := openRaw(ifi.Index)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var xidb [4]byte
	rand.Read(xidb[:])
	xid := binary.BigEndian.Uint32(xidb[:])
	base := packet{op: opRequest, xid: xid, flags: 0x8000, chaddr: ifi.HardwareAddr}
	params := []byte{optSubnet, optRouter, optDNS, optLeaseTime}

	discover := base
	discover.options = map[byte][]byte{optMsgType: {msgDiscover}, optParams: params}
	offer, err := exchange(ctx, conn, encode(discover, optionOrder), xid, msgOffer)
	if err != nil {
		return nil, fmt.Errorf("dhcp on %s: %w", iface, err)
	}
	request := base
	request.options = map[byte][]byte{
		optMsgType:   {msgRequest},
		optRequested: offer.yiaddr.To4(),
		optParams:    params,
	}
	if sid := offer.options[optServerID]; len(sid) == 4 {
		request.options[optServerID] = sid
	}
	ack, err := exchange(ctx, conn, encode(request, optionOrder), xid, msgAck)
	if err != nil {
		return nil, fmt.Errorf("dhcp on %s: %w", iface, err)
	}
	return leaseFrom(ack)
}

func exchange(ctx context.Context, conn *rawConn, msg []byte, xid uint32, want byte) (packet, error) {
	for attempt := 0; attempt < 5; attempt++ {
		if err := ctx.Err(); err != nil {
			return packet{}, err
		}
		if err := conn.send(msg); err != nil {
			return packet{}, err
		}
		deadline := time.Now().Add(time.Duration(2+attempt*2) * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		for time.Now().Before(deadline) {
			payload, err := conn.recv(deadline)
			if err != nil {
				break
			}
			p, err := decode(payload)
			if err != nil || p.op != opReply || p.xid != xid {
				continue
			}
			switch p.msgType() {
			case want:
				return p, nil
			case msgNak:
				return packet{}, errors.New("the server refused the request")
			}
		}
	}
	return packet{}, errors.New("no answer from a DHCP server")
}

// Configure gives iface the leased address, a default route through the
// router and writes the name servers to resolv.
func Configure(iface string, l *Lease, resolv string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	ones, _ := l.Mask.Size()
	if err := addAddress(ifi.Index, l.IP.To4(), ones); err != nil {
		return fmt.Errorf("address %s/%d on %s: %w", l.IP, ones, iface, err)
	}
	if l.Router != nil {
		if err := addDefaultRoute(ifi.Index, l.Router.To4()); err != nil {
			return fmt.Errorf("route via %s: %w", l.Router, err)
		}
	}
	if len(l.DNS) > 0 && resolv != "" {
		var b strings.Builder
		for _, d := range l.DNS {
			fmt.Fprintf(&b, "nameserver %s\n", d)
		}
		if err := os.WriteFile(resolv, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}
	return nil
}
