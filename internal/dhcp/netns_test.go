package dhcp

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func serve(t *testing.T, iface string, offer net.IP) {
	conn, err := listenServer(iface)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer conn.Close()
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req, err := decode(buf[:n])
			if err != nil || req.op != opRequest {
				continue
			}
			reply := packet{op: opReply, xid: req.xid, flags: req.flags, yiaddr: offer.To4(), chaddr: req.chaddr, options: map[byte][]byte{
				optSubnet:    {255, 255, 255, 0},
				optRouter:    {10, 9, 0, 1},
				optDNS:       {10, 9, 0, 53},
				optServerID:  {10, 9, 0, 1},
				optLeaseTime: {0, 0, 0x0e, 0x10},
			}}
			switch req.msgType() {
			case msgDiscover:
				reply.options[optMsgType] = []byte{msgOffer}
			case msgRequest:
				reply.options[optMsgType] = []byte{msgAck}
			default:
				continue
			}
			order := []byte{optMsgType, optSubnet, optRouter, optDNS, optServerID, optLeaseTime}
			conn.WriteToUDP(encode(reply, order), &net.UDPAddr{IP: net.IPv4bcast, Port: 68})
		}
	}()
}

func listenServer(iface string) (*net.UDPConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	if err := syscall.BindToDevice(fd, iface); err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 67}); err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "server")
	defer f.Close()
	c, err := net.FilePacketConn(f)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// TestLeaseInNamespace runs a real lease over a veth pair. It needs its own
// network namespace: SINTY_DHCP_NETNS=1 unshare -rn go test ./internal/dhcp
func TestLeaseInNamespace(t *testing.T) {
	if os.Getenv("SINTY_DHCP_NETNS") != "1" {
		t.Skip("needs a private network namespace")
	}
	for _, args := range [][]string{
		{"link", "add", "dev", "cl0", "type", "veth", "peer", "name", "sv0"},
		{"link", "set", "lo", "up"},
		{"link", "set", "cl0", "up"},
		{"link", "set", "sv0", "up"},
		{"addr", "add", "10.9.0.1/24", "dev", "sv0"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	serve(t, "sv0", net.IPv4(10, 9, 0, 50))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, err := Acquire(ctx, "cl0")
	if err != nil {
		t.Fatal(err)
	}
	resolv := filepath.Join(t.TempDir(), "resolv.conf")
	if err := Configure("cl0", l, resolv); err != nil {
		t.Fatal(err)
	}
	addr, _ := exec.Command("ip", "-4", "-br", "addr", "show", "dev", "cl0").Output()
	if !strings.Contains(string(addr), "10.9.0.50/24") {
		t.Errorf("address not set: %s", addr)
	}
	route, _ := exec.Command("ip", "-4", "route", "show", "default").Output()
	if !strings.Contains(string(route), "via 10.9.0.1 dev cl0") {
		t.Errorf("default route not set: %s", route)
	}
	data, _ := os.ReadFile(resolv)
	if string(data) != "nameserver 10.9.0.53\n" {
		t.Errorf("resolv.conf = %q", data)
	}
}
