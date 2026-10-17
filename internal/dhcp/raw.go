package dhcp

import (
	"encoding/binary"
	"errors"
	"syscall"
	"time"
)

const ethPIP = 0x0800

// rawConn speaks DHCP below the IP stack. Until the interface has an address
// the kernel does not hand IPv4 traffic to ordinary sockets, so requests and
// replies travel as hand-built IPv4/UDP packets on a packet socket.
type rawConn struct {
	fd    int
	index int
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func openRaw(index int) (*rawConn, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(htons(ethPIP)))
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &rawConn{fd: fd, index: index}, nil
}

func (c *rawConn) Close() error { return syscall.Close(c.fd) }

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func udpPacket(payload []byte, srcPort, dstPort uint16) []byte {
	total := 20 + 8 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	b[8] = 64
	b[9] = syscall.IPPROTO_UDP
	copy(b[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	binary.BigEndian.PutUint16(b[20:], srcPort)
	binary.BigEndian.PutUint16(b[22:], dstPort)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func (c *rawConn) send(payload []byte) error {
	to := &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: c.index, Halen: 6}
	copy(to.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	return syscall.Sendto(c.fd, udpPacket(payload, 68, 67), 0, to)
}

// recv returns the UDP payload of the next IPv4 packet sent to port 68.
func (c *rawConn) recv(deadline time.Time) ([]byte, error) {
	buf := make([]byte, 2048)
	for {
		wait := time.Until(deadline)
		if wait <= 0 {
			return nil, errors.New("timeout")
		}
		tv := syscall.NsecToTimeval(wait.Nanoseconds())
		syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		if payload, ok := udpPayload(buf[:n], 68); ok {
			return payload, nil
		}
	}
}

func udpPayload(b []byte, port uint16) ([]byte, bool) {
	if len(b) < 20 || b[0]>>4 != 4 || b[9] != syscall.IPPROTO_UDP {
		return nil, false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if ihl < 20 || total > len(b) || total < ihl+8 {
		return nil, false
	}
	if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
		return nil, false
	}
	udp := b[ihl:total]
	if binary.BigEndian.Uint16(udp[2:]) != port {
		return nil, false
	}
	ulen := int(binary.BigEndian.Uint16(udp[4:]))
	if ulen < 8 || ulen > len(udp) {
		return nil, false
	}
	return udp[8:ulen], true
}
