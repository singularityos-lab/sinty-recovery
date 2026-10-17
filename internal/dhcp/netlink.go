package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

const (
	rtProtBoot   = 3
	rtScopeUniv  = 0
	rtTableMain  = 254
	rtnUnicast   = 1
	nlmsgHdrLen  = 16
	rtattrHdrLen = 4
	ifaddrmsgLen = 8
	rtmsgLen     = 12
	nlmFRequest  = 0x1
	nlmFAck      = 0x4
	nlmFCreate   = 0x400
	nlmFReplace  = 0x100
	nlmsgError   = 2
	ifaLocal     = 2
	ifaAddress   = 1
	ifaBroadcast = 4
	rtaGateway   = 5
	rtaOif       = 4
	rtmNewAddr   = 20
	rtmNewRoute  = 24
)

func attr(typ uint16, data []byte) []byte {
	l := rtattrHdrLen + len(data)
	b := make([]byte, (l+3)&^3)
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[rtattrHdrLen:], data)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func request(typ uint16, flags uint16, body []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	msg := make([]byte, nlmsgHdrLen+len(body))
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], typ)
	binary.LittleEndian.PutUint16(msg[6:], flags|nlmFRequest|nlmFAck)
	binary.LittleEndian.PutUint32(msg[8:], 1)
	copy(msg[nlmsgHdrLen:], body)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < nlmsgHdrLen+4 || binary.LittleEndian.Uint16(buf[4:]) != nlmsgError {
		return errors.New("unexpected netlink reply")
	}
	if code := int32(binary.LittleEndian.Uint32(buf[nlmsgHdrLen:])); code != 0 {
		return syscall.Errno(-code)
	}
	return nil
}

func addAddress(index int, ip net.IP, prefix int) error {
	body := make([]byte, ifaddrmsgLen)
	body[0] = syscall.AF_INET
	body[1] = byte(prefix)
	body[3] = rtScopeUniv
	binary.LittleEndian.PutUint32(body[4:], uint32(index))
	body = append(body, attr(ifaLocal, ip)...)
	body = append(body, attr(ifaAddress, ip)...)
	bcast := make(net.IP, 4)
	mask := net.CIDRMask(prefix, 32)
	for i := range bcast {
		bcast[i] = ip[i] | ^mask[i]
	}
	body = append(body, attr(ifaBroadcast, bcast)...)
	err := request(rtmNewAddr, nlmFCreate|nlmFReplace, body)
	if err == syscall.EEXIST {
		return nil
	}
	return err
}

func addDefaultRoute(index int, gw net.IP) error {
	body := make([]byte, rtmsgLen)
	body[0] = syscall.AF_INET
	body[4] = rtTableMain
	body[5] = rtProtBoot
	body[6] = rtScopeUniv
	body[7] = rtnUnicast
	body = append(body, attr(rtaGateway, gw)...)
	body = append(body, attr(rtaOif, u32(uint32(index)))...)
	return request(rtmNewRoute, nlmFCreate|nlmFReplace, body)
}
