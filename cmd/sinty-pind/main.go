// Command sinty-pind changes a desktop user's PIN over a unix socket, re-sealing via
// sintykey after binding the request to the caller's uid (SO_PEERCRED). It replaces
// the pkexec path, which polkit denies without an active logind session.
//
// Protocol, one request per connection:
//
//	-> "<current-PIN>\n<new-PIN>\n"
//	<- "OK\n" | "FAIL: <reason>\n"
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	socket := flag.String("socket", "/run/sinty-pind.sock", "unix socket the desktop connects to")
	sintykey := flag.String("sintykey", "/usr/bin/sintykey", "path to the sintykey CLI")
	flag.Parse()

	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("sinty-pind: listen %s: %v", *socket, err)
	}
	// 0666: the boundary is the peer uid plus the current PIN, not who opens the socket.
	if err := os.Chmod(*socket, 0o666); err != nil {
		log.Fatalf("sinty-pind: chmod: %v", err)
	}
	log.Printf("sinty-pind: serving %s", *socket)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c.(*net.UnixConn), *sintykey)
	}
}

// peerUID returns the caller's uid from the kernel (SO_PEERCRED). The client sends no
// uid, so a caller can only change its own PIN.
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		ucred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return int(ucred.Uid), nil
}

func handle(c *net.UnixConn, sintykey string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	uid, err := peerUID(c)
	if err != nil {
		fmt.Fprint(c, "FAIL: cannot determine caller identity\n")
		return
	}

	r := bufio.NewReader(io.LimitReader(c, 4096)) // PINs are short; cap the read
	cur, err1 := r.ReadString('\n')
	next, err2 := r.ReadString('\n')
	if err1 != nil || err2 != nil {
		fmt.Fprint(c, "FAIL: protocol (send <current-PIN>\\n<new-PIN>\\n)\n")
		return
	}
	cur = strings.TrimRight(cur, "\r\n")
	next = strings.TrimRight(next, "\r\n")
	if len(next) < 4 {
		fmt.Fprint(c, "FAIL: new PIN too short (minimum 4 characters)\n")
		return
	}

	// sintykey unseals under the current PIN (wrong PIN -> non-zero exit, TPM-throttled),
	// then re-seals under the new one. uid is the kernel's, never the client's.
	cmd := exec.Command(sintykey, "change-pin", "--uid", strconv.Itoa(uid))
	cmd.Stdin = strings.NewReader(cur + "\n" + next + "\n")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprint(c, "FAIL: current PIN incorrect or re-seal failed\n") // don't reveal which
		return
	}
	fmt.Fprint(c, "OK\n")
}
