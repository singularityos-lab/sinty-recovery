// Command sinty-pind changes a desktop user's PIN over a unix socket, re-sealing via
// sintykey after binding the request to the caller's uid (SO_PEERCRED). It replaces
// the pkexec path, which polkit denies without an active logind session.
//
// Protocol, one request per connection:
//
//	-> "<current-PIN>\n<new-PIN>\n"
//	<- "OK\n" | "FAIL: <reason>\n"
//
//	-> "keys v1\n"
//	<- "KEY <index>\t<name>\n"... "OK\n"
//
//	-> "add-key v1\n<PIN>\n<name>\n<security-key-PIN>\n"
//	-> "remove-key v1\n<PIN>\n<index>\n"
//	<- "OK\n" | "FAIL: <reason>\n"
//
// A failure caused by the security key carries its sintykey code, such as
// security-key-untouched, as the reason.
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
	"regexp"
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

var keyFailure = regexp.MustCompile(`security-key-[a-z-]+`)

func readLine(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	return strings.TrimRight(s, "\r\n"), err
}

func runKey(sintykey string, stdin string, args ...string) (string, error) {
	cmd := exec.Command(sintykey, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr strings.Builder
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	out, err := cmd.Output()
	if err != nil {
		if code := keyFailure.FindString(stderr.String()); code != "" {
			return "", fmt.Errorf("%s", code)
		}
	}
	return string(out), err
}

func handleKeys(c *net.UnixConn, r *bufio.Reader, sintykey, request string, uid int) {
	id := strconv.Itoa(uid)
	switch request {
	case "keys v1":
		out, err := runKey(sintykey, "", "security-keys", "--uid", id)
		if err != nil {
			fmt.Fprint(c, "FAIL: cannot list the security keys\n")
			return
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line != "" {
				fmt.Fprintf(c, "KEY %s\n", line)
			}
		}
		fmt.Fprint(c, "OK\n")
	case "add-key v1":
		pin, err1 := readLine(r)
		name, err2 := readLine(r)
		devicePin, err3 := readLine(r)
		if err1 != nil || err2 != nil || err3 != nil || strings.TrimSpace(name) == "" {
			fmt.Fprint(c, "FAIL: protocol\n")
			return
		}
		if _, err := runKey(sintykey, pin+"\n"+devicePin+"\n", "add-security-key", "--uid", id, "--name", name); err != nil {
			reply(c, err, "PIN incorrect or the security key was not added")
			return
		}
		fmt.Fprint(c, "OK\n")
	case "remove-key v1":
		pin, err1 := readLine(r)
		index, err2 := readLine(r)
		if _, err := strconv.Atoi(index); err1 != nil || err2 != nil || err != nil {
			fmt.Fprint(c, "FAIL: protocol\n")
			return
		}
		if _, err := runKey(sintykey, pin+"\n", "remove-security-key", "--uid", id, "--index", index); err != nil {
			reply(c, err, "PIN incorrect or the security key was not removed")
			return
		}
		fmt.Fprint(c, "OK\n")
	}
}

func reply(c *net.UnixConn, err error, fallback string) {
	if strings.HasPrefix(err.Error(), "security-key-") {
		fmt.Fprintf(c, "FAIL: %s\n", err)
		return
	}
	fmt.Fprintf(c, "FAIL: %s\n", fallback)
}

func handle(c *net.UnixConn, sintykey string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(150 * time.Second))

	uid, err := peerUID(c)
	if err != nil {
		fmt.Fprint(c, "FAIL: cannot determine caller identity\n")
		return
	}

	r := bufio.NewReader(io.LimitReader(c, 4096)) // PINs are short; cap the read
	cur, err1 := readLine(r)
	if err1 == nil && (cur == "keys v1" || cur == "add-key v1" || cur == "remove-key v1") {
		handleKeys(c, r, sintykey, cur, uid)
		return
	}
	next, err2 := readLine(r)
	if err1 != nil || err2 != nil {
		fmt.Fprint(c, "FAIL: protocol (send <current-PIN>\\n<new-PIN>\\n)\n")
		return
	}
	if len(next) < 4 {
		fmt.Fprint(c, "FAIL: new PIN too short (minimum 4 characters)\n")
		return
	}

	// sintykey unseals under the current PIN (wrong PIN -> non-zero exit, TPM-throttled),
	// then re-seals under the new one. uid is the kernel's, never the client's.
	if _, err := runKey(sintykey, cur+"\n"+next+"\n", "change-pin", "--uid", strconv.Itoa(uid)); err != nil {
		reply(c, err, "current PIN incorrect or re-seal failed")
		return
	}
	fmt.Fprint(c, "OK\n")
}
