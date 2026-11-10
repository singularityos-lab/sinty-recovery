package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const fake = `#!/bin/sh
in=$(cat)
echo "$* | $in" >> "$LOG"
case "$1" in
security-keys) printf '0\tBlue\n1\tSpare\n' ;;
add-security-key|remove-security-key|change-pin)
	case "$in" in
	untouched*) echo "sintykey: security-key-untouched" >&2; exit 3 ;;
	wrong*) exit 1 ;;
	esac ;;
esac
`

func ask(t *testing.T, sock, req string) []string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(req))
	var lines []string
	s := bufio.NewScanner(c)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines
}

func TestKeys(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sintykey")
	if err := os.WriteFile(bin, []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "log")
	t.Setenv("LOG", log)
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c.(*net.UnixConn), bin)
		}
	}()
	cases := []struct{ req, want string }{
		{"keys v1\n", "KEY 0\tBlue|KEY 1\tSpare|OK"},
		{"add-key v1\n1234\nYubi\n\n", "OK"},
		{"add-key v1\nuntouched\nYubi\n\n", "FAIL: security-key-untouched"},
		{"add-key v1\nwrong\nYubi\n\n", "FAIL: PIN incorrect or the security key was not added"},
		{"add-key v1\n1234\n \n\n", "FAIL: protocol"},
		{"remove-key v1\n1234\n1\n", "OK"},
		{"remove-key v1\n1234\nx\n", "FAIL: protocol"},
		{"remove-key v1\nuntouched\n0\n", "FAIL: security-key-untouched"},
		{"1234\n56789\n", "OK"},
		{"untouched\n56789\n", "FAIL: security-key-untouched"},
		{"wrong\n56789\n", "FAIL: current PIN incorrect or re-seal failed"},
	}
	for _, tc := range cases {
		if got := strings.Join(ask(t, sock, tc.req), "|"); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.req, got, tc.want)
		}
	}
	data, _ := os.ReadFile(log)
	uid := strings.TrimSpace(strings.Split(string(data), "\n")[0])
	if !strings.Contains(uid, "--uid "+strconv.Itoa(os.Getuid())) {
		t.Errorf("the uid is not the caller's: %s", uid)
	}
	if !strings.Contains(string(data), "add-security-key --uid "+strconv.Itoa(os.Getuid())+" --name Yubi | 1234") {
		t.Errorf("add did not reach sintykey: %s", data)
	}
}

