//go:build darwin

package process

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestFindByLibproc(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		host := "127.0.0.1"
		if network == "tcp6" {
			host = "::1"
		}
		l, err := net.Listen(network, net.JoinHostPort(host, "0"))
		if err != nil {
			t.Skip(err)
		}
		defer l.Close()
		go func() {
			if c, err := l.Accept(); err == nil {
				defer c.Close()
				select {}
			}
		}()
		c, err := net.Dial(network, l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		la := c.LocalAddr().(*net.TCPAddr)
		ip, _ := netip.AddrFromSlice(la.IP)
		path, err := findByLibproc(TCP, ip, la.Port)
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if path != self {
			t.Errorf("%s: path = %q, want %q", network, path, self)
		}
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ua := u.LocalAddr().(*net.UDPAddr)
	if path, err := findByLibproc(UDP, netip.MustParseAddr("127.0.0.1"), ua.Port); err != nil || path != self {
		t.Errorf("udp: %q %v", path, err)
	}
}
