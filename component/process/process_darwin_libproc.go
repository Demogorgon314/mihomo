//go:build darwin

package process

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// findByLibproc finds the process owning a socket by walking every
// process's file descriptors with proc_pidinfo/proc_pidfdinfo, as lsof does.
//
// It is the fallback for the net.inet.*.pcblist_n sysctl, which some
// processes get an empty list from: on recent macOS a process whose
// responsible process is not a shell (e.g. one started by a GUI app or
// another Go program) sees only the 24-byte header.
func findByLibproc(network string, ip netip.Addr, port int) (string, error) {
	wantKind := int32(sockinfoTCP)
	if network == UDP {
		wantKind = sockinfoIN
	}
	pids, err := listPIDs()
	if err != nil {
		return "", err
	}
	var fallbackUDP string
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		fds, err := listFDs(pid)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if fd.fdtype != proxFDTypeSocket {
				continue
			}
			var si socketFDInfo
			if !pidFDSocketInfo(pid, fd.fd, &si) {
				continue
			}
			if si.kind != wantKind {
				continue
			}
			if int(si.lport) != port || !si.ok {
				continue
			}
			laddr := si.laddr
			if laddr == ip.Unmap() {
				return getExecPathFromPID(uint32(pid))
			}
			if network == UDP && laddr.IsUnspecified() && laddr.Is4() == ip.Unmap().Is4() && fallbackUDP == "" {
				fallbackUDP, _ = getExecPathFromPID(uint32(pid))
			}
		}
	}
	if fallbackUDP != "" {
		return fallbackUDP, nil
	}
	return "", ErrNotFound
}

const (
	procAllPIDs         = 1
	procPIDListFDs      = 1
	procPIDFDSocketInfo = 3
	proxFDTypeSocket    = 2
	sockinfoIN          = 1
	sockinfoTCP         = 2
	iniIPv4             = 0x1
	iniIPv6             = 0x2
	procPIDListFDSize   = 8
	procPIDFDSocketSize = 792 // sizeof(struct socket_fdinfo)
	callProcListPIDs    = 1
	callProcPIDInfo     = 2
	callProcPIDFDInfo   = 3
)

func procInfo(call, pid, flavor int, arg uint64, buf unsafe.Pointer, size int) (int, error) {
	r, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, uintptr(call), uintptr(pid), uintptr(flavor), uintptr(arg), uintptr(buf), uintptr(size))
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

func listPIDs() ([]int32, error) {
	n, err := procInfo(callProcListPIDs, procAllPIDs, 0, 0, nil, 0)
	if err != nil {
		return nil, err
	}
	buf := make([]int32, n/4+64)
	n, err = procInfo(callProcListPIDs, procAllPIDs, 0, 0, unsafe.Pointer(&buf[0]), len(buf)*4)
	if err != nil {
		return nil, err
	}
	return buf[:n/4], nil
}

type fdInfo struct {
	fd     int32
	fdtype uint32
}

func listFDs(pid int32) ([]fdInfo, error) {
	n, err := procInfo(callProcPIDInfo, int(pid), procPIDListFDs, 0, nil, 0)
	if err != nil || n <= 0 {
		return nil, err
	}
	buf := make([]fdInfo, n/procPIDListFDSize+16)
	n, err = procInfo(callProcPIDInfo, int(pid), procPIDListFDs, 0, unsafe.Pointer(&buf[0]), len(buf)*procPIDListFDSize)
	if err != nil {
		return nil, err
	}
	return buf[:n/procPIDListFDSize], nil
}

// Offsets in struct socket_fdinfo (sys/proc_info.h), checked with
// offsetof() against the macOS SDK; the layout is the same on arm64 and
// amd64 and has been stable since 10.x.
const (
	offSoiKind  = 256 // psi.soi_kind
	offSoiProto = 264 // psi.soi_proto: in_sockinfo (tcp_sockinfo.tcpsi_ini at 0)
	offInLport  = 4   // in_sockinfo.insi_lport
	offInVflag  = 24  // in_sockinfo.insi_vflag
	offInLaddr  = 48  // in_sockinfo.insi_laddr (in4in6_addr: v4 at +12)
)

type socketFDInfo struct {
	kind  int32
	lport uint16
	laddr netip.Addr
	ok    bool
}

func pidFDSocketInfo(pid int32, fd int32, out *socketFDInfo) bool {
	var raw [procPIDFDSocketSize]byte
	n, err := procInfo(callProcPIDFDInfo, int(pid), procPIDFDSocketInfo, uint64(fd), unsafe.Pointer(&raw[0]), len(raw))
	if err != nil || n != procPIDFDSocketSize {
		return false
	}
	out.kind = int32(binary.LittleEndian.Uint32(raw[offSoiKind:]))
	in := raw[offSoiProto:]
	// insi_lport holds the port in network order in its low 16 bits
	out.lport = binary.BigEndian.Uint16(in[offInLport:])
	vflag := in[offInVflag]
	addr := in[offInLaddr : offInLaddr+16]
	switch {
	case vflag&iniIPv4 != 0:
		out.laddr, out.ok = netip.AddrFrom4([4]byte(addr[12:16])), true
	case vflag&iniIPv6 != 0:
		out.laddr, out.ok = netip.AddrFrom16([16]byte(addr)).Unmap(), true
	default:
		out.ok = false
	}
	return true
}
