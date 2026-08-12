//go:build linux && (amd64 || arm64)

package guardian

import "syscall"

// pidfd_send_signal and pidfd_open use the asm-generic syscall numbering on
// both supported release architectures.
const (
	sysPidfdSendSignal = 424
	sysPidfdOpen       = 434
)

func platformPidfdSupported() bool { return true }

func pidfdOpenExact(pid int) (int, error) {
	fd, _, errno := syscall.Syscall(uintptr(sysPidfdOpen), uintptr(pid), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func pidfdSignalExact(fd int, signal syscall.Signal) error {
	_, _, errno := syscall.Syscall6(uintptr(sysPidfdSendSignal), uintptr(fd), uintptr(signal), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
