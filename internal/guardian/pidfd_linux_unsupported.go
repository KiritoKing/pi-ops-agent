//go:build linux && !amd64 && !arm64

package guardian

import "syscall"

func platformPidfdSupported() bool { return false }

func pidfdOpenExact(int) (int, error) { return -1, syscall.ENOSYS }

func pidfdSignalExact(int, syscall.Signal) error { return syscall.ENOSYS }
