//go:build linux

package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSOPEERCREDReportsClientUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan Credential, 1)
	fail := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			fail <- err
			return
		}
		defer connection.Close()
		credential, err := OSResolver{}.Resolve(connection)
		if err != nil {
			fail <- err
			return
		}
		done <- credential
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case err := <-fail:
		t.Fatal(err)
	case credential := <-done:
		if credential.UID != uint32(os.Getuid()) {
			t.Fatalf("uid=%d want=%d", credential.UID, os.Getuid())
		}
	}
}
