package approvalsubmit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const maxConfirmationBytes = 2048

type DeviceConfirmer struct{}

func (DeviceConfirmer) Confirm(plan []byte, exactText string) error {
	if len(plan) == 0 || len(plan) > protocol.MaxFrameBytes || len(exactText) == 0 || len(exactText) > maxConfirmationBytes {
		return errors.New("approval plan or confirmation text exceeds its bound")
	}
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("a local controlling TTY is required for approval")
	}
	defer terminal.Close()
	info, err := terminal.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("/dev/tty is not a character device")
	}
	if _, err := fmt.Fprintf(terminal,
		"Pi Ops Agent authoritative canonical ApprovalPlan:\n%s\n\nType exactly to continue:\n%s\n> ",
		plan, exactText); err != nil {
		return errors.New("write approval plan to local TTY")
	}
	reader := bufio.NewReader(&io.LimitedReader{R: terminal, N: maxConfirmationBytes + 2})
	line, err := reader.ReadString('\n')
	if err != nil {
		return errors.New("read exact approval confirmation from local TTY")
	}
	if len(line) > maxConfirmationBytes+1 {
		return errors.New("approval confirmation exceeds its bound")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line != exactText {
		return errors.New("approval confirmation did not exactly match the required text")
	}
	return nil
}
