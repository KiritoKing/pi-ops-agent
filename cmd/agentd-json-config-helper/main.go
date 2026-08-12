package main

import (
	"fmt"
	"os"

	"github.com/KiritoKing/pi-ops-agent/internal/jsonconfighelper"
)

func main() {
	if err := jsonconfighelper.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "agentd-json-config-helper:", err.Error())
		os.Exit(1)
	}
}
