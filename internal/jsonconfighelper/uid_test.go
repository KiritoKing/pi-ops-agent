package jsonconfighelper

import "os"

func currentUIDForTest() int { return os.Getuid() }
