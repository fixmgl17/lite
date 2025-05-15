package sysproxy

import (
	_ "embed"
	"net"
)

//go:embed proxy_set_linux.sh
var linuxScript []byte

func init() {
	set = func(addr, bypass string) error {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		args := []string{"manual", host, port, bypass}
		return executeShellScript(linuxScript, args...)
	}
	unset = func() error {
		return executeShellScript(linuxScript, "none")
	}
}
