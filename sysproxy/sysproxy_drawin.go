package sysproxy

import (
	_ "embed"
	"net"
	"strings"
)

//go:embed proxy_set_osx.sh
var macosScript []byte

func init() {
	set = func(addr, bypass string) error {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		args := []string{"set", host, port}
		if bypass != "" {
			args = append(args, strings.Split(bypass, ";")...)
		}
		return executeShellScript(macosScript, args...)
	}
	unset = func() error {
		return executeShellScript(macosScript, "clear")
	}
}
