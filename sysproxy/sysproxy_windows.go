package sysproxy

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func init() {
	set = func(addr, bypass string) error {
		commands := []string{
			"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value " + addr,
			"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyOverride -Value '" + bypass + "'",
			"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1",
		}
		return executeMultiplePowershellCommands(commands)
	}
	unset = func() error {
		commands := []string{
			"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0",
			"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value ''",
			"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyOverride -Value ''",
		}
		return executeMultiplePowershellCommands(commands)
	}
}

func executeMultiplePowershellCommands(commands []string) error {
	errMap := make(map[int]error)
	for i := range commands {
		b, err := exec.Command("powershell", "-NoProfile", "-Command", commands[i]).CombinedOutput()
		if err != nil {
			errMap[i] = fmt.Errorf("%w: %s", err, string(b))
		}
	}
	if len(errMap) > 0 {
		reasons := make([]string, len(errMap))
		for i, err := range errMap {
			reasons = append(reasons, fmt.Sprintf("command %d: %v", i+1, err))
		}
		return errors.New(strings.Join(reasons, "; "))
	}
	return nil
}
