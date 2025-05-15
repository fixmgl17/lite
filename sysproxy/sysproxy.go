package sysproxy

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

var (
	set   func(addr string, bypass string) error
	unset func() error
)

// Bypass internal IP ranges
var InternalIPRanges = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*"

func Set(addr string, bypass string) error {
	if set == nil {
		return errors.New("not support os " + runtime.GOOS)
	}
	return set(addr, bypass)
}

func Unset() error {
	if unset == nil {
		return errors.New("not support os " + runtime.GOOS)
	}
	return unset()
}

func executeShellScript(b []byte, args ...string) error {
	f, err := os.CreateTemp("", "created_by_lite_*.sh")
	if err != nil {
		return err
	}
	p := f.Name()
	defer os.Remove(p)
	f.Chmod(0777)
	f.Write(b)
	f.Close()
	output, err := exec.Command(p, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	return errors.New(string(output))
}
