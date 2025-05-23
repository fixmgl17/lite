package app

var PrivateHosts = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
	"localhost",
}

func GetPrivateHostMatcher() *HostMatcher {
	m := &HostMatcher{}
	for _, host := range PrivateHosts {
		if err := m.AddHost(host); err != nil {
			panic(err)
		}
	}
	return m
}

func init() {
	_ = GetPrivateHostMatcher()
}
