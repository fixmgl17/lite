package app

import (
	"context"
	"errors"
	"fmt"
	"lite/common"
	"lite/dns"
	"lite/pkg"
	"lite/sysproxy"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger = pkg.NewLogger(zapcore.DebugLevel, os.Stdout)

func SetLogger(l *zap.SugaredLogger) {
	logger = l
}

var Version = "0.0.3"

type App struct {
	config         *Config
	startTime      time.Time
	geoFileUpdater *geoFileUpdater
	Routing        *Routing
	DNSClient      *dns.Client
	Inbounds       []*Inbound
	Outbounds      []*Outbound
	apiServer      *http.Server
}

func NewApp(config *Config) (*App, error) {
	if config.API != nil {
		_, err := parseListenAddr(config.API.Listen)
		if err != nil {
			return nil, fmt.Errorf("invalid api listen: %v", err)
		}
	}
	if len(config.Inbounds) == 0 {
		return nil, errors.New("inbounds cannot be empty")
	}
	app := &App{}
	var err error
	app.DNSClient, err = BuildDNSClient(config.DNS)
	if err != nil {
		return nil, err
	}
	inbTagMap := make(map[string]int)
	for i, v := range config.Inbounds {
		inbound, err := BuildInbound(v)
		if err != nil {
			return nil, fmt.Errorf("build the %dth inbound error: %v", i+1, err)
		}
		if inbound.Tag == GeoTag {
			return nil, fmt.Errorf("the %dth inbound tag cannot be %s", i+1, GeoTag)
		}
		if inbound.Tag == "" {
			inbound.Tag = "inbound-" + strconv.Itoa(i+1)
			config.Inbounds[i].Tag = inbound.Tag
		}
		if j := inbTagMap[inbound.Tag]; j > 0 {
			return nil, fmt.Errorf("the %dth inbound tag is duplicated by the one at position %d: %s", i+1, j, inbound.Tag)
		}
		inbTagMap[inbound.Tag] = i + 1
		app.Inbounds = append(app.Inbounds, inbound)
		printTLSCertInfo(fmt.Sprintf("Inbound <%s> tls cert info: ", inbound.Tag), v.TLS)
	}
	var existDirectOutbound, existBlockOutbound bool
	obTagMap := make(map[string]int)
	for i, v := range config.Outbounds {
		outbound, err := BuildOutbound(v)
		if err != nil {
			return nil, fmt.Errorf("build the %dth outbound error: %v", i+1, err)
		}
		if outbound.Tag == "" {
			outbound.Tag = "outbound-" + strconv.Itoa(i+1)
			config.Outbounds[i].Tag = outbound.Tag
		}
		if j := obTagMap[outbound.Tag]; j > 0 {
			return nil, fmt.Errorf("the %dth outbound tag is duplicated by the one at position %d: %s", i+1, j, outbound.Tag)
		}
		if outbound.Tag == DirectOutboundTag {
			existDirectOutbound = true
		} else if outbound.Tag == BlockOutboundTag {
			existBlockOutbound = true
		}
		printTLSCertInfo(fmt.Sprintf("Outbound <%s> tls cert info: ", outbound.Tag), v.TLS)
		app.Outbounds = append(app.Outbounds, outbound)
	}
	if !existDirectOutbound {
		app.Outbounds = append(app.Outbounds, NewDirectOutbound(DirectOutboundTag, DialModeAuto, ""))
	}
	if !existBlockOutbound {
		app.Outbounds = append(app.Outbounds, NewBlockOutbound())
	}
	for _, ob := range app.Outbounds {
		dnsClient := app.DNSClient.Clone()
		dnsClient.OnLookupIP = func(serverURL, host string, requireIPv6 bool, ipList []net.IP, err error) {
			var ipType string
			if requireIPv6 {
				ipType = "ipv6"
			} else {
				ipType = "ipv4"
			}
			if err == nil {
				logger.Debug("[", ob.Tag, "] lookup ", host, " to ", ipType, " on ", serverURL, ": ", joinIPList(ipList, ", "))
			} else {
				logger.Debug("[", ob.Tag, "] failed to lookup ", host, " to ", ipType, " on ", serverURL, ": ", err)
			}
		}
		dnsClient.OnLookupIPByCache = func(host string, requireIPv6 bool, ipList []net.IP, ok bool) {
			if !ok {
				return
			}
			var ipType string
			if requireIPv6 {
				ipType = "ipv6"
			} else {
				ipType = "ipv4"
			}
			logger.Debug("[", ob.Tag, "] lookup ", host, " to ", ipType, " on cache: ", joinIPList(ipList, ", "))
		}
		ob.Resolver = dnsClient
	}
	if config.Geo.IPURL != "" || config.Geo.SiteURL != "" {
		app.geoFileUpdater, err = newGeoFileUpdater(config.Geo, app)
		if err != nil {
			return nil, err
		}
	}
	app.Routing, err = BuildRouting(config.Routing)
	if err != nil {
		return nil, err
	}
	err = app.Routing.Validate(app.Inbounds, app.Outbounds)
	if err != nil {
		return nil, err
	}
	app.config = config
	inbMap := make(map[string][]string)
	for _, inb := range app.Inbounds {
		key := inb.ListenAddr.Network() + "://" + inb.ListenAddr.Address()
		inbMap[key] = append(inbMap[key], inb.Tag)
	}
	for k, v := range inbMap {
		if len(v) > 1 {
			return nil, fmt.Errorf("inbound tags %s have same listen address %s", strings.Join(v, ", "), k)
		}
	}
	if config.API != nil {
		apiServer, err := buildAPIServer(app, config.API)
		if err != nil {
			return nil, err
		}
		printTLSCertInfo("API server tls cert info: ", config.API.TLS)
		app.apiServer = apiServer
	}
	return app, nil
}

func (app *App) Start(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			app.Close()
		}
	}()
	if app.apiServer != nil {
		for _, inb := range app.Inbounds {
			if inb.liteServer != nil {
				inb.liteServer.EnableMeta()
			}
		}
		for _, ob := range app.Outbounds {
			if ob.liteDialer != nil {
				ob.liteDialer.EnableMeta()
			}
		}
	}
	for i := range app.Inbounds {
		inb := app.Inbounds[i]
		inb.GetOutbound = func(addr *common.NetAddr) *Outbound {
			return app.Routing.Match(inb.Tag, addr, app.Outbounds)
		}
	}
	startFns := make([]func() error, 0, len(app.Inbounds))
	for _, inb := range app.Inbounds {
		startFns = append(startFns, func() error {
			return inb.Start(ctx)
		})
	}
	startFns = append(startFns, func() error {
		srv := app.apiServer
		if srv != nil {
			var err error
			if srv.TLSConfig != nil {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("API server error: %v", err)
			}
		}
		return nil
	})
	err = common.RunWithTimeout(time.Millisecond*200, startFns...)
	if err != nil {
		return err
	}
	if app.geoFileUpdater != nil {
		app.geoFileUpdater.Start(ctx)
	}
	app.startTime = time.Now()
	if app.config.AutoSystemProxy {
		var addr string
		app.RangeInbound(func(inb *Inbound) bool {
			protocol, _ := inb.Info()
			if protocol == "mixed" {
				addr = common.JoinAddrPort("127.0.0.1", inb.ListenAddr.Port)
				return false
			}
			return true
		})
		if addr != "" {
			err := sysproxy.Set(addr, sysproxy.InternalIPRanges)
			if err != nil {
				logger.Errorln("Set system proxy", addr, "failed:", err)
			} else {
				logger.Warnln("Set system proxy", addr, "finished")
			}
		} else {
			logger.Warnln("No inbound using protocol mixed found, skip set system proxy")
		}
	}
	return nil
}

func (app *App) Close() (err error) {
	if app.apiServer != nil {
		app.apiServer.Close()
	}
	if app.geoFileUpdater != nil {
		app.geoFileUpdater.Close()
	}
	for i := range app.Inbounds {
		app.Inbounds[i].Close()
	}
	for i := range app.Outbounds {
		app.Outbounds[i].Close()
	}
	app.DNSClient.Close()
	if app.config.AutoSystemProxy {
		err = sysproxy.Unset()
		if err != nil {
			logger.Errorln("Unset system proxy failed:", err)
		} else {
			logger.Warnln("Unset system proxy finished")
		}
	}
	return err
}

func (app *App) RebuildRouting() error {
	routing, err := BuildRouting(app.config.Routing)
	if err != nil {
		return err
	}
	app.Routing = routing
	return nil
}

func (app *App) StartTime() time.Time {
	return app.startTime
}

func (app *App) RangeInbound(cb func(inb *Inbound) bool) {
	for _, inb := range app.Inbounds {
		if !cb(inb) {
			return
		}
	}
}

func (app *App) RangeOutbound(cb func(ob *Outbound) bool) {
	for _, ob := range app.Outbounds {
		if !cb(ob) {
			return
		}
	}
}

func (app *App) GetOutboundByTag(tag string) *Outbound {
	for _, ob := range app.Outbounds {
		if ob.Tag == tag {
			return ob
		}
	}
	return nil
}
