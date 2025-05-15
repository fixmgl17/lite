package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"lite/common"
	"lite/geo"
	"lite/pkg"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"
)

const GeoTag = "geo"

var (
	geoipDatPath   string
	geositeDatPath string
)

func init() {
	f, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exeDir := filepath.Dir(f)
	geoipDatPath = filepath.Join(exeDir, "geoip.dat")
	geositeDatPath = filepath.Join(exeDir, "geosite.dat")
}

func NewHostMatcherFromGeoIP(list *geo.GeoIP) (*HostMatcher, error) {
	n4 := make([]*net.IPNet, 0)
	n6 := make([]*net.IPNet, 0)
	for _, cidr := range list.Cidr {
		if len(cidr.Ip) == 4 {
			// IPv4
			n4 = append(n4, &net.IPNet{
				IP:   cidr.Ip,
				Mask: net.CIDRMask(int(cidr.Prefix), 32),
			})
		} else if len(cidr.Ip) == 16 {
			// IPv6
			n6 = append(n6, &net.IPNet{
				IP:   cidr.Ip,
				Mask: net.CIDRMask(int(cidr.Prefix), 128),
			})
		} else {
			return nil, errors.New("invalid IP length")
		}
	}
	return &HostMatcher{
		N4: n4,
		N6: n6,
	}, nil
}

type geoHandle struct {
	loadedGeoIP       bool
	loadedGeoSite     bool
	geoIPMatcherMap   map[string]*HostMatcher
	geoSiteMatcherMap map[string]*geo.GeoSiteMatcher
}

func (h *geoHandle) LoadGeoIP() error {
	h.loadedGeoIP = true
	geoIPMap, err := geo.LoadGeoIP(geoipDatPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	h.geoIPMatcherMap = make(map[string]*HostMatcher)
	for k, v := range geoIPMap {
		m, err := NewHostMatcherFromGeoIP(v)
		if err != nil {
			return fmt.Errorf("geoip %s: %w", k, err)
		}
		h.geoIPMatcherMap[k] = m
	}
	runtime.GC()
	return nil
}

func (h *geoHandle) LoadGeoSite() error {
	h.loadedGeoSite = true
	geoSiteMatcherMap, err := geo.LoadGeoSite(geositeDatPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	h.geoSiteMatcherMap = make(map[string]*geo.GeoSiteMatcher)
	for k, v := range geoSiteMatcherMap {
		m, err := geo.NewGeoSiteMatcher(v, nil)
		if err != nil {
			return fmt.Errorf("geosite %s: %w", k, err)
		}
		h.geoSiteMatcherMap[k] = m
	}
	runtime.GC()
	return nil
}

func (h *geoHandle) Release() {
	h.geoIPMatcherMap = nil
	h.geoSiteMatcherMap = nil
	runtime.GC()
	debug.FreeOSMemory()
}

func (h *geoHandle) GetGeoIPMatcher(k string) (*HostMatcher, error) {
	if !h.loadedGeoIP {
		err := h.LoadGeoIP()
		if err != nil {
			return nil, err
		}
	}
	if v := h.geoIPMatcherMap[k]; v == nil {
		return nil, fmt.Errorf("geoip %s not found", k)
	} else {
		return v, nil
	}
}

func (h *geoHandle) GetGeoSiteMatcher(k string) (*geo.GeoSiteMatcher, error) {
	if !h.loadedGeoSite {
		err := h.LoadGeoSite()
		if err != nil {
			return nil, err
		}
	}
	if v := h.geoSiteMatcherMap[k]; v == nil {
		return nil, fmt.Errorf("geosite %s not found", k)
	} else {
		return v, nil
	}
}

type geoFileUpdater struct {
	ipURL    string
	siteURL  string
	interval time.Duration
	app      *App
	cancel   func()
}

func newGeoFileUpdater(config *GeoConfig, app *App) (g *geoFileUpdater, err error) {
	g = &geoFileUpdater{
		app: app,
	}
	if config.UpdateInterval == "" {
		config.UpdateInterval = "72h"
	}
	g.interval, err = time.ParseDuration(config.UpdateInterval)
	if err != nil {
		return nil, err
	}
	g.interval = max(time.Minute*1, g.interval)
	if !pkg.IsURL(config.IPURL) {
		return nil, errors.New("invalid geoip url")
	}
	if !pkg.IsURL(config.SiteURL) {
		return nil, errors.New("invalid geosite url")
	}
	g.ipURL, g.siteURL = config.IPURL, config.SiteURL
	return
}

func (g *geoFileUpdater) Start(ctx context.Context) {
	ctx, g.cancel = context.WithCancel(ctx)
	for k, v := range map[string][]string{
		"geoip":   {g.ipURL, geoipDatPath},
		"geosite": {g.siteURL, geositeDatPath},
	} {
		name := k
		u, path := v[0], v[1]
		go func() {
			for {
				interval := g.interval
				if g.shouldUpdate(path) {
					logger.Debugf("Start update %s file", name)
					err := g.download(ctx, u, path)
					if err != nil {
						interval = time.Minute * 3
						logger.Errorf("Update %s file failed: %v", name, err)
					} else {
						logger.Infof("Update %s file successfully", name)
						err = g.app.RebuildRouting()
						if err != nil {
							logger.Errorln("Rebuild routing failed: ", err)
						} else {
							logger.Infoln("Rebuild routing successfully")
						}
					}
				}
				logger.Infof("Next %s file check in %s", name, interval)
				select {
				case <-time.After(interval):
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

func (g *geoFileUpdater) Close() error {
	if fn := g.cancel; fn != nil {
		fn()
	}
	return nil
}

func (g *geoFileUpdater) download(ctx context.Context, url string, p string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", common.DefaultUserAgent)
	host, port := req.URL.Hostname(), req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "http" {
			port = "80"
		} else if req.URL.Scheme == "https" {
			port = "443"
		}
	}
	a, err := common.NewNetAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	ob := g.app.Routing.Match(GeoTag, a, g.app.Outbounds)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		a, err := common.NewNetAddr(network, addr)
		if err != nil {
			return nil, err
		}
		return ob.DialTCP(ctx, a)
	}
	client := &http.Client{
		Transport: tr,
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	tempFile, err := os.CreateTemp("", "geo*.dat")
	if err != nil {
		return err
	}
	_, err = io.Copy(tempFile, resp.Body)
	tempFile.Close()
	if err == nil {
		err = os.Rename(tempFile.Name(), p)
	} else {
		os.Remove(tempFile.Name())
	}
	return err
}

func (g *geoFileUpdater) shouldUpdate(p string) bool {
	if info, err := os.Stat(p); err == nil && !info.IsDir() {
		return time.Since(info.ModTime()) >= g.interval
	}
	return true
}
