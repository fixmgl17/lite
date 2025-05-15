package app

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"lite/lite"
	"lite/pkg"
	"net/http"
	"time"
)

func respondText(w http.ResponseWriter, status int, err string) {
	w.WriteHeader(status)
	w.Write([]byte(err))
}

func respondJSON(w http.ResponseWriter, v any) {
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(b)
}

func buildAPIServer(app *App, config *APIConfig) (*http.Server, error) {
	token := app.config.API.Token
	addr, err := parseListenAddr(config.Listen)
	if err != nil {
		return nil, err
	}
	var tlsConfig *tls.Config
	if config.TLS != nil {
		tlsConfig, err = config.TLS.ToServerTLSConfig()
		if err != nil {
			return nil, err
		}
	}
	srv := &http.Server{
		Addr:      addr.Address(),
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Infoln(r.RemoteAddr, r.Method, r.RequestURI, r.Proto)
			q := r.URL.Query()
			if token != "" && q.Get("token") != token {
				respondText(w, http.StatusForbidden, "Forbidden")
				return
			}
			tag := q.Get("tag")
			switch r.URL.Path {
			case "/":
				resp := &appDetail{StartTime: app.StartTime()}
				app.RangeInbound(func(inb *Inbound) bool {
					detail := &inboundDetail{
						Tag: inb.Tag,
					}
					detail.Protocol, detail.Transport = inb.Info()
					if inb.liteServer != nil {
						inb.liteServer.RangeUser(func(user *lite.User) bool {
							detail.Users = append(detail.Users, getLiteUserDetail(user))
							return true
						})
					} else {
						detail.Username, detail.Password = inb.mixedServer.User()
					}
					resp.Inbounds = append(resp.Inbounds, detail)
					return true
				})
				app.RangeOutbound(func(ob *Outbound) bool {
					detail := &outboundDetail{
						Tag: ob.Tag,
					}
					detail.Protocol, detail.Transport = ob.Info()
					if ob.liteDialer != nil {
						user := ob.liteDialer.User()
						detail.User = getLiteUserDetail(user)
					} else if ob.mixedDialer != nil {
						detail.Username, detail.Password = ob.mixedDialer.User()
					}
					resp.Outbounds = append(resp.Outbounds, detail)
					return true
				})
				resp.Rules = app.config.Routing.Rules
				resp.Time = time.Now()
				resp.Duration = resp.Time.Sub(resp.StartTime).String()
				respondJSON(w, resp)
				return
			case "/tags":
				tags := make([]string, 0)
				app.RangeLiteInbound(func(inb *Inbound) bool {
					tags = append(tags, inb.Tag)
					return true
				})
				respondJSON(w, tags)
				return
			case "/users":
				inb := app.QueryLiteInbound(tag)
				if inb == nil {
					respondText(w, http.StatusBadRequest, "tag "+tag+" not found")
				} else {
					list := []*liteUserDetail{}
					inb.liteServer.RangeUser(func(user *lite.User) bool {
						list = append(list, getLiteUserDetail(user))
						return true
					})
					respondJSON(w, list)
				}
				return
			case "/add-user":
				if r.Method == http.MethodPut {
					inb := app.QueryLiteInbound(tag)
					if inb == nil {
						respondText(w, http.StatusBadRequest, "Tag "+tag+" not found")
						return
					}
					var user lite.UserConfig
					if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
						respondText(w, http.StatusBadRequest, err.Error())
						return
					}
					if err := inb.liteServer.AddUser(user); err != nil {
						respondText(w, http.StatusBadRequest, err.Error())
					} else {
						respondText(w, http.StatusOK, "User added")
					}
					return
				}
			case "/remove-user":
				if r.Method == http.MethodDelete {
					inb := app.QueryLiteInbound(tag)
					if inb == nil {
						respondText(w, http.StatusBadRequest, "tag "+tag+" not found")
						return
					}
					idStr := q.Get("id")
					if err := inb.liteServer.RemoveUser(idStr); err != nil {
						respondText(w, http.StatusBadRequest, err.Error())
					} else {
						respondText(w, http.StatusOK, "User removed")
					}
					return
				}
			}
			respondText(w, http.StatusNotFound, "Not Found")
		}),
	}
	return srv, nil
}

func (app *App) RangeLiteInbound(cb func(inb *Inbound) bool) {
	for _, inb := range app.Inbounds {
		if inb.liteServer != nil && !cb(inb) {
			return
		}
	}
}

func (app *App) QueryLiteInbound(tag string) (inb *Inbound) {
	app.RangeLiteInbound(func(entry *Inbound) bool {
		if entry.Tag == tag {
			inb = entry
			return false
		}
		return true
	})
	return
}

func getLiteUserDetail(user *lite.User) *liteUserDetail {
	detail := &liteUserDetail{
		ID:       hex.EncodeToString(user.ID[:]),
		LastTime: user.LastTime(),
		NetworkTraffic: NetworkTraffic{
			ReadBytes:  user.ReadBytes(),
			WriteBytes: user.WriteBytes(),
		},
		ReadBytesRateLimit:  user.ReadBytesRateLimit(),
		WriteBytesRateLimit: user.WriteBytesRateLimit(),
		ExpireTime:          user.ExpireTime,
	}
	return detail.Fill()
}

type inboundDetail struct {
	Tag       string            `json:"tag"`
	Protocol  string            `json:"protocol"`
	Transport string            `json:"transport,omitempty"`
	Users     []*liteUserDetail `json:"users,omitempty"`
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
}

type liteUserDetail struct {
	ID string `json:"id"`

	LastTime time.Time `json:"last_time"`

	NetworkTraffic

	ReadBytesRateLimit  int    `json:"read_bytes_rate_limit"`
	WriteBytesRateLimit int    `json:"write_bytes_rate_limit"`
	HReadRateLimit      string `json:"h_read_rate_limit"`
	HWriteRateLimit     string `json:"h_write_rate_limit"`

	ExpireTime time.Time `json:"expire_time"`
}

func (u *liteUserDetail) Fill() *liteUserDetail {
	u.NetworkTraffic.Fill()
	u.HReadRateLimit = pkg.FormatSize(u.ReadBytesRateLimit) + "/s"
	u.HWriteRateLimit = pkg.FormatSize(u.WriteBytesRateLimit) + "/s"
	return u
}

type outboundDetail struct {
	Tag       string `json:"tag"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport,omitempty"`
	User      any    `json:"user,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

type NetworkTraffic struct {
	ReadBytes  int64  `json:"read_bytes"`
	WriteBytes int64  `json:"write_bytes"`
	HRead      string `json:"h_read"`
	HWrite     string `json:"h_write"`
}

func (t *NetworkTraffic) Fill() *NetworkTraffic {
	t.HRead = pkg.FormatSize(t.ReadBytes)
	t.HWrite = pkg.FormatSize(t.WriteBytes)
	return t
}

type appDetail struct {
	StartTime time.Time           `json:"start_time"`
	Time      time.Time           `json:"time"`
	Duration  string              `json:"duration"`
	Inbounds  []*inboundDetail    `json:"inbounds,omitempty"`
	Outbounds []*outboundDetail   `json:"outbounds,omitempty"`
	Rules     []RoutingRuleConfig `json:"rules,omitempty"`
}
