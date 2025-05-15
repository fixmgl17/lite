# Lite

A simple yet powerful proxy protocol and tool.

> Refer to the `examples` directory for configuration examples. For detailed protocol specifications and sharing links, refer to [lite-protocol.en.md](./lite-protocol.en.md). After downloading the program, run it with the `--help` parameter in the command line for more usage instructions.

## Features

* [x] Lite Protocol, UTLS, and Full Cone UDP support
* [x] Custom DNS and Dual Stack (IPv4/IPv6) support
* [x] Powerful routing
* [x] HTTP fallback support
* [x] Auto system proxy (for clients)
* [ ] Outbound automatic selection policy (Coming Soon)

## Guide

* [Config Structure](#config-structure)
* [Auto System Proxy](#auto-system-proxy)
* [Log](#log)
* [API](#api)
* [DNS](#dns)
* [Routing](#routing)
* [Inbounds](#inbounds)

  * [Tag](#tag)
  * [Protocol](#protocol)
  * [Transport](#transport)
  * [TLS](#tls)
  * [Listen](#listen)
* [Outbounds](#outbounds)

  * [Tag](#tag-1)
  * [Dial Mode](#dial-mode)
  * [DNS Resolve](#dns-resolve)
  * [Protocol](#protocol-1)
  * [Transport](#transport-1)
  * [TLS](#tls-1)
  * [Server](#server)

## Config Structure

Supports both TOML and JSON. This documentation uses TOML as an example.

```toml
auto_system_proxy=false

[log]
level=""
output=""
max_size=""

[api]
listen=""
token=""
tls={}

[dns]
ttl=""
server=""

[routing]
rules = [
    { inbound_tags = [], outbound_tags = [], time_range = "", require_ipv6 = false, network = "", port_range = "", include_hosts = [], exclude_hosts = [] },
]

[[inbounds]]
tag=""
protocol=""
protocol_settings={}
transport=""
transport_settings={}
tls={}
listen=""

[[outbounds]]
tag=""
dial_mode=""
dns_resolve=""
protocol=""
protocol_settings={}
transport=""
transport_settings={}
tls={}
server=""
```

## Auto System Proxy

```toml
auto_system_proxy=true
# When the program starts, automatically sets the first 'mixed' inbound as the system proxy entry, and clears it upon exit
```

## Log

```toml
[log]
level = ""  # Default is info, options: debug | info | warn | error | fatal
output = "" # Default is stdout; can specify a file path. If set to "discard", logging is disabled.
max_size = "" # When using a file for logging, specifies the max file size. Exceeds this size, log is reset. e.g., 1KB, 1MB, 1GB
```

## API

Refer to [api.en.md](./api.en.md) for API documentation.

```toml
[api]
listen = ""  # host:port
token = ""
tls = { cert_path = "xxx", key_path = "xxx" }
```

## DNS

Traffic bypasses routing and goes directly through the local network. It's recommended to use DoH.

```toml
ttl = "" # DNS cache duration, default 5 minutes. Format: 3s, 3m, 3h. Set to 0 to disable caching.
server_url=""
# Default is empty (uses system DNS)
# Supports UDP and HTTPS: e.g., udp://1.1.1.1 or https://1.1.1.1/dns-query
```

## Geo

```toml
[geo]
update_interval=""
ip_url=""
site_url=""
# GeoIP database configuration. Automatically downloads to program directory and rebuilds routing on update.
# Default update interval: 72h (3 days)
# Geo file download is routed and uses the inbound tag 'geo' to enter routing.
```

## Routing

Simple and effective routing rules.

```toml
[routing]
rules = [
    { inbound_tags = [ "inbound1" ], outbound_tags = [ "direct" ], time_range = "16:00-23:00", require_ipv6 = false, network = "tcp", port_range = "22,80-443", include_hosts = ["private"], exclude_hosts = ["google.com"]  },
]
```

* `inbound_tags`: If empty, matches all; otherwise, exact match is required.
* `outbound_tags`: Must not be empty.
* `time_range`: Format: `hour-hour`, `hh:mm-hh:mm`, or `hh:mm:ss-hh:mm:ss`. Defaults: 0:00 and 23:59:59.
* `require_ipv6`: Requires IPv6 environment if true.
* `network`: `tcp` or `udp`. Empty means all protocols.
* `port_range`: Format: `port1,port2,port3-port4`.
* `include_hosts`, `exclude_hosts`: Can be domain, IP, or CIDR. Supports subdomain matching and predefined lists like `private`, `geosite:xxx`, or `geoip:xxx`.

If no rule matches an inbound, the first outbound is used. If `direct` or `block` outbounds are missing, they are auto-created with special meanings: direct connection or block.

## Inbounds

Array of inbound configurations.

```toml
[[inbounds]]
tag=""
protocol=""
protocol_settings={}

# Only used for 'lite' protocol
transport=""
transport_settings={}

tls={}
listen=""
```

### Tag

String. Default is `inbound-{index+1}` (e.g., `inbound-2`). Must not be "geo".

```toml
tag = "xxx"
```

### Protocol

`lite` | `mixed`

* `lite`: Core protocol. Lightweight, supports TCP/UDP, and Full Cone UDP.

  ```toml
  protocol="lite"
  protocol_settings={ users=[{id="",expire_time="",read_rate_limit="",write_rate_limit=""}] }
  # id: UUID or plain string. If empty, creates a default user with empty id.
  # *_rate_limit: Optional. Limit data rate per second. e.g., 1.2MB, 1KB
  # expire_time: Optional. Formats supported: RFC3339, DateOnly, or "2006/01/02 15:04:05"
  ```

* `mixed`: Multiplexes HTTP and SOCKS5. Intended for internal LAN clients.

  ```toml
  protocol="mixed"
  protocol_settings={ username="xxx", password="xxx" }
  # If no username/password, authentication is skipped
  ```

### Transport

`tcp` | `websocket` (only for `lite`)

* `tcp`:

  ```toml
  transport="tcp"
  transport_settings={} # No options
  ```

* `websocket`: HTTP/1.1 only. Requires TLS. Supports fallback.

  ```toml
  transport="websocket"
  transport_settings={path="/xxx", host="/xxx", early_data_header_name="xxx", fallback="xxx"}
  # path/host: if empty, not validated.
  # early_data_header_name: sends early data via specified HTTP header. Base64.RawURLEncoding, max 2048 bytes.
  # fallback: triggered when path/host don't match. Acts as reverse proxy or static file server.
  ```

### TLS

Enable by setting this section.

```toml
tls={cert_path = "xxx", key_path = "xxx"}
# Paths to certificate and private key files
```

### Listen

```toml
listen="" # host:port
```

## Outbounds

Array of outbound configurations.

```toml
[[outbounds]]
tag=""
dial_mode=""
dns_resolve=""
protocol=""
protocol_settings={}

# Only used for 'lite' protocol
transport=""
transport_settings={}

tls={}
server=""
```

### Tag

String. Default is `outbound-{index+1}`.

```toml
tag="xxx"
```

### Dial Mode

`auto` | `46` | `64` | `4` | `6`

Used when outbound's protocol is `direct`, or for resolving domain targets.

```toml
dial_mode = "46"
# auto: connect to both IPv4 and IPv6, use first success
# 64: prefer IPv6, fallback to IPv4
# 46: prefer IPv4, fallback to IPv6
# 6: IPv6 only
# 4: IPv4 only
```

### DNS Resolve

`46` | `64` | `4` | `6`

If set, tries to resolve the domain locally before outbound. Works with UDP NAT mapping.

```toml
dns_resolve = "46"
# 64: resolve both, prefer IPv4
# 46: resolve both, prefer IPv4
# 6: IPv6 only
# 4: IPv4 only
```

### Protocol

`lite` | `http` | `socks5` | `direct` | `block`

Default: `direct`

* `lite`:

  ```toml
  protocol="lite"
  protocol_settings={ user={id="",expire_time="",read_rate_limit="",write_rate_limit=""} }
  # id must be UUID or 32-char hex string
  ```

* `http`:

  ```toml
  protocol="http"
  protocol_settings={ user={ username="xxx", password="xxx"} }
  ```

* `socks5`:

  ```toml
  protocol="socks5"
  protocol_settings={ user={ username="xxx", password="xxx"} }
  ```

* `direct`: Bypasses proxy, uses system network stack.

* `block`: Blocks the connection.

### Transport

`tcp` | `websocket`

* `tcp`:

  ```toml
  transport="tcp"
  transport_settings={} # No options
  ```

* `websocket`:

  ```toml
  transport="websocket"
  transport_settings={only_http_upgrade=false, early_data_header_name="xxx", path="/xxx", host="/xxx", headers={ "user-agent"="xxx" } }
  # only_http_upgrade: disables websocket frames
  # host: if empty, uses tls.server_name or server host
  # headers: default User-Agent and Origin will be set automatically
  ```

### TLS

Recommended to enable and specify cert\_hash or cert\_path.

```toml
tls={server_name="xxx",insecure=false,cert_hash="",cert_path="xxxx",fingerprint="firefox"}
# server_name: if empty, inherits from server
# cert_hash: verify self-signed certificate
# cert_path: use local cert for validation
# fingerprint: default is chrome. Options: go | chrome | firefox | edge | safari | android | ios | random | randomized
```

### Server

```toml
server=""  # host:port
```
