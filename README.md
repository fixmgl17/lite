# Lite

[English](./README.en.md)

一个简单且强大的代理协议和工具。 

> 配置可以参考`examples`目录下内容；具体协议和分享链接倡导参考[lite-protocol.md](./lite-protocol.md)文档；下载程序后在命令行中添加`--help`参数执行获取更多用法

## Features

-   [x] Lite & UTLS & UDP Full Cone
-   [x] 自定义 DNS 和双栈支持
-   [x] 强大的路由
-   [x] HTTP 回落
-   [x] 自动系统代理(适用于客户端)
-   [ ] 出站自动选择策略

## Guide

-   [Config Structure](#config-structure)

-   [Auto System Proxy](#auto-system-proxy)

-   [Log](#log)

-   [API](#api)

-   [DNS](#dns)

-   [Routing](#routing)

-   [Inbounds](#inbounds)

    -   [Tag](#tag)
    -   [Protocol](#protocol)
    -   [Transport](#transport)
    -   [TLS](#tls)
    -   [Listen](#listen)

-   [Outbounds](#outbounds)

    -   [Tag](#tag-1)
    -   [Dial Mode](#dial-mode)
    -   [DNS Resolve](#dns-resolve)
    -   [Protocol](#protocol-1)
    -   [Transport](#transport-1)
    -   [TLS](#tls-1)
    -   [Server](#server)

## Config Structure

支持 toml 和 json，文档以 toml 为例

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

# Auto System Proxy

```toml
auto_system_proxy=true
# 程序启动时，自动将第一个mixed的inbound设置为系统代理入口，并在关闭前自动清除系统代理
```

## Log

```toml
[log]
level = ""  # 默认 info，可选 debug | info | warn | error | fatal
output = "" # 默认标准输出，可填入文件路径，如果值为 discard，则不输出日志
max_size = "" # 如果 output 指定了日志文件，那么可以设置文件最大值，超出时清空重置，如 1KB 1MB 1GB
```

## API

API 接口参考[api.md](./api.md)

```toml
[api]
listen = ""  # host:port
token = ""
tls = { cert_path = "xxx", key_path = "xxx" }
```

## DNS

流量不经过路由，直接使用本地网络出站，推荐配置 DoH

```toml
ttl = "" # DNS缓存，默认5分钟，格式如 3s, 3m, 3h，时长若设置为0，则不使用缓存
server_url=""
# 默认空值，使用系统DNS
# 支持udp和https协议，形如 udp://1.1.1.1 或 https://1.1.1.1/dns-query
```

## Geo

```toml
[geo]
update_interval=""
ip_url=""
site_url=""
# 地理IP网络信息数据库配置，自动根据更新间隔下载在程序所在目录上，并重建路由
# 更新间隔默认值为 72h (3天)
# Geo 文件下载经过路由，且使用值为 geo 的 inbound tag 来进入路由匹配
```

## Routing

简单且有效的路由规则

```toml
[routing]
rules = [
    { inbound_tags = [ "inbound1" ], outbound_tags = [ "direct" ], time_range = "16:00-23:00", require_ipv6 = false, network = "tcp", port_range = "22,80-443", include_hosts = ["private"], exclude_hosts = ["google.com"]  },
]
```

`inbound_tags` 若未设置则表示任意 tag 都可以命中，如果设置，则单项完全匹配为命中，`outbound_tags` 不能为空。

`time_range` 表示该规则的每日生效期间，`time_range` 的格式可以是 `时-时`，`时:分-时:分`，`时:分:秒-时:分:秒`。左侧缺失默认取 0 点，右侧缺失默认取 23:59:59。

`require_ipv6` 表示当前网络环境必须具有 IPv6。

`network` 表示匹配的网络，可填 tcp 或 udp，如果为空，则匹配所有。

`port_range` 表示匹配的端口范围，格式为 `port1,port2,port3-port4`，如果为范围，左侧缺失默认取 0，右侧缺失默认取 65535。

`include_hosts` 表示包含的地址，`exclude_hosts` 表示排除的地址，可以填写 CIDR、IP、域名的字符串，域名匹配兼容子域名，例如配置有 `example.com`，那么 `example.com` 和 `***.example.com` 都匹配，如配置为 `.example.com`，那么仅有 `***.example.com` 匹配。此外支持预定义地址列表，程序本身内置`private`的地址列表，可直接使用，用过绕过局域网地址；另外还有 `geosite:xxx` 和 `geoip:xxx` 的特殊格式，这时则必须保证程序文件目录下存在`geosite.dat` 和 `geoip.dat` 文件，程序会自动读取，如果不存在则会报错，更多格式信息参考 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)。

如果 inbound 没有匹配到任何规则，则取第一个 outbound。此外，如果配置中不存在 tag 名为 `direct` 和 `block` 的 outbound，则自动创建，这两个 tag 具有特殊意义，即直连或阻断。

## Inbounds

数组形式，允许多个 inbound，以下为单个 inbound 的可配置项。

```toml
[[inbounds]]
tag=""
protocol=""
protocol_settings={}

# transport 配置仅用于 lite 协议
transport=""
transport_settings={}

tls={}
listen=""
```

### Tag

字符串，默认值为 `inbound-{index+1}`，比如第二个 inbound 的默认 `tag` 值为 `inbound-2`。注意 `tag`值不能为保留值`geo`，该值专属为 geo 文件自动更新模块。

```toml
tag = "xxx"
```

### Protocol

`lite` | `mixed`

-   `lite`

    支持代理 tcp/udp，udp 支持 Full Cone，本程序的核心协议，足够轻量

    ```toml
    protocol="lite"
    protocol_settings={ users=[{id="",expire_time="",read_rate_limit="",write_rate_limit=""}] }
    # id为uuid text或普通字符串，如若没有填写任何user，则创建一个id为空字符串的user
    # *_radte_limit 字段为每秒读写数据的速率限制，不设置则不限制，可填带单位的值，如 1.2MB 1KB 1B
    # 以取值1MB为例 表示控制在每秒读写最多1MB数据，简单来说就是限制网速不超过1MB/s
    # expire_time为空则不过期，格式支持 time.RFC3339, time.DateOnly, time.DateOnly, "2006/01/02 15:04:05"
    ```

-   `mixed`

    `http`和`socks5`的多路复用，请仅作为内网客户端代理的流量入口，用于公网代理没有安全性可言

    ```toml
    protocol="mixed"
    protocol_settings={  username="xxx",password="xxx" }
    # 如若没有填写任何用户名和密码，则忽略验证
    # 其余配置参考lite
    ```

### Transport

`tcp` | `websocket`

默认 tcp，可以省略，`transport_settings`均可省略，该配置仅用于`lite`协议

-   `tcp`

    基础的传输方式，需要 tls 来加密流量

    ```toml
    transport="tcp"
    transport_settings={} # 暂无配置
    ```

-   `websocket`

    仅支持 http/1.1，通常用在 CDN 和伪装上，需要 tls 来加密流量，此传输层支持 Fallback

    服务端自动检测请求头`Sec-Websocket-Protocol`是否是"wamp", "soap", "mqtt"中的值，是的话，则仅执行 httpupgrade 操作，不封装 websocket 帧

    ```toml
    transport="websocket"
    transport_settings={path="/xxx",host="/xxx",early_data_header_name="xxx",fallback="xxx"}
    # path 为空则不验证，host 为空则不验证，
    # early_data_header_name 接受发送请求的前置数据的 HTTP 头的名字，客户端需要在 outbound 中配置一致才奏效，若不配置，服务端也能兼容
    # 该 header 填充值通过 base64.RawURLEncoding 编码，且解码后的数据不超过2048个字节
    # fallback 仅当path和host不匹配时生效，反代其它 URL （支持websocket）或者静态文件服务，会打印错误日志，格式如 https://example.com , /xxx/xxx
    ```

### TLS

不填写该配置项则不启用 tls 加密层

```toml
tls={cert_path = "xxx", key_path = "xxx"}
# 填写公钥私钥的路径
```

### Listen

```toml
listen="" # host:port
```

## Outbounds

数组形式，允许多个 outbound，以下为单个 outbound 的可配置项

```toml
[[outbounds]]
tag=""
dial_mode=""
dns_resolve=""
protocol=""
protocol_settings={}

# transport 配置仅用于 lite 协议
transport=""
transport_settings={}

tls={}
server=""
```

### Tag

字符串，默认值为`outbound-{index+1}`，index 为该 outbound 在整体 outbounds 的索引，比如第二个 outbound 的默认 `tag` 值为`outbound-2`

```toml
tag="xxx"
```

### Dial Mode

`auto` | `46` | `64` | `4` | `6`

默认`auto`，当`outbound`的`protocol`为`direct`时，用来决定对出站目标域名的拨号模式；若为其它代理协议，当代理服务器为域名时，决定其拨号模式。推荐根据设备网络栈来配置`auto`外的选项，以此提高性能

```toml
dial_mode = "46"
# 仅在目标为域名时起效
# auto：默认值，有利于双栈模式，同时解析 IPv4 和 IPv6 地址并连接目标，选择第一个成功的。
# 64：同时解析 IPv4 和 IPv6 地址，首先连接 IPv6 地址，失败则回退至 IPv4。
# 46：同时解析 IPv4 和 IPv6 地址，首先连接 IPv4 地址，失败则回退至 IPv4。
# 6：仅解析为 IPv6 地址进行连接。
# 4：仅解析为 IPv4 地址进行连接。
```

### DNS Resolve

`46` | `64` | `4` | `6`

默认空值，不起作用。在域名流量出栈前本地尝试根据此配置进行 DNS 解析，如果解析失败，保持原域名出站，配置该项后，UDP 域名请求会自动保存并使用 NAT 映射表

```toml
dns_resolve = "46"
# 仅在目标为域名时起效
# 64：同时解析 IPv4 和 IPv6 地址，优先使用 IPv4 地址。
# 46：同时解析 IPv4 和 IPv6 地址，优先使用 IPv4 地址。
# 6：仅解析为 IPv6 地址。
# 4：仅解析为 IPv4 地址。。
```

### Protocol

`lite` | `http` | `socks5` | `direct` | `block`

默认`direct`

-   `lite`

    支持代理 tcp/udp，udp 支持 Full Cone，本程序的核心协议，足够轻量

    ```toml
    protocol="lite"
    protocol_settings={ user={id="",expire_time="",read_rate_limit="",write_rate_limit=""} }
    # id要求必须为uuid text或32位hex字符串
    # *_radte_limit 字段为每秒读写数据的速率限制，不设置则不限制，可填带单位的值，如 1.2MB 1KB 1B
    # 以取值1MB为例 表示控制在每秒读写最多1MB数据，简单来说就是限制网速不超过1MB/s
    # expire_time为空则不过期，格式支持 time.RFC3339, time.DateOnly, time.DateOnly, "2006/01/02 15:04:05"
    ```

-   `http`

    仅支持代理 tcp

    ```toml
    protocol="http"
    protocol_settings={ user={ username="xxx", password="xxx"} }
    ```

-   `socks5`

    支持代理 tcp/udp，udp 支持 Full Cone

    ```toml
    protocol="socks5"
    protocol_settings={ user={ username="xxx", password="xxx"} }
    ```

-   `direct`

    从设备的网络栈直接请求目标，此时`outbound`的其它配置项均可不用填写

-   `block`

    阻断连接，此时`outbound`的其它配置项均可不用填写

### Transport

`tcp` | `websocket`

默认 tcp，可以省略，`transport_settings`均可省略

-   `tcp`

    也是最底层的传输方式，需要 tls 来加密流量

    ```toml
    transport="tcp"
    transport_settings={} # 暂无配置
    ```

-   `websocket`

    目前仅支持 http/1.1，通常用在 CDN 和伪装上，需要 tls 来加密流量，headers 会自动配置 User-Agent 和 Origin 等的默认值

    ```toml
    transport="websocket"
    transport_settings={only_http_upgrade=false, early_data_header_name="xxx", path="/xxx", host="/xxx", headers={ "user-agent"="xxx" } }
    # only_http_upgrade 启用后，upgrade后，不封装帧，服务端自适应，无需额外配置
    # host若为空，则按优先级继承tls.server_name和server中的host
    # early_data_header_name 配置发送前置数据的 HTTP 请求头名称，客户端需要与服务端中相关配置一致才能起效，若不配置，服务端也会兼容客户端请求
    # headers 会自动配置 User-Agent 和 Origin 等的默认值
    ```

### TLS

不填写该配置项则不应用 tls 加密层，强烈建议配置 TLS 和其中的 cert_hash 或 cert_path 值

```toml
tls={server_name="xxx",insecure=false,cert_hash="",cert_path="xxxx",fingerprint="firefox"}
# server_name若为空，则继承server中的host
# cert_hash 为校验证书的哈希值，可通过程序命令生成。一般用于自签名证书，此时insecure也应置为true
# cert_path 为证书路径
# fingerprint默认chrome，所有可选值如下所示
# go | chrome | firefox | edge | sasafari | android | ios | random | randomized
```

### Server

```toml
server=""  # host:port
```
