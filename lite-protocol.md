### Lite 代理协议

Lite 是一种极简的基于可靠流的代理协议，不依赖于特定可靠流的实现方式。

**Lite 协议分享链接倡导**

> id-text 可以为 hex 编码的 16 字节字符串或者 UUID 文本

```
lite://<id-text>@<server>:<server_port>
    ?transport=<tcp|websocket>&
    host=<host>&
    path=<path>&
    only_http_upgrade=<true|false>&
    early_data_header_name=<early_data_header_name>&
    server_name=<server_name>&
    fignerprint=<fignerprint>&
    cert_hash=<cert_hash>&
    insecure=<true|false>
    #<descriptive-text>
```

---

### **请求格式 (Request)**

请求报文的结构如下：

| 字段     | 长度 (字节) | 描述                                     |
| -------- | ----------- | ---------------------------------------- |
| ID       | 16          | 认证信息，任何 16 字节数据。             |
| CMD      | 1           | 命令类型，定义代理的行为。               |
| ATYP     | 1           | 地址类型，指示目标地址的格式。           |
| DST.ADDR | 可变        | 目标地址，格式由 ATYP 决定。             |
| DST.PORT | 2           | 目标端口号，以网络字节序（大端序）表示。 |

#### **CMD 字段取值**

-   `1`：TCP 请求。
-   `2`：UDP 请求。

> **注意**：如果 CMD 为 UDP 请求，则请求报文中不包含 `ATYP`、`DST.ADDR` 和 `DST.PORT` 字段。

#### **ATYP 字段取值**

-   `1`：IPv4 地址（4 字节）。
-   `2`：域名（FQDN，1 字节长度 + 域名内容，域名长度不超过 255 字节）。
-   `3`：IPv6 地址（16 字节）。

#### **DST.ADDR 字段格式**

-   IPv4：4 字节。
-   IPv6：16 字节。
-   域名：1 字节长度 + 域名内容（长度不超过 255 字节）。

---

### **响应格式 (Response)**

-   代理服务器不返回任何响应报文。
-   如果认证失败，代理服务器会直接中断连接。

---

### **数据传输规则**

#### **TCP 代理**

-   数据原样传输，不进行任何额外封装。

#### **UDP 代理**

-   双方传输的 UDP 报文格式如下：

| 字段     | 长度 (字节) | 描述                                       |
| -------- | ----------- | ------------------------------------------ |
| ATYP     | 1           | 地址类型，指示目标地址的格式。             |
| DST.ADDR | 可变        | 目标地址，格式由 ATYP 决定。               |
| DST.PORT | 2           | 目标端口号，以网络字节序（大端序）表示。   |
| Length   | 2           | 负载数据长度，以网络字节序（大端序）表示。 |
| Payload  | 可变        | 实际传输的数据。                           |
