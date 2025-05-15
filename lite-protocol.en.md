### **Lite Proxy Protocol**

Lite is a minimalist proxy protocol based on reliable streams. It does not depend on any specific implementation of reliable streams.

---

### **Lite Protocol Share Link Format**

> `id-text` can be either a 16-byte hex string or a UUID string.

```
lite://<id-text>@<server>:<server_port>
    ?transport=<tcp|websocket>&
    host=<host>&
    path=<path>&
    only_http_upgrade=<true|false>&
    early_data_header_name=<early_data_header_name>&
    server_name=<server_name>&
    fingerprint=<fingerprint>&
    cert_hash=<cert_hash>&
    insecure=<true|false>
    #<descriptive-text>
```

---

### **Request Format**

The structure of a request packet is as follows:

| Field    | Length (Bytes) | Description                                               |
| -------- | -------------- | --------------------------------------------------------- |
| ID       | 16             | Authentication data; any 16-byte value.                   |
| CMD      | 1              | Command type, defines the proxy behavior.                 |
| ATYP     | 1              | Address type, indicates the format of the target address. |
| DST.ADDR | Variable       | Destination address, format determined by ATYP.           |
| DST.PORT | 2              | Destination port in network byte order (big-endian).      |

#### **CMD Field Values**

* `1`: TCP request
* `2`: UDP request

> **Note**: If CMD is a UDP request, the request packet **does not** include `ATYP`, `DST.ADDR`, or `DST.PORT` fields.

#### **ATYP Field Values**

* `1`: IPv4 address (4 bytes)
* `2`: Domain name (FQDN; 1-byte length + domain, max 255 bytes)
* `3`: IPv6 address (16 bytes)

#### **DST.ADDR Field Format**

* IPv4: 4 bytes
* IPv6: 16 bytes
* Domain name: 1-byte length + domain name content (max 255 bytes)

---

### **Response Format**

* The proxy server **does not return any response packet**.
* If authentication fails, the proxy server will **terminate the connection immediately**.

---

### **Data Transmission Rules**

#### **TCP Proxy**

* Data is transmitted **as-is**, with **no additional encapsulation**.

#### **UDP Proxy**

* UDP packets transmitted between both ends follow this format:

| Field    | Length (Bytes) | Description                                                    |
| -------- | -------------- | -------------------------------------------------------------- |
| ATYP     | 1              | Address type, indicates the format of the destination address. |
| DST.ADDR | Variable       | Destination address, format determined by ATYP.                |
| DST.PORT | 2              | Destination port in network byte order (big-endian).           |
| Length   | 2              | Payload length, in network byte order (big-endian).            |
| Payload  | Variable       | Actual data being transmitted.                                 |


