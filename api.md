# API

若没有配置`token`值，服务端则不鉴权，`token`值应放在 URL 参数中，形如`token=xxx`

除了`/`路由，其余路由均是对 lite 协议的 inbound 的查询配置

以下接口，请求成功，且未给出 Response 内容示例，响应则为 200 状态码的文本信息，如果请求失败，响应均为状态码非 200 的文本信息内容

-   获取整体详情

    Path: `/`

    Method: `GET`

    Response:

    ```json
    {
        "start_time": "2011-01-01T11:02:46.2945134+08:00",
        "time": "2011-01-01T11:02:47.717249+08:00",
        "duration": "1.4227356s",
        "inbounds": [
            {
                "tag": "inbound-1",
                "protocol": "mixed",
                "username": "x", // 如果值为空则该键不存在
                "password": "y" // 如果值为空则该键不存在
            },
            {
                "tag": "inbound-2",
                "protocol": "lite",
                "transport": "tls+websocket",
                "users": [
                    {
                        "id": "00000000000000000000000000000000", // hex编码的16字节
                        "last_time": "0001-01-01T00:00:00Z", // 时间零值表示还未访问过
                        "read_bytes": 0,
                        "write_bytes": 0,
                        "h_read": "0B",
                        "h_write": "0B",
                        "read_bytes_rate_limit": 0,
                        "write_bytes_rate_limit": 0,
                        "h_read_rate_limit": "0B/s",
                        "h_write_rate_limit": "0B/s",
                        "expire_time": "0001-01-01T00:00:00Z" // 时间零值表示永不过期
                    }
                ]
            }
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "direct"
            },
            {
                "tag": "proxy",
                "protocol": "socks5",
                "username": "x",
                "password": "y"
            },
            {
                "tag": "lite",
                "protocol": "lite",
                "transport": "tcp",
                "user": {
                    "id": "00000000000000000000000000000000", // hex编码的16字节
                    "last_time": "0001-01-01T00:00:00Z", // 时间零值表示还未访问过
                    "read_bytes": 0,
                    "write_bytes": 0,
                    "h_read": "0B",
                    "h_write": "0B",
                    "read_bytes_rate_limit": 0,
                    "write_bytes_rate_limit": 0,
                    "h_read_rate_limit": "0B/s",
                    "h_write_rate_limit": "0B/s",
                    "expire_time": "0001-01-01T00:00:00Z" // 时间零值表示永不过期
                }
            },
            {
                "tag": "block",
                "protocol": "block"
            }
        ],
        "rules": [  // 路由规则与配置文件的内容保持一致
            {
                "outbound_tags": [
                    "direct"
                ]
            }
        ]
    }
    ```

-   获取所有 lite 协议的 inbound 的 tag

    Path: `/tags`

    Method: `GET`

    Response:

    ```json
    [
        "inbound-2"
    ]
    ```

-   查询指定 tag 的所有 lite 用户

    Path: `/users?tag=inbound-2`

    Method: `GET`

    Response:

    ```json
    [
        {
            "id": "a82a4d6f303740b2810154d90cb71858", // hex编码的16字节
            "last_time": "0001-01-01T00:00:00Z", // 时间零值表示还未访问过
            "read_bytes": 0,
            "write_bytes": 0,
            "h_read": "0B",
            "h_write": "0B",
            "read_bytes_rate_limit": 0,
            "write_bytes_rate_limit": 0,
            "h_read_rate_limit": "0B/s",
            "h_write_rate_limit": "0B/s",
            "expire_time": "0001-01-01T00:00:00Z"  // 时间零值表示永不过期
        }
    ]
    ```

-   指定 tag 添加 lite 用户

    Path: `/add-user?tag=inbound-2`

    Method: `PUT`

    Request:

    ```json
    {
        "id": "00000000000000000000000000000000", // hex编码的16字节或uuid text
        "read_bytes_rate_limit": 0, // 读限速，零值不限
        "write_bytes_rate_limit": 0, // 写限速，零值不限
        "expire_time": "0001-01-01T00:00:00Z" // 时间零值表示永不过期
    }
    ```

-   指定 tag 和 id 删除 lite 用户

    Path: `/remove-user?tag=inbound-2&id=00000000000000000000000000000000`

    Method: `DELETE`
