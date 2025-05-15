# API

If the `token` value is not configured, the server does not perform authentication. The `token` value should be included in the URL parameters in the format `token=xxx`.

Except for the `/` route, all other routes are used to query configurations related to the **lite** protocol inbounds.

For the following APIs, a successful request that does not specify a Response content will return a 200 status code with plain text. If the request fails, the response will contain a non-200 status code with a plain text message.

---

* **Get overall details**

  * **Path:** `/`
  * **Method:** `GET`
  * **Response:**

  ```json
  {
      "start_time": "2011-01-01T11:02:46.2945134+08:00",
      "time": "2011-01-01T11:02:47.717249+08:00",
      "duration": "1.4227356s",
      "inbounds": [
          {
              "tag": "inbound-1",
              "protocol": "mixed",
              "username": "x", // Omitted if empty
              "password": "y"  // Omitted if empty
          },
          {
              "tag": "inbound-2",
              "protocol": "lite",
              "transport": "tls+websocket",
              "users": [
                  {
                      "id": "00000000000000000000000000000000", // 16-byte hex encoded
                      "last_time": "0001-01-01T00:00:00Z", // Zero value indicates never accessed
                      "read_bytes": 0,
                      "write_bytes": 0,
                      "h_read": "0B",
                      "h_write": "0B",
                      "read_bytes_rate_limit": 0,
                      "write_bytes_rate_limit": 0,
                      "h_read_rate_limit": "0B/s",
                      "h_write_rate_limit": "0B/s",
                      "expire_time": "0001-01-01T00:00:00Z" // Zero value means never expires
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
                  "id": "00000000000000000000000000000000",
                  "last_time": "0001-01-01T00:00:00Z",
                  "read_bytes": 0,
                  "write_bytes": 0,
                  "h_read": "0B",
                  "h_write": "0B",
                  "read_bytes_rate_limit": 0,
                  "write_bytes_rate_limit": 0,
                  "h_read_rate_limit": "0B/s",
                  "h_write_rate_limit": "0B/s",
                  "expire_time": "0001-01-01T00:00:00Z"
              }
          },
          {
              "tag": "block",
              "protocol": "block"
          }
      ],
      "rules": [  // Routing rules consistent with the configuration file
          {
              "outbound_tags": [
                  "direct"
              ]
          }
      ]
  }
  ```

---

* **Get all tags of lite protocol inbounds**

  * **Path:** `/tags`
  * **Method:** `GET`
  * **Response:**

  ```json
  [
      "inbound-2"
  ]
  ```

---

* **Get all lite users under a specific tag**

  * **Path:** `/users?tag=inbound-2`
  * **Method:** `GET`
  * **Response:**

  ```json
  [
      {
          "id": "a82a4d6f303740b2810154d90cb71858",
          "last_time": "0001-01-01T00:00:00Z",
          "read_bytes": 0,
          "write_bytes": 0,
          "h_read": "0B",
          "h_write": "0B",
          "read_bytes_rate_limit": 0,
          "write_bytes_rate_limit": 0,
          "h_read_rate_limit": "0B/s",
          "h_write_rate_limit": "0B/s",
          "expire_time": "0001-01-01T00:00:00Z"
      }
  ]
  ```

---

* **Add a lite user to a specific tag**

  * **Path:** `/add-user?tag=inbound-2`
  * **Method:** `PUT`
  * **Request:**

  ```json
  {
      "id": "00000000000000000000000000000000", // 16-byte hex encoded or UUID string
      "read_bytes_rate_limit": 0,  // Read limit; 0 means unlimited
      "write_bytes_rate_limit": 0, // Write limit; 0 means unlimited
      "expire_time": "0001-01-01T00:00:00Z" // Zero value means never expires
  }
  ```

---

* **Remove a lite user by tag and ID**

  * **Path:** `/remove-user?tag=inbound-2&id=00000000000000000000000000000000`
  * **Method:** `DELETE`
