package websocket

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"strings"
)

// Early data header limit
const MaxEarlyDataSize = 1024 * 2

func IsWebsocketUpgradeRequest(r *http.Request) bool {
	if len(r.Header["Sec-Websocket-Key"]) == 0 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(r.Header["Sec-Websocket-Key"][0])
	if err != nil || len(decoded) != 16 {
		return false
	}
	return r.Method == http.MethodGet &&
		len(r.Header["Sec-Websocket-Version"]) > 0 && r.Header["Sec-Websocket-Version"][0] == "13" &&
		len(r.Header["Upgrade"]) > 0 && strings.Contains(strings.ToLower(r.Header["Upgrade"][0]), "websocket") &&
		len(r.Header["Connection"]) > 0 && strings.Contains(strings.ToLower(r.Header["Connection"][0]), "upgrade")
}

func GenerateWebSocketKey() string {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func ComputeWebSocketAccept(key string) string {
	const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	combined := key + magicGUID

	hash := sha1.New()
	hash.Write([]byte(combined))
	hashedData := hash.Sum(nil)

	acceptKey := base64.StdEncoding.EncodeToString(hashedData)
	return acceptKey
}
