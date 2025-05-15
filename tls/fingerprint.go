package tls

import (
	"crypto/rand"
	"math/big"

	utls "github.com/refraction-networking/utls"
)

var fpSet = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
	"ios":     &utls.HelloIOS_Auto,
	"android": &utls.HelloAndroid_11_OkHttp,
	"edge":    &utls.HelloEdge_Auto,
	"go":      nil,
}

// Fingerprint must be one of "random", "randomized", "go", "chrome", "firefox", "safari", "ios", "android", "edge"
//
// if fingerprint is "go", return nil
func PickClientHelloID(fingerprint string) (*utls.ClientHelloID, bool) {
	if fingerprint == "random" {
		bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(fpSet))))
		stopAt := int(bigInt.Int64())
		i := 0
		for _, v := range fpSet {
			if i == stopAt {
				return v, true
			}
			i++
		}
	}
	if fingerprint == "randomized" {
		randomized := utls.HelloRandomized
		randomized.Seed, _ = utls.NewPRNGSeed()
		randomized.Weights = &utls.DefaultWeights
		return &randomized, true
	}
	return fpSet[fingerprint], fpSet[fingerprint] != nil
}
