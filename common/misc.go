package common

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"reflect"
	"sync"
)

const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

func TryToClose(v any) error {
	if closer, ok := v.(io.Closer); ok {
		value := reflect.ValueOf(closer)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface,
			reflect.Map, reflect.Ptr, reflect.Slice, reflect.UnsafePointer:
			if !value.IsNil() {
				return closer.Close()
			}
		default:
			return closer.Close()
		}
	}
	return nil
}

func ConvertStruct(from, to any) error {
	data, err := json.Marshal(from)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, to)
	if err != nil {
		return err
	}
	return nil
}

// Ref: https://github.com/juicity/juicity/blob/4c5e8bd948ba2f72a0dd38681cf13ae532f6c9f5/common/utils.go#L5
func CalculateCertChainHash(rawCerts [][]byte) (chainHash []byte) {
	for _, cert := range rawCerts {
		certHash := sha256.Sum256(cert)
		if chainHash == nil {
			chainHash = certHash[:]
		} else {
			newHash := sha256.Sum256(append(chainHash, certHash[:]...))
			chainHash = newHash[:]
		}
	}
	return chainHash
}

func ConnectStream(a io.ReadWriter, b io.ReadWriter, bufferSize int) error {
	var once sync.Once
	var fatalErr error
	ch := make(chan struct{}, 1)
	go func() {
		buf := GetBuffer(bufferSize)
		defer PutBuffer(buf)
		_, err := io.CopyBuffer(a, b, buf)
		once.Do(func() {
			fatalErr = err
			ch <- struct{}{}
		})
	}()
	go func() {
		buf := GetBuffer(bufferSize)
		defer PutBuffer(buf)
		_, err := io.CopyBuffer(b, a, buf)
		once.Do(func() {
			fatalErr = err
			ch <- struct{}{}
		})
	}()
	<-ch
	return fatalErr
}
