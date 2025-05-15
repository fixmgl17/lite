package tls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"lite/common"
	"os"
	"strings"

	utls "github.com/refraction-networking/utls"
)

type Config struct {
	ServerName      string `json:"server_name" toml:"server_name"`
	Insecure        bool   `json:"insecure" toml:"insecure"`
	Fingerprint     string `json:"fingerprint" toml:"fingerprint"`
	CertificateHash string `json:"cert_hash" toml:"cert_hash"`

	CertificatePath string `json:"cert_path" toml:"cert_path"`

	KeyPath string `json:"key_path" toml:"key_path"`
}

func (config *Config) GetCertificates() ([]*x509.Certificate, error) {
	var (
		certPEMBlock []byte
		err          error
	)
	if config.CertificatePath != "" {
		certPEMBlock, err = os.ReadFile(config.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("read certificate path: %v", err)
		}
	} else {
		return nil, nil
	}
	var certs []*x509.Certificate
	for i := 0; ; i++ {
		block, rest := pem.Decode(certPEMBlock)
		if block == nil {
			break
		} else if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %dth cert pem block: %v", i+1, err)
		}
		certs = append(certs, cert)
		certPEMBlock = rest
	}
	return certs, nil
}

func (config *Config) ToServerTLSConfig() (*tls.Config, error) {
	conf := &tls.Config{}
	if config.CertificatePath == "" || config.KeyPath == "" {
		return nil, fmt.Errorf("cert_path and key_path must be set for server tls config")
	}
	cert, err := tls.LoadX509KeyPair(config.CertificatePath, config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair for server tls config: %v", err)
	}
	conf.Certificates = append(conf.Certificates, cert)
	return conf, nil
}

func (config *Config) ToClientTLSConfig() (*utls.Config, *utls.ClientHelloID, error) {
	conf := &utls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.Insecure,
	}
	var (
		certPEM []byte
		err     error
	)
	if config.CertificatePath != "" {
		certPEM, err = os.ReadFile(config.CertificatePath)
		if err != nil {
			return nil, nil, fmt.Errorf("read certificate path for client tls config: %v", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certPEM) {
			return nil, nil, fmt.Errorf("failed to append certificate for client tls config")
		}
		conf.RootCAs = certPool
	}
	if len(config.CertificateHash) > 0 {
		hash, err := decodeSHA256HashString(config.CertificateHash)
		if err != nil {
			return nil, nil, fmt.Errorf("decode certificate hash for tls client config: %w", err)
		}
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if !bytes.Equal(common.CalculateCertChainHash(rawCerts), hash) {
				return fmt.Errorf("cert chain hash does not match")
			}
			return nil
		}
	}
	clientHelloID, hit := PickClientHelloID(config.Fingerprint)
	if !hit {
		return nil, nil, fmt.Errorf("unknown client hello id: %s", config.Fingerprint)
	}
	return conf, clientHelloID, nil
}

func (config *Config) ToLayer() (*Layer, error) {
	tlsConfig, clientHelloID, err := config.ToClientTLSConfig()
	if err != nil {
		return nil, err
	}
	return NewLayer(tlsConfig, clientHelloID), nil
}

func decodeSHA256HashString(s string) ([]byte, error) {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 64 {
		return nil, fmt.Errorf("invalid sha256 hash string length %d", len(s))
	}
	return hex.DecodeString(s)
}
