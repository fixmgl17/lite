package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var gencertCmd = &cobra.Command{
	Use:   "gencert",
	Short: "Generate tls certificate",
	Run: func(cmd *cobra.Command, args []string) {
		days, _ := cmd.Flags().GetInt("days")
		keyPath, _ := cmd.Flags().GetString("keyfile")
		certPath, _ := cmd.Flags().GetString("certfile")
		san, _ := cmd.Flags().GetStringSlice("san")
		var (
			ips   []net.IP
			names []string
		)
		for _, s := range san {
			ip := net.ParseIP(s)
			if ip != nil {
				ips = append(ips, net.ParseIP(s))
			} else {
				names = append(names, s)
			}
		}
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			logger.Fatalln(err)
		}
		now := time.Now()
		duration := time.Duration(days) * 24 * time.Hour
		end := now.Add(duration)
		logger.Infof("Subject Alternative Names: %s", strings.Join(san, ","))
		logger.Infof("Duration: %v", duration)
		logger.Infof("Expiration: %v", end)
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Private"},
			},
			DNSNames:              names,
			IPAddresses:           ips,
			NotBefore:             now,
			NotAfter:              end,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			logger.Fatalln(err)
		}

		keyFile, err := os.Create(keyPath)
		if err != nil {
			logger.Fatalln(err)
		}
		defer keyFile.Close()
		b, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			logger.Fatalln(err)
		}
		keyPEM := pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		}
		if err := pem.Encode(keyFile, &keyPEM); err != nil {
			logger.Fatalln(err)
		}
		logger.Infoln("Successfully wrote private key to", keyFile.Name())
		certFile, err := os.Create(certPath)
		if err != nil {
			logger.Fatalln(err)
		}
		defer certFile.Close()
		certPEM := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}
		if err := pem.Encode(certFile, &certPEM); err != nil {
			logger.Fatalln(err)
		}
		logger.Infoln("Successfully wrote certificate to", certFile.Name())
		logger.Infoln("Key and certificate generated successfully")
	},
}

func init() {
	gencertCmd.Flags().StringSlice("san", nil, "additional subject alternative names")
	gencertCmd.Flags().Int("days", 365*10, "the validity of the certificate in days")
	gencertCmd.Flags().String("keyfile", "key.pem", "output private key file")
	gencertCmd.Flags().String("certfile", "cert.pem", "output certificate file")
	rootCmd.AddCommand(gencertCmd)
}
