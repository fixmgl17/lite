package cmd

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"lite/common"
	"os"

	"github.com/spf13/cobra"
)

var certHashCmd = &cobra.Command{
	Use:   "certhash",
	Short: "Calculate certificate hash",
	Run: func(cmd *cobra.Command, args []string) {
		for _, f := range args {
			b, err := calculateCertFileHash(f)
			if err != nil {
				fmt.Printf("%s    %s\n", err.Error(), f)
			} else {
				fmt.Printf("%s    %s\n", hex.EncodeToString(b), f)
			}
		}
	},
}

func calculateCertFileHash(f string) ([]byte, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var rawCerts [][]byte
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		rawCerts = append(rawCerts, block.Bytes)
		b = rest
	}
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("invalid certificate")
	}
	return common.CalculateCertChainHash(rawCerts), nil
}

func init() {
	rootCmd.AddCommand(certHashCmd)
}
