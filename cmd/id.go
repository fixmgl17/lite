package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"lite/common/uuid"

	"github.com/spf13/cobra"
)

var idCmd = &cobra.Command{
	Use:   "id",
	Short: "Generate id",
	Run: func(cmd *cobra.Command, args []string) {
		requireUUID, _ := cmd.Flags().GetBool("uuid")
		if requireUUID {
			id := uuid.New()
			fmt.Println(id.String())
		} else {
			b := make([]byte, 16)
			_, err := io.ReadFull(rand.Reader, b)
			if err != nil {
				panic(err)
			}
			fmt.Println(hex.EncodeToString(b))
		}

	},
}

func init() {
	idCmd.Flags().BoolP("uuid", "u", false, "Generate with uuid")
	rootCmd.AddCommand(idCmd)
}
