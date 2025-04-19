package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jwks_demo/internal/verify"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		// 引数1つ目の値を取得
		if len(args) < 1 {
			slog.Info("No arguments provided")
			fmt.Println("Please provide a JWT string as an argument.")
			return
		}
		jwtString := args[0]

		v := verify.NewVerfier()
		ok, err := v.Verify(jwtString)
		if err != nil {
			fmt.Println("Verification failed:", err)
			slog.Error("Failed to verify JWT", "error", err)
			os.Exit(1)
			return
		}
		if !ok {
			slog.Info("JWT verification failed", "jwtString", jwtString)
		}
		slog.Info("JWT verification succeeded", "jwtString", jwtString)
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
