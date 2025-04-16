package cmd

import (
	"log/slog"
	"os"

	"github.com/jwks_demo/internal/fileoperator"
	"github.com/jwks_demo/internal/issue"
	"github.com/spf13/cobra"
)

// 秘密鍵作成
// openssl genpkey -algorithm ed25519 -out ed25519.pem
// 秘密鍵から公開鍵を作成
// openssl pkey -in ed25519.pem -pubout -out ed25519_pub.pem

const testKeyPath = "files/private/test_ed25519.pem"
const testKID = "key-001"

// issueCmd represents the issue command
var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("issue called")
		f := fileoperator.NewFileOperator()
		issuer := issue.NewIssuer(f)
		if err := issuer.Issue(testKeyPath, testKID); err != nil {
			slog.Error("failed to issue", "error", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(issueCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// issueCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// issueCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
