/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jwks_demo/internal/verify"
	"github.com/spf13/cobra"
)

const (
	defaultPort  = 3000
	shutdownWait = 15 * time.Second
)

// dummyServiceCmd represents the dummyService command
var dummyServiceCmd = &cobra.Command{
	Use:   "dummyService",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

var verifier *verify.Verifier

func run() error {
	verifier = verify.NewVerfier()

	slog.Info("start dummy service", "port", defaultPort)

	// サーバーを起動
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/service", proxyHandler)

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("0.0.0.0:%d", defaultPort),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				slog.Info("service closed")
				err = nil // エラー扱いにしない
			} else {
				slog.Error("failed to start service", "error", err)
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), shutdownWait)
	defer cancel()
	srv.Shutdown(ctx)

	slog.Info("server shutting down")

	return nil

}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ready\n"))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// 認証に必要な情報をヘッダから取得

	//// Authorization ヘッダーを取得
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	//// ヘッダーが "Bearer " で始まるか確認
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		http.Error(w, "Authorization header format must be Bearer {token}", http.StatusUnauthorized)
		return
	}

	//// "Bearer " の部分を除去してトークンを取得
	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		http.Error(w, "Token is missing", http.StatusUnauthorized)
		return
	}

	// 認証を確認
	if ok, err := verifier.Verify(token); err != nil {
		slog.Error("failed to verify token", "error", err)
		http.Error(w, "Unauthorized", http.StatusInternalServerError)
		return
	} else if !ok {
		slog.Warn("token is not valid")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// レスポンス
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK\n"))
}

func init() {
	rootCmd.AddCommand(dummyServiceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dummyServiceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dummyServiceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
