package main

import (
	"log/slog"
	"os"

	"github.com/jwks_demo/cmd"
)

func main() {
	cmd.Execute()
}

func init() {
	// init 関数で slog の初期化を行う。形式は JSON 形式で出力する。
	opts := &slog.HandlerOptions{
		AddSource: true,
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, opts)))
}
