package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

const defaultPublicKeyDir = "files/public"
const ShutdownWait = 15 * time.Second

type FileOperator interface {
	LoadTxtFile(filePath string) ([]byte, error)
	GetFileNames(dirPath string) ([]string, error)
}

type Server struct {
	FileOperator FileOperator
	PublicKeyDir string
	Port         int

	Keys []Key
}

func NewServer(f FileOperator, port int) *Server {
	return &Server{
		FileOperator: f,
		PublicKeyDir: defaultPublicKeyDir,
		Port:         port,
	}
}

func NewEd25519key(kid, x string) Key {
	return Key{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: kid,
		Use: "sig",
		Alg: "EdDSA",
		X:   x,
	}
}

func (s *Server) RegistPublicKey() error {
	// 公開鍵情報を取得
	pubPath, err := s.FileOperator.GetFileNames(s.PublicKeyDir)
	if err != nil {
		slog.Error("failed to get public key file names", "error", err)
		return err
	}

	for _, p := range pubPath {
		pubKey, err := s.FileOperator.LoadTxtFile(s.PublicKeyDir + "/" + p)
		if err != nil {
			slog.Error("failed to load public key file", "error", err)
			return err
		}
		key := NewEd25519key("key-001", string(pubKey))
		s.Keys = append(s.Keys, key)
		slog.Info("loaded public key", "file_name", p, "key_length", len(pubKey))
	}

	return nil
}

func (s *Server) Start() error {
	// 公開鍵情報を取得
	if err := s.RegistPublicKey(); err != nil {
		slog.Error("failed to register public key", "error", err)
		return err
	}

	slog.Info("start JWKS server", "port", s.Port)

	// サーバーを起動
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler)

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("0.0.0.0:%d", s.Port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				slog.Info("server closed")
				err = nil // エラー扱いにしない
			} else {
				slog.Error("failed to start server", "error", err)
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	ctx, cancel := context.WithTimeout(context.Background(), ShutdownWait)
	defer cancel()
	srv.Shutdown(ctx)

	slog.Info("server shutting down")

	return nil
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ready\n"))
}
