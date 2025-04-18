package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jwks_demo/internal/model"
)

const defaultPublicKeyDir = "files/public"
const defaultTestKeyId = "key-001"
const ShutdownWait = 15 * time.Second

type FileOperator interface {
	LoadTxtFile(filePath string) ([]byte, error)
	GetFileNames(dirPath string) ([]string, error)
}

type Server struct {
	FileOperator FileOperator
	PublicKeyDir string
	Port         int

	Keys []model.Key
}

func NewServer(f FileOperator, port int) *Server {
	return &Server{
		FileOperator: f,
		PublicKeyDir: defaultPublicKeyDir,
		Port:         port,
	}
}

func NewEd25519key(kid, x string) model.Key {
	return model.Key{
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
		pubKeyLine, err := s.FileOperator.LoadTxtFile(s.PublicKeyDir + "/" + p)
		if err != nil {
			slog.Error("failed to load public key file", "error", err)
			return err
		}

		keyPub, err := parsePemPublicKeyLine(string(pubKeyLine))
		if err != nil {
			return err
		}

		// base64 に変換して登録
		// kid = 拡張子なしファイル名
		kid := getBaseFilename(p)
		if kid == "" {
			slog.Error("failed to get base filename. Maybe file_name is hidden filename.", "file_name", p)
			return fmt.Errorf("failed to get base filename")
		}

		key := NewEd25519key(kid, base64.RawURLEncoding.EncodeToString(keyPub))
		s.Keys = append(s.Keys, key)
		slog.Info("loaded public key", "file_name", p, "key_length", len(key.X))
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
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/.well-known/jwks.json", s.jwksHandler).Methods("GET")

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

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ready\n"))
}

func (s *Server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := model.Response{
		Keys: []model.Key{},
	}
	response.Keys = append(response.Keys, s.Keys...)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode response", "error", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

}

func getBaseFilename(path string) string {
	// Get the filename with extension (e.g., "file.txt")
	base := filepath.Base(path)
	// Get the extension (e.g., ".txt")
	ext := filepath.Ext(base)
	// Remove the extension from the base filename
	return strings.TrimSuffix(base, ext)
}
