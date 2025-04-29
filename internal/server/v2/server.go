package v2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/jwks_demo/internal/issue"
	"github.com/jwks_demo/internal/model"
)

const (
	shutdownWait = 15 * time.Second
)

type privateKey struct {
	Kid         string
	PrivKeyLine string // --BEGIN PRIVATE KEY-- の文字列そのまま
}

type Server struct {
	Port int
	Keys []model.Key

	privateKeys []privateKey
}

func NewServer(port int) *Server {
	return &Server{
		Port: port,
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

func (s *Server) RegistNewPrivateKey(kid string) error {
	// TODO: Kid = "" の validation を行う

	slog.Info("regist new private key", "kid", kid)
	privKeyLine, pubKeyLine, err := issue.GeneratePrivateKey()
	if err != nil {
		slog.Error("failed to create key pair", "err", err)
		return err
	}

	// 秘密鍵の登録
	privateKey := privateKey{
		Kid:         kid,
		PrivKeyLine: privKeyLine,
	}
	s.privateKeys = append(s.privateKeys, privateKey)

	// 公開鍵の登録
	keyPub, err := parsePemPublicKeyLine(string(pubKeyLine))
	if err != nil {
		return err
	}

	key := NewEd25519key(kid, base64.RawURLEncoding.EncodeToString(keyPub))
	s.Keys = append(s.Keys, key)
	slog.Info("loaded public key", "key_length", len(key.X), "X", key.X)

	return nil
}

func (s *Server) Start() error {
	slog.Info("start JWKS server", "port", s.Port)

	// サーバーを起動
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/issue/secret/{kid}", s.generateTokenHandler).Methods("POST") // for issuer admin
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

	ctx, cancel := context.WithTimeout(context.Background(), shutdownWait)
	defer cancel()
	srv.Shutdown(ctx)

	slog.Info("server shutting down")

	return nil
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ready\n"))
}

func (s *Server) generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r) //パスパラメータ取得
	kid := vars["kid"]
	if kid == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("kid is empty\n"))
		return
	}

	if err := s.RegistNewPrivateKey("kid"); err != nil {
		slog.Error("failed to create key pair", "err", err)
		http.Error(w, "failed to create key pair", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	ret := struct {
		Kid string `json:"kid"`
	}{
		Kid: kid,
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ret)
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
