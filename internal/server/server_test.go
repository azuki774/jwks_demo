package server

import (
	"errors"
	"reflect"
	"testing"

	"github.com/jwks_demo/internal/model"
)

func TesNewEd25519key(t *testing.T) {
	type args struct {
		kid string
		x   string
	}
	tests := []struct {
		name string
		args args
		want model.Key
	}{
		{
			name: "valid inputs",
			args: args{
				kid: "testKid",
				x:   "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NDUwNDA3MzEsImlzcyI6Imp3a3NfZGVtb19pc3N1ZXIiLCJzdWIiOiJqd2tzX2RlbW9fc3ViamVjdCJ9.gFiXfDvSJnmrm5isM9Ny4IPNKpEiiiQwMRqE2AyMSewrEGLg4PoYPy8WzSi9ZVm34xPGEURHHZH5Hd1Tn98pAQ",
			},
			want: model.Key{
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: "testKid",
				Use: "sig",
				Alg: "EdDSA",
				X:   "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NDUwNDA3MzEsImlzcyI6Imp3a3NfZGVtb19pc3N1ZXIiLCJzdWIiOiJqd2tzX2RlbW9fc3ViamVjdCJ9.gFiXfDvSJnmrm5isM9Ny4IPNKpEiiiQwMRqE2AyMSewrEGLg4PoYPy8WzSi9ZVm34xPGEURHHZH5Hd1Tn98pAQ",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEd25519key(tt.args.kid, tt.args.x); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewEd25519key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServer_RegistPublicKey(t *testing.T) {
	type fields struct {
		FileOperator FileOperator
		PublicKeyDir string
		Port         int
		Keys         []model.Key
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "normal",
			fields: fields{
				FileOperator: &MockFileOperator{
					ErrLoadTxtFile:  nil,
					ErrGetFileNames: nil,
				},
				PublicKeyDir: "files/public",
				Port:         8080,
				Keys:         []model.Key{},
			},
			wantErr: false,
		},
		{
			name: "error loadTextFile",
			fields: fields{
				FileOperator: &MockFileOperator{
					ErrLoadTxtFile:  errors.New("error"),
					ErrGetFileNames: nil,
				},
				PublicKeyDir: "files/public",
				Port:         8080,
				Keys:         []model.Key{},
			},
			wantErr: true,
		},
		{
			name: "error getFileNames",
			fields: fields{
				FileOperator: &MockFileOperator{
					ErrLoadTxtFile:  nil,
					ErrGetFileNames: errors.New("error"),
				},
				PublicKeyDir: "files/public",
				Port:         8080,
				Keys:         []model.Key{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				FileOperator: tt.fields.FileOperator,
				PublicKeyDir: tt.fields.PublicKeyDir,
				Port:         tt.fields.Port,
				Keys:         tt.fields.Keys,
			}
			if err := s.RegistPublicKey(); (err != nil) != tt.wantErr {
				t.Errorf("Server.RegistPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getBaseFilename(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "/path/to/dir/file.txt",
			args: args{
				path: "/path/to/dir/file.txt",
			},
			want: "file",
		},
		{
			name: "file.txt",
			args: args{
				path: "file.txt",
			},
			want: "file",
		},
		{
			name: "/path/to/dir/.config",
			args: args{
				path: "/path/to/dir/.config",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getBaseFilename(tt.args.path); got != tt.want {
				t.Errorf("getBaseFilename() = %v, want %v", got, tt.want)
			}
		})
	}
}
