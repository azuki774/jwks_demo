package server

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
	"testing"
)

func Test_parsePemPublicKeyLine(t *testing.T) {
	type args struct {
		pemLine string
	}
	tests := []struct {
		name    string
		args    args
		want    ed25519.PublicKey
		wantErr bool
	}{
		{
			name: "normal case",
			args: args{pemLine: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ/gYirMuxyY=
-----END PUBLIC KEY-----`},
			want:    ed25519.PublicKey([]byte{193, 128, 216, 129, 137, 240, 135, 19, 31, 71, 216, 68, 238, 43, 13, 214, 181, 135, 185, 181, 239, 17, 109, 68, 39, 248, 24, 138, 179, 46, 199, 38}),
			wantErr: false,
		},
		{
			name: "error case: invalid PEM format",
			args: args{pemLine: `-----BEGIN PRIVATE KEY-----
MCowBQYDK2VwAyEAwYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ/gYirMuxyY=
-----END PRIVATE KEY-----`},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error case: invaild value",
			args: args{pemLine: `-----BEGIN PUBLIC KEY-----
XXXwBQYDK2VwAyEAwYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ/gYirMuxyY=
-----END PUBLIC KEY-----`},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePemPublicKeyLine(tt.args.pemLine)
			fmt.Println(got)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePemPublicKeyLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePemPublicKeyLine() = %v, want %v", got, tt.want)
			}
		})
	}
}
