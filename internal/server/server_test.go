package server

import (
	"reflect"
	"testing"
)

func TesNewEd25519key(t *testing.T) {
	type args struct {
		kid string
		x   string
	}
	tests := []struct {
		name string
		args args
		want Key
	}{
		{
			name: "valid inputs",
			args: args{
				kid: "testKid",
				x:   "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NDUwNDA3MzEsImlzcyI6Imp3a3NfZGVtb19pc3N1ZXIiLCJzdWIiOiJqd2tzX2RlbW9fc3ViamVjdCJ9.gFiXfDvSJnmrm5isM9Ny4IPNKpEiiiQwMRqE2AyMSewrEGLg4PoYPy8WzSi9ZVm34xPGEURHHZH5Hd1Tn98pAQ",
			},
			want: Key{
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
