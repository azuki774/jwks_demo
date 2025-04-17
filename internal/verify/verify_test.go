package verify

import "testing"

func TestVerifier_verify(t *testing.T) {
	type args struct {
		jwtString string
	}
	tests := []struct {
		name    string
		v       *Verifier
		args    args
		wantOk  bool
		wantErr bool
	}{
		{
			name:    "valid token",
			v:       &Verifier{},
			args:    args{jwtString: "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJqd2tzX2RlbW9faXNzdWVyIn0.9oN0XeGWUBEiC2XmbwbMUCbN3J3rL3vlUENb8rj-OdZ1dfx7mGDZzH2FgXgDnWYgvmLg0d10kkSBzhjaJ-kCBQ"},
			wantOk:  true,
			wantErr: false,
		},
		{
			name:    "invalid token 1",
			v:       &Verifier{},
			args:    args{jwtString: "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1Qifa.eyJpc3MiOiJqd2tzX2RlbW9faXNzdWVyIn0.9oN0XeGWUBEiC2XmbwbMUCbN3J3rL3vlUENb8rj-OdZ1dfx7mGDZzH2FgXgDnWYgvmLg0d10kkSBzhjaJ-kCBQ"},
			wantOk:  false,
			wantErr: true,
		},
		{
			name:    "invalid token 2",
			v:       &Verifier{},
			args:    args{jwtString: "invalid"},
			wantOk:  false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{}
			gotOk, err := v.verify(tt.args.jwtString)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOk != tt.wantOk {
				t.Errorf("Verifier.verify() = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}
