package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   bool
		wantErrIs error
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
		{
			name:      "missing authorization header",
			headers:   http.Header{},
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "wrong auth scheme",
			headers: http.Header{"Authorization": []string{"Bearer token"}},
			wantErr: true,
		},
		{
			name:    "missing key after scheme",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantErr: false, // intentional failure
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("GetAPIKey() error = %v, want %v", err, tt.wantErrIs)
			}
			if got != tt.wantKey {
				t.Fatalf("GetAPIKey() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}
