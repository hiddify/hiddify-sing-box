package gooserelay_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hiddify/gooserelay"
)

const validHexKey = "0000000000000000000000000000000000000000000000000000000000000000"

func TestNew_OptionValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		opts     option.GooseRelayOptions
		wantErr  string // substring expected in the error; "" = expect success
		wantSkip bool
	}{
		{
			name:    "missing script_keys",
			opts:    option.GooseRelayOptions{TunnelKey: validHexKey},
			wantErr: "script_keys is required",
		},
		{
			name:    "missing tunnel_key",
			opts:    option.GooseRelayOptions{ScriptKeys: []string{"abc"}},
			wantErr: "tunnel_key is required",
		},
		{
			name: "tunnel_key wrong length",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"abc"},
				TunnelKey:  "deadbeef",
			},
			wantErr: "64 hex characters",
		},
		{
			name: "tunnel_key not hex",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"abc"},
				TunnelKey:  strings.Repeat("Z", 64),
			},
			wantErr: "not valid hex",
		},
		{
			name: "empty entry in script_keys",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"abc", "   "},
				TunnelKey:  validHexKey,
			},
			wantErr: "script_keys[1] is empty",
		},
		{
			name: "script_keys contains URL separator /",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"abc/def"},
				TunnelKey:  validHexKey,
			},
			wantErr: "URL separator",
		},
		{
			name: "script_keys contains URL separator ?",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"abc?evil=1"},
				TunnelKey:  validHexKey,
			},
			wantErr: "URL separator",
		},
		{
			name: "script_keys contains URL separator #",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"abc#frag"},
				TunnelKey:  validHexKey,
			},
			wantErr: "URL separator",
		},
		{
			name: "valid minimal options",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"AKfycbxFakeDeploymentID"},
				TunnelKey:  validHexKey,
			},
			wantErr: "",
		},
		{
			name: "valid with custom GoogleHost and SNI defaults applied",
			opts: option.GooseRelayOptions{
				ScriptKeys: []string{"AKfycbxFakeDeploymentID"},
				TunnelKey:  validHexKey,
				GoogleHost: "1.2.3.4:443",
			},
			wantErr: "",
		},
	}

	logger := log.NewNOPFactory().Logger()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.wantSkip {
				t.Skip()
			}
			out, err := gooserelay.New(context.Background(), nil, logger, "goose-test", tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if out == nil {
					t.Fatal("expected non-nil outbound on success")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
