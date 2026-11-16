package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/flare/internal/oidcprelink"
	"github.com/google/uuid"
)

func TestCLIRefusesUnknownArgumentsWithoutValues(t *testing.T) {
	var out bytes.Buffer
	secret := "DO_NOT_PRINT_PRIVATE_VALUE"
	called := false
	code := run([]string{"--database-url=" + secret}, func(string) string { called = true; return secret }, &out)
	if code == 0 || called || strings.Contains(out.String(), secret) {
		t.Fatal("unknown argument leaked or reached configuration")
	}
	if !strings.Contains(out.String(), "ARGUMENTS_REFUSED") {
		t.Fatal("missing fixed error")
	}
}
func TestCLIApplyNeedsAuthorityBeforeDatabase(t *testing.T) {
	r := oidcprelink.Request{RequestID: uuid.NewString(), UserID: "fixture-user", OrgID: "fixture-org", ExpectedRole: "owner", Issuer: "https://issuer.example.test", ClientID: "fixture-client", Subject: "PRIVATE_SUBJECT_NOT_OUTPUT"}
	raw, _ := json.Marshal(r)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("temporary directory unavailable")
	}
	p := filepath.Join(dir, "request.json")
	if os.WriteFile(p, raw, 0600) != nil {
		t.Fatal("fixture write failed")
	}
	var out bytes.Buffer
	code := run([]string{"--request", p, "--apply"}, func(string) string { return "postgres://sensitive-password@invalid.invalid/database" }, &out)
	if code == 0 || !strings.Contains(out.String(), "AUTHORITY_CHANGED") || strings.Contains(out.String(), r.Subject) || strings.Contains(out.String(), "sensitive-password") {
		t.Fatal("unsafe CLI error")
	}
}

func TestCLIApplyPinsExactRequestBeforeDatabase(t *testing.T) {
	original := oidcprelink.Request{RequestID: uuid.NewString(), UserID: "fixture-user", OrgID: "fixture-org", ExpectedRole: "owner", Issuer: "https://issuer.example.test", ClientID: "fixture-client", Subject: "PRIVATE_SUBJECT_NOT_OUTPUT"}
	raw, _ := json.Marshal(original)
	sum := sha256.Sum256(raw)
	pin := hex.EncodeToString(sum[:])
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("temporary directory unavailable")
	}
	p := filepath.Join(dir, "request.json")
	for _, mode := range []string{"missing_pin", "subject", "request_id"} {
		t.Run(mode, func(t *testing.T) {
			request := original
			if mode == "subject" {
				request.Subject = "CHANGED_PRIVATE_SUBJECT"
			}
			if mode == "request_id" {
				request.RequestID = uuid.NewString()
			}
			raw, _ := json.Marshal(request)
			if os.WriteFile(p, raw, 0600) != nil {
				t.Fatal("fixture write failed")
			}
			args := []string{"--request", p, "--apply", "--expected-authority-sha256", strings.Repeat("a", 64)}
			if mode != "missing_pin" {
				args = append(args, "--expected-request-sha256", pin)
			}
			var out bytes.Buffer
			if code := run(args, func(string) string { return "PRIVATE_DSN_INVALID" }, &out); code == 0 || !strings.Contains(out.String(), "REQUEST_CHANGED") || strings.Contains(out.String(), request.Subject) || strings.Contains(out.String(), "PRIVATE_DSN") {
				t.Fatal("request mutation was not refused/redacted before database")
			}
		})
	}
}
