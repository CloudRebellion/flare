package oidcprelink

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/uuid"
)

func fixtureRequest() Request {
	return Request{uuid.NewString(), "fixture-user", "fixture-org", "owner", "https://issuer.example.test", "fixture-client", "fixture-private-subject"}
}
func TestDecodeClosedRequest(t *testing.T) {
	r := fixtureRequest()
	raw, _ := json.Marshal(r)
	if got, err := Decode(raw); err != nil || got != r {
		t.Fatal("valid request refused")
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), []byte(` {}`)...),
		[]byte(strings.Replace(string(raw), `"subject":`, `"unknown":"value","subject":`, 1)),
		[]byte(strings.Replace(string(raw), `"subject":`, `"subject":"duplicate","subject":`, 1)),
		[]byte(strings.Replace(string(raw), `"expected_role":"owner"`, `"expected_role":true`, 1)),
		[]byte("{\"subject\":\"\xff\"}"),
	} {
		if _, err := Decode(bad); err != ErrInput {
			t.Fatal("malformed request accepted")
		}
	}
	for _, change := range []func(*Request){
		func(r *Request) { r.Subject = " " }, func(r *Request) { r.Subject = " trailing " },
		func(r *Request) { r.Subject = strings.Repeat("a", 256) }, func(r *Request) { r.Subject = "control\nvalue" },
		func(r *Request) { r.Issuer = "http://issuer.example.test" }, func(r *Request) { r.Issuer = "https://user:pass@issuer.example.test" },
		func(r *Request) { r.Issuer = "https://issuer.example.test/?query=1" }, func(r *Request) { r.RequestID = "not-a-uuid" },
		func(r *Request) { r.ExpectedRole = "superuser" }, func(r *Request) { r.UserID = "" },
	} {
		bad := r
		change(&bad)
		if bad.Validate() != ErrInput {
			t.Fatal("invalid identity/profile accepted")
		}
	}
	r.Subject = strings.Repeat("a", 255)
	if r.Validate() != nil {
		t.Fatal("subject boundary refused")
	}
}
func TestReadFilePrivateRegularNoFollow(t *testing.T) {
	r := fixtureRequest()
	raw, _ := json.Marshal(r)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("temporary directory unavailable")
	}
	p := filepath.Join(dir, "request.json")
	if err = os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal("fixture write failed")
	}
	if got, err := ReadFile(p); err != nil || got != r {
		t.Fatal("private request refused")
	}
	if err = os.Chmod(p, 0644); err != nil {
		t.Fatal("fixture chmod failed")
	}
	if _, err := ReadFile(p); err != ErrFile {
		t.Fatal("public request accepted")
	}
	_ = os.Chmod(p, 0600)
	link := filepath.Join(dir, "link")
	if os.Symlink(p, link) != nil {
		t.Fatal("fixture symlink failed")
	}
	if _, err := ReadFile(link); err != ErrFile {
		t.Fatal("symlink request accepted")
	}
	hard := filepath.Join(dir, "hard")
	if os.Link(p, hard) != nil {
		t.Fatal("fixture hardlink failed")
	}
	if _, err := ReadFile(p); err != ErrFile {
		t.Fatal("multi-link request accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if syscall.Mkfifo(fifo, 0600) != nil {
		t.Fatal("fixture fifo failed")
	}
	if _, err := ReadFile(fifo); err != ErrFile {
		t.Fatal("FIFO request accepted")
	}
}
