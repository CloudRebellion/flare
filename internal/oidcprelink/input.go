// Package oidcprelink implements explicit, existing-account OIDC binding only.
package oidcprelink

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

type Code string

func (c Code) Error() string { return string(c) }

const (
	ErrInput        Code = "INPUT_REFUSED"
	ErrFile         Code = "REQUEST_FILE_REFUSED"
	ErrDatabase     Code = "DATABASE_REFUSED"
	ErrBusy         Code = "OPERATION_BUSY"
	ErrProfile      Code = "PROFILE_REFUSED"
	ErrRole         Code = "ROLE_REFUSED"
	ErrBound        Code = "BINDING_REFUSED"
	ErrAudit        Code = "AUDIT_REFUSED"
	ErrAuthority    Code = "AUTHORITY_CHANGED"
	ErrRequest      Code = "REQUEST_CHANGED"
	ErrIdentity     Code = "IDENTITY_CONFLICT"
	ErrPreservation Code = "NONBINDING_AUTHORITY_CHANGED"
	ErrUnknown      Code = "COMMIT_OUTCOME_UNKNOWN"
)

type Request struct {
	RequestID    string `json:"request_id"`
	UserID       string `json:"user_id"`
	OrgID        string `json:"org_id"`
	ExpectedRole string `json:"expected_role"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	Subject      string `json:"subject"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func bounded(value string, max int) bool {
	if value == "" || len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (r Request) Validate() error {
	id, err := uuid.Parse(r.RequestID)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || id.String() != r.RequestID ||
		!identifier.MatchString(r.UserID) || !identifier.MatchString(r.OrgID) ||
		!bounded(r.ClientID, 255) || !bounded(r.Subject, 255) || !bounded(r.Issuer, 2048) {
		return ErrInput
	}
	if r.ExpectedRole != "owner" && r.ExpectedRole != "admin" && r.ExpectedRole != "member" && r.ExpectedRole != "viewer" {
		return ErrInput
	}
	u, err := url.Parse(r.Issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrInput
	}
	return nil
}

// Decode rejects unknown/duplicate fields, non-string values and trailing JSON.
func Decode(raw []byte) (Request, error) {
	var r Request
	if len(raw) == 0 || len(raw) > 16<<10 || !utf8.Valid(raw) {
		return r, ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return r, ErrInput
	}
	values := map[string]string{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return r, ErrInput
		}
		name, ok := key.(string)
		if !ok {
			return r, ErrInput
		}
		if _, ok := values[name]; ok {
			return r, ErrInput
		}
		switch name {
		case "request_id", "user_id", "org_id", "expected_role", "issuer", "client_id", "subject":
		default:
			return r, ErrInput
		}
		var value string
		if d.Decode(&value) != nil {
			return r, ErrInput
		}
		values[name] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return r, ErrInput
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return r, ErrInput
	}
	r = Request{values["request_id"], values["user_id"], values["org_id"], values["expected_role"], values["issuer"], values["client_id"], values["subject"]}
	return r, r.Validate()
}

type fileIdentity struct {
	dev, ino                       uint64
	mode                           os.FileMode
	uid, gid                       uint32
	nlink                          uint64
	size, mtime, ctimeSec, ctimeNS int64
}

func identity(s os.FileInfo) (fileIdentity, bool) {
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, false
	}
	sec, ns := changeTime(st)
	return fileIdentity{uint64(st.Dev), uint64(st.Ino), s.Mode(), st.Uid, st.Gid, uint64(st.Nlink), s.Size(), s.ModTime().UnixNano(), sec, ns}, true
}

// ReadFile never follows a symlink or blocks on a FIFO. Private caller-owned
// single-link files are checked through the FD and name before/after the read.
func ReadFile(path string) (Request, error) {
	var empty Request
	absolute, err := filepath.Abs(path)
	if err != nil {
		return empty, ErrFile
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil || canonical != absolute {
		return empty, ErrFile
	}
	named, err := os.Lstat(absolute)
	if err != nil {
		return empty, ErrFile
	}
	before, ok := identity(named)
	if !ok || !named.Mode().IsRegular() || named.Mode().Perm() != 0600 || before.uid != uint32(os.Getuid()) || before.nlink != 1 || before.size <= 0 || before.size > 16<<10 {
		return empty, ErrFile
	}
	fd, err := syscall.Open(absolute, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrFile
	}
	f := os.NewFile(uintptr(fd), absolute)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return empty, ErrFile
	}
	a, ok := identity(opened)
	if !ok || a != before {
		return empty, ErrFile
	}
	raw, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if err != nil {
		return empty, ErrFile
	}
	after, err := f.Stat()
	if err != nil {
		return empty, ErrFile
	}
	a, ok = identity(after)
	if !ok || a != before {
		return empty, ErrFile
	}
	named, err = os.Lstat(absolute)
	if err != nil {
		return empty, ErrFile
	}
	a, ok = identity(named)
	if !ok || a != before || int64(len(raw)) != before.size {
		return empty, ErrFile
	}
	return Decode(raw)
}
