package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func zipped(t *testing.T, input []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestUnpackExtensionRejectsBoundsAndCorruption(t *testing.T) {
	data := zipped(t, bytes.Repeat([]byte("x"), 64))
	for _, tc := range []struct {
		name                 string
		data                 []byte
		compressed, expanded int64
		want                 bool
	}{
		{"valid", data, 128, 64, true},
		{"compressed bound", data, int64(len(data) - 1), 64, false},
		{"expanded bound", data, 128, 63, false},
		{"truncated gzip", data[:len(data)-2], 128, 64, false},
		{"invalid gzip", []byte("bad"), 128, 64, false},
		{"empty extension", zipped(t, nil), 128, 64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "extension")
			err := unpackExtension(bytes.NewReader(tc.data), output, tc.compressed, tc.expanded)
			if (err == nil) != tc.want {
				t.Fatalf("success=%v want=%v", err == nil, tc.want)
			}
			if tc.want {
				actual, err := os.ReadFile(output)
				if err != nil || !bytes.Equal(actual, bytes.Repeat([]byte("x"), 64)) {
					t.Fatal("wrong bytes")
				}
			}
		})
	}
	output := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(output, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unpackExtension(bytes.NewReader(data), output, 128, 64); err == nil {
		t.Fatal("overwrote existing output")
	}
	actual, _ := os.ReadFile(output)
	if string(actual) != "preserve" {
		t.Fatal("existing output changed")
	}
}

func TestOfficialRedirectRejectsDowngradeAndForeignOrigins(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		count int
		want  bool
	}{
		{"https://extensions.duckdb.org/a", 1, true},
		{"http://extensions.duckdb.org/a", 1, false},
		{"https://example.com/a", 1, false},
		{"https://user:password@extensions.duckdb.org/a", 1, false},
		{"https://extensions.duckdb.org:444/a", 1, false},
		{"https://extensions.duckdb.org/a", 3, false},
	} {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		err = officialRedirect(&http.Request{URL: u}, make([]*http.Request, tc.count))
		if (err == nil) != tc.want {
			t.Errorf("redirect %s count%d success=%v", u.Redacted(), tc.count, err == nil)
		}
	}
}
