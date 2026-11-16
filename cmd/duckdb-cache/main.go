// duckdb-cache is a build-only tool. It installs signed official extensions
// using the same embedded DuckDB library as Flare, never a separate CLI version.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb/v2"
)

func main() {
	dir := flag.String("directory", "", "new build-only extension cache")
	manifest := flag.String("manifest", "", "new public SHA manifest")
	flag.Parse()
	if err := install(*dir, *manifest); err != nil {
		fmt.Fprintf(os.Stderr, "duckdb-cache: %.160s\n", err.Error())
		os.Exit(1)
	}
}

func install(dir, manifest string) error {
	if !filepath.IsAbs(dir) || !filepath.IsAbs(manifest) || flag.NArg() != 0 {
		return fmt.Errorf("absolute outputs required")
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		return err
	}
	q := url.Values{"extension_directory": {dir}, "allow_unsigned_extensions": {"false"}, "custom_extension_repository": {"https://extensions.duckdb.org"}}
	db, err := sql.Open("duckdb", "?"+q.Encode())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var unsigned bool
	if err = db.QueryRowContext(ctx, "SELECT current_setting('allow_unsigned_extensions')").Scan(&unsigned); err != nil || unsigned {
		return fmt.Errorf("unsigned extensions must be disabled")
	}
	var version, platform string
	if err = db.QueryRowContext(ctx, "SELECT version()").Scan(&version); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA platform").Scan(&platform); err != nil {
		return err
	}
	if platform != "linux_amd64" && platform != "linux_amd64_gcc4" {
		return fmt.Errorf("unexpected DuckDB platform")
	}
	// HTTPS extension downloads themselves require httpfs. Bootstrap its signed
	// file with Go's HTTPS client, then let the embedded DuckDB verify/install it.
	staging, err := os.MkdirTemp(filepath.Dir(dir), ".duckdb-bootstrap-")
	if err != nil {
		return fmt.Errorf("bootstrap staging failed")
	}
	defer os.RemoveAll(staging)
	local := filepath.Join(staging, "httpfs.duckdb_extension")
	if err = downloadHTTPFS(ctx, version, platform, local); err != nil {
		return err
	}
	quoted := strings.ReplaceAll(local, "'", "''")
	if _, err = db.ExecContext(ctx, "INSTALL '"+quoted+"'"); err != nil {
		return fmt.Errorf("signed local httpfs install failed")
	}
	if _, err = db.ExecContext(ctx, "LOAD httpfs"); err != nil {
		return fmt.Errorf("signed local httpfs load failed")
	}
	if _, err = db.ExecContext(ctx, "INSTALL postgres FROM 'https://extensions.duckdb.org'"); err != nil {
		return fmt.Errorf("official postgres HTTPS install failed")
	}
	if _, err = db.ExecContext(ctx, "LOAD postgres"); err != nil {
		return fmt.Errorf("signed postgres load failed")
	}
	type file struct {
		Path   string `json:"path"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	files := []file{}
	var total int64
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || len(files) >= 32 || total+info.Size() > 128<<20 {
			return fmt.Errorf("cache bound")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(f, info.Size()+1))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || n != info.Size() {
			return fmt.Errorf("cache changed")
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, file{filepath.ToSlash(rel), n, hex.EncodeToString(h.Sum(nil))})
		total += n
		return nil
	})
	if err != nil || len(files) == 0 {
		return fmt.Errorf("cache inventory failed")
	}
	f, err := os.OpenFile(manifest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(struct {
		Version    string `json:"duckdb_version"`
		Platform   string `json:"platform"`
		Repository string `json:"repository"`
		Unsigned   bool   `json:"allow_unsigned_extensions"`
		Files      []file `json:"files"`
	}{version, platform, "https://extensions.duckdb.org", false, files})
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Bootstrap only this fixed official extension. No HTTP downgrade, unsigned
// mode, arbitrary repository, provider credential or runtime egress is added.
func downloadHTTPFS(ctx context.Context, version, platform, destination string) error {
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) ||
		(platform != "linux_amd64" && platform != "linux_amd64_gcc4") {
		return fmt.Errorf("unexpected bootstrap identity")
	}
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: officialRedirect}
	rawURL := "https://extensions.duckdb.org/" + version + "/" + platform + "/httpfs.duckdb_extension.gz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("bootstrap request failed")
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("official httpfs HTTPS download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("official httpfs response status %d", response.StatusCode)
	}
	if err = unpackExtension(response.Body, destination, 32<<20, 64<<20); err != nil {
		return fmt.Errorf("bounded httpfs decompression failed")
	}
	return nil
}

func officialRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != "extensions.duckdb.org" || req.URL.User != nil {
		return fmt.Errorf("bootstrap redirect refused")
	}
	return nil
}

func unpackExtension(source io.Reader, destination string, compressedLimit, expandedLimit int64) error {
	// Limit the compressed and expanded representations independently.
	compressed, err := io.ReadAll(io.LimitReader(source, compressedLimit+1))
	if err != nil || int64(len(compressed)) > compressedLimit {
		return fmt.Errorf("compressed bound")
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	defer reader.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(output, io.LimitReader(reader, expandedLimit+1))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil || n == 0 || n > expandedLimit {
		return fmt.Errorf("expanded bound or invalid gzip")
	}
	return nil
}
