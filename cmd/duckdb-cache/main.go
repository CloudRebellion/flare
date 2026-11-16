// duckdb-cache is a build-only tool. It installs signed official extensions
// using the same embedded DuckDB library as Flare, never a separate CLI version.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "github.com/marcboeker/go-duckdb/v2"
)

func main() {
	dir := flag.String("directory", "", "new build-only extension cache")
	manifest := flag.String("manifest", "", "new public SHA manifest")
	flag.Parse()
	if err := install(*dir, *manifest); err != nil {
		fmt.Fprintln(os.Stderr, "duckdb-cache: qualification failed")
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
	for _, ext := range []string{"postgres", "httpfs"} {
		if _, err = db.ExecContext(ctx, "INSTALL "+ext+" FROM 'https://extensions.duckdb.org'"); err != nil {
			return err
		}
		if _, err = db.ExecContext(ctx, "LOAD "+ext); err != nil {
			return err
		}
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
