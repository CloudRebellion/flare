//go:build imagequalification

package analytics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Runs inside the exact candidate image, with its preloaded extension cache,
// against only the job's disposable PG16 on an internal Docker network.
func TestImageRequiredPG16AnalyticsExportAndBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	dsn := os.Getenv("FLARE_IMAGE_TEST_DATABASE_URL")
	commit := os.Getenv("FLARE_IMAGE_EXPECTED_COMMIT")
	if dsn == "" || len(commit) != 40 {
		t.Fatal("required image fixture inputs absent")
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ready := false
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		r, err := client.Get("http://127.0.0.1:8080/readyz")
		if err != nil {
			continue
		}
		var v struct {
			Status string `json:"status"`
			Source string `json:"source_commit"`
			DB     struct {
				Healthy bool `json:"healthy"`
			} `json:"db"`
			Analytics struct {
				Configured bool `json:"configured"`
				Healthy    bool `json:"healthy"`
			} `json:"analytics"`
			Retention struct {
				Required bool `json:"export_required"`
			} `json:"retention"`
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 262145))
		r.Body.Close()
		if readErr == nil && len(body) <= 262144 && json.Unmarshal(body, &v) == nil && r.StatusCode == 200 && v.Status == "ok" && v.Source == commit && v.DB.Healthy && v.Analytics.Configured && v.Analytics.Healthy && v.Retention.Required {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("strict readiness or analytics unavailable; hot-only startup is not a pass")
	}
	for _, path := range []string{"/api/projects", "/api/analytics-health", "/api/mcp"} {
		r, err := client.Get("http://127.0.0.1:8080" + path)
		if err != nil {
			t.Fatal("anonymous boundary request failed")
		}
		io.Copy(io.Discard, io.LimitReader(r.Body, 262145))
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatal("anonymous protected route was not denied")
		}
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("PG fixture open failed")
	}
	defer pool.Close()
	var version int
	if err = pool.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil || version < 160000 || version >= 170000 {
		t.Fatal("actual PostgreSQL16 required")
	}
	// Separate named table exercises the real export implementation, without
	// changing the server's current partitions or making a retention-run claim.
	if _, err = pool.Exec(ctx, "CREATE TABLE public.logs_2099_01_02(id INTEGER PRIMARY KEY, org_id TEXT, project_id TEXT); INSERT INTO public.logs_2099_01_02 VALUES (1,'synthetic','fixture'),(2,'synthetic','fixture')"); err != nil {
		t.Fatal("synthetic cold fixture creation failed")
	}
	defer pool.Exec(context.Background(), "DROP TABLE IF EXISTS public.logs_2099_01_02")
	dir := t.TempDir()
	m, err := Open(ctx, Config{PostgresDSN: dsn, ParquetDir: dir})
	if err != nil {
		t.Fatal("real DuckDB/PG attach failed")
	}
	defer m.Close()
	if !m.Healthy(ctx) {
		t.Fatal("actual analytics query failed")
	}
	day := time.Date(2099, 1, 2, 0, 0, 0, 0, time.UTC)
	if err = NewExporter(m, pool).ExportDay(ctx, "logs", day); err != nil {
		t.Fatal("actual cold exporter failed")
	}
	file := filepath.Join(dir, "logs", "dt=2099-01-02", "part.parquet")
	if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		t.Fatal("nonempty Parquet output required")
	}
	var status string
	var rows int64
	if err = pool.QueryRow(ctx, "SELECT status,row_count FROM export_log WHERE tbl='logs' AND day=$1", day).Scan(&status, &rows); err != nil || status != "succeeded" || rows != 2 {
		t.Fatal("durable export ledger mismatch")
	}
	// A cold read survives removal of ONLY the test table, after export proof.
	if _, err = pool.Exec(ctx, "DROP TABLE public.logs_2099_01_02"); err != nil {
		t.Fatal("fixture drop failed")
	}
	if err = m.db.QueryRowContext(ctx, "SELECT count(*) FROM read_parquet('"+strings.ReplaceAll(filepath.ToSlash(file), "'", "''")+"', hive_partitioning=false)").Scan(&rows); err != nil || rows != 2 {
		t.Fatal("cold Parquet roundtrip failed")
	}
	if _, err = m.db.ExecContext(ctx, "LOAD httpfs"); err != nil {
		t.Fatal("signed offline httpfs cache missing")
	}
	t.Log("IMAGE_PG16_ANALYTICS_EXPORT_BOUNDARIES_PASSED")
}
