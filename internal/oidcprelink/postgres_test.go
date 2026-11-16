package oidcprelink

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type pgFixture struct {
	dsn     string
	conn    *pgx.Conn
	request Request
}

func postgresFixture(t *testing.T) pgFixture {
	t.Helper()
	base := os.Getenv("FLARE_TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("FLARE_OIDC_PRELINK_REQUIRE_DB") == "1" {
			t.Fatal("required PostgreSQL fixture is missing")
		}
		t.Skip("FLARE_TEST_DATABASE_URL absent; required mode refuses this skip")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	control, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal("PostgreSQL fixture unavailable")
	}
	schema := "oidc_prelink_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = control.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal("isolated fixture schema unavailable")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = control.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = control.Close(ctx)
	})
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("fixture requires PostgreSQL URL")
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal("isolated fixture connection unavailable")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = conn.Close(ctx)
	})
	if _, err = conn.Exec(ctx, fixtureDDL); err != nil {
		t.Fatal("exact fixture schema creation failed")
	}
	f := pgFixture{u.String(), conn, fixtureRequest()}
	f.exec(t, `ALTER TABLE users ADD COLUMN future_authority JSONB NOT NULL DEFAULT '{"disabled":false,"native_mfa":"preserve"}'`)
	f.exec(t, `INSERT INTO orgs(id,name,slug) VALUES('fixture-org','Fixture','fixture'),('other-org','Other','other')`)
	f.exec(t, `INSERT INTO users(id,org_id,email,password_hash,role) VALUES
 ('fixture-user','fixture-org','owner@example.test','synthetic-password-hash','owner'),
 ('other-user','fixture-org','other@example.test','other-password-hash','member'),
 ('foreign-user','other-org','foreign@example.test','foreign-password-hash','owner')`)
	f.exec(t, `INSERT INTO oidc_config(org_id,issuer,client_id,client_secret,default_role,enabled) VALUES
 ('fixture-org','https://issuer.example.test','fixture-client','synthetic-encrypted-secret','member',false),
 ('other-org','https://other.example.test','other-client','other-encrypted-secret','member',false)`)
	f.exec(t, `INSERT INTO api_keys(id,org_id,name,key_hash,key_prefix) VALUES('fixture-key','fixture-org','Fixture','synthetic-hash','test')`)
	f.exec(t, `INSERT INTO sessions(token,data,expiry) VALUES('fixture-session',decode('abcd','hex'),now()+interval '1 hour')`)
	return f
}
func (f pgFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.conn.Exec(ctx, sql, args...); err != nil {
		t.Fatal("fixture SQL failed")
	}
}
func (f pgFixture) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if f.conn.QueryRow(context.Background(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n) != nil {
		t.Fatal("fixture count failed")
	}
	return n
}
func (f pgFixture) plan(t *testing.T) Result {
	t.Helper()
	out, err := Execute(context.Background(), f.dsn, f.request, false, "", "")
	if err != nil {
		t.Fatal("read-only plan refused")
	}
	return out
}
func (f pgFixture) snapshot(t *testing.T) map[string][]byte {
	t.Helper()
	values := map[string][]byte{}
	for _, table := range []string{"orgs", "users", "oidc_config", "api_keys", "sessions", "projects"} {
		row := "to_jsonb(t)"
		if table == "users" {
			row = "CASE WHEN t.id='fixture-user' THEN to_jsonb(t)-'sso_issuer'-'sso_subject' ELSE to_jsonb(t) END"
		}
		var raw []byte
		if f.conn.QueryRow(context.Background(), "SELECT COALESCE(jsonb_agg("+row+" ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM "+pgx.Identifier{table}.Sanitize()+" t").Scan(&raw) != nil {
			t.Fatal("fixture snapshot failed")
		}
		values[table] = raw
	}
	return values
}
func sameSnapshot(t *testing.T, a, b map[string][]byte) {
	t.Helper()
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			t.Fatal("nonbinding fixture authority changed")
		}
	}
}
func noBinding(t *testing.T, f pgFixture) {
	t.Helper()
	var issuer, subject string
	if f.conn.QueryRow(context.Background(), `SELECT sso_issuer,sso_subject FROM users WHERE id=$1`, f.request.UserID).Scan(&issuer, &subject) != nil {
		t.Fatal("fixture readback failed")
	}
	if issuer != "" || subject != "" || f.count(t, "audit_log") != 0 {
		t.Fatal("refusal left effects")
	}
}

// One required top-level PG test, no hidden skips. A separate native runner
// requires its exact marker AND successful test exit; this is not Stage CI.
func TestPostgresPrelink(t *testing.T) {
	t.Run("plan_bind_preservation_and_audit", func(t *testing.T) {
		f := postgresFixture(t)
		before := f.snapshot(t)
		p := f.plan(t)
		if p.Status != "planned" || p.Changed || p.CurrentRole != "owner" {
			t.Fatal("incorrect plan")
		}
		noBinding(t, f)
		out, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request))
		if err != nil || out.Status != "applied" || !out.Changed || !out.OriginalAuthorityMatchesCurrent {
			t.Fatal("explicit bind failed")
		}
		sameSnapshot(t, before, f.snapshot(t))
		var issuer, subject string
		if f.conn.QueryRow(context.Background(), `SELECT sso_issuer,sso_subject FROM users WHERE id=$1`, f.request.UserID).Scan(&issuer, &subject) != nil || issuer != f.request.Issuer || subject != f.request.Subject {
			t.Fatal("binding missing")
		}
		var actor *string
		var action, target string
		if f.conn.QueryRow(context.Background(), `SELECT actor_user_id,action,target FROM audit_log WHERE id=$1`, f.request.RequestID).Scan(&actor, &action, &target) != nil || actor != nil || action != Action || strings.Contains(target, f.request.Subject) {
			t.Fatal("audit privacy/authority mismatch")
		}
		if !strings.Contains(target, hash([]byte(f.request.Subject))) {
			t.Fatal("audit lacks subject digest")
		}
	})
	t.Run("all_initial_refusals", func(t *testing.T) {
		for _, mode := range []string{"wrong_org", "wrong_role", "wrong_issuer", "wrong_client", "enabled", "stale_hash", "already_bound_no_audit", "partial_binding"} {
			t.Run(mode, func(t *testing.T) {
				f := postgresFixture(t)
				p := f.plan(t)
				r := f.request
				pin := p.PlannedAuthoritySHA256
				switch mode {
				case "wrong_org":
					r.OrgID = "other-org"
				case "wrong_role":
					r.ExpectedRole = "member"
				case "wrong_issuer":
					r.Issuer = "https://other.example.test"
				case "wrong_client":
					r.ClientID = "other-client"
				case "enabled":
					f.exec(t, `UPDATE oidc_config SET enabled=true WHERE org_id='fixture-org'`)
				case "stale_hash":
					f.exec(t, `UPDATE users SET future_authority='{"native_mfa":"changed"}' WHERE id='fixture-user'`)
				case "already_bound_no_audit":
					f.exec(t, `UPDATE users SET sso_issuer=$1,sso_subject=$2 WHERE id='fixture-user'`, r.Issuer, r.Subject)
				case "partial_binding":
					f.exec(t, `UPDATE users SET sso_issuer=$1 WHERE id='fixture-user'`, r.Issuer)
				}
				before := f.snapshot(t)
				if _, err := Execute(context.Background(), f.dsn, r, true, pin, requestDigest(r)); err == nil {
					t.Fatal("invalid initial binding accepted")
				}
				sameSnapshot(t, before, f.snapshot(t))
				if f.count(t, "audit_log") != 0 {
					t.Fatal("refusal wrote audit")
				}
				if mode != "already_bound_no_audit" && mode != "partial_binding" {
					noBinding(t, f)
				}
			})
		}
	})
	t.Run("changed_request_refuses_despite_same_authority", func(t *testing.T) {
		for _, mode := range []string{"subject", "request_id"} {
			t.Run(mode, func(t *testing.T) {
				f := postgresFixture(t)
				p := f.plan(t)
				before := f.snapshot(t)
				r := f.request
				if mode == "subject" {
					r.Subject = "unreviewed-different-subject"
				} else {
					r.RequestID = uuid.NewString()
				}
				if f.plan(t).PlannedAuthoritySHA256 != p.PlannedAuthoritySHA256 {
					t.Fatal("fixture authority changed")
				}
				if _, err := Execute(context.Background(), f.dsn, r, true, p.PlannedAuthoritySHA256, p.RequestSHA256); err != ErrRequest {
					t.Fatal("changed request accepted with unchanged authority hash")
				}
				noBinding(t, f)
				sameSnapshot(t, before, f.snapshot(t))
			})
		}
	})
	t.Run("identity_unique_conflict_rolls_back", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		f.exec(t, `UPDATE users SET sso_issuer=$1,sso_subject=$2 WHERE id='other-user'`, f.request.Issuer, f.request.Subject)
		before := f.snapshot(t)
		if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != ErrIdentity {
			t.Fatal("identity conflict not refused")
		}
		noBinding(t, f)
		sameSnapshot(t, before, f.snapshot(t))
	})
	t.Run("atomic_audit_failure_rolls_back_binding", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		before := f.snapshot(t)
		f.exec(t, `CREATE FUNCTION reject_prelink_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic audit refusal'; END$$;
   CREATE TRIGGER reject_prelink BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_prelink_audit()`)
		if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err == nil {
			t.Fatal("audit failure accepted")
		}
		noBinding(t, f)
		sameSnapshot(t, before, f.snapshot(t))
	})
	t.Run("future_column_trigger_change_rolls_back", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		before := f.snapshot(t)
		f.exec(t, `CREATE FUNCTION alter_future_authority() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.future_authority='{"unexpected":true}'; RETURN NEW; END$$;
   CREATE TRIGGER alter_future BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION alter_future_authority()`)
		if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != ErrPreservation {
			t.Fatal("nonbinding trigger mutation accepted")
		}
		noBinding(t, f)
		sameSnapshot(t, before, f.snapshot(t))
	})
	t.Run("audit_trigger_authority_change_rolls_back", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		before := f.snapshot(t)
		f.exec(t, `CREATE FUNCTION change_authority_from_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE users SET future_authority='{"audit_mutation":true}' WHERE id='fixture-user'; RETURN NEW; END$$;
		 CREATE TRIGGER change_audit AFTER INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION change_authority_from_audit()`)
		if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != ErrPreservation {
			t.Fatal("audit trigger authority mutation accepted")
		}
		noBinding(t, f)
		sameSnapshot(t, before, f.snapshot(t))
	})
	t.Run("request_audit_collision_refuses", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		f.exec(t, `INSERT INTO audit_log(id,org_id,action,target) VALUES($1,'fixture-org','other.action','unrelated')`, f.request.RequestID)
		before := f.snapshot(t)
		if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != ErrAudit {
			t.Fatal("wrong audit accepted")
		}
		sameSnapshot(t, before, f.snapshot(t))
		if f.count(t, "audit_log") != 1 {
			t.Fatal("conflicting audit changed")
		}
		var sub string
		_ = f.conn.QueryRow(context.Background(), `SELECT sso_subject FROM users WHERE id='fixture-user'`).Scan(&sub)
		if sub != "" {
			t.Fatal("audit conflict bound account")
		}
	})
	t.Run("same_request_reconciles_without_rewinding_current_authority", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != nil {
			t.Fatal("initial fixture bind failed")
		}
		f.exec(t, `UPDATE users SET role='admin',password_hash='legitimate-new-hash',sessions_valid_from=now()+interval '1 second',future_authority='{"native_mfa":"new-native-state"}' WHERE id='fixture-user'`)
		f.exec(t, `UPDATE oidc_config SET enabled=true WHERE org_id='fixture-org'`)
		before := f.snapshot(t)
		for _, apply := range []bool{false, true} {
			out, err := Execute(context.Background(), f.dsn, f.request, apply, p.PlannedAuthoritySHA256, requestDigest(f.request))
			if err != nil || out.Status != "reconciled" || out.Changed || out.CurrentRole != "admin" || out.OriginalAuthorityMatchesCurrent || out.PlannedAuthoritySHA256 != p.PlannedAuthoritySHA256 || out.CurrentAuthoritySHA256 == p.PlannedAuthoritySHA256 {
				t.Fatal("reconciliation misreported/rewound authority")
			}
		}
		sameSnapshot(t, before, f.snapshot(t))
		if f.count(t, "audit_log") != 1 {
			t.Fatal("reconciliation duplicated audit")
		}
		wrong := f.request
		wrong.Subject = "different-private-subject"
		if _, err := Execute(context.Background(), f.dsn, wrong, false, "", ""); err == nil {
			t.Fatal("wrong request reconciled")
		}
		f.exec(t, `UPDATE oidc_config SET client_id='wrong-client' WHERE org_id='fixture-org'`)
		if _, err := Execute(context.Background(), f.dsn, f.request, false, "", ""); err != ErrProfile {
			t.Fatal("changed profile reconciled")
		}
	})
	t.Run("no_matching_audit_never_adopts_binding", func(t *testing.T) {
		f := postgresFixture(t)
		f.exec(t, `UPDATE users SET sso_issuer=$1,sso_subject=$2 WHERE id='fixture-user'`, f.request.Issuer, f.request.Subject)
		if _, err := Execute(context.Background(), f.dsn, f.request, false, "", ""); err != ErrBound {
			t.Fatal("unaudited binding adopted")
		}
		if f.count(t, "audit_log") != 0 {
			t.Fatal("read-only refusal wrote audit")
		}
	})
	t.Run("nonblocking_request_and_native_row_locks", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		var locked bool
		if f.conn.QueryRow(context.Background(), `SELECT pg_try_advisory_lock($1)`, operationKey(f.request.RequestID)).Scan(&locked) != nil || !locked {
			t.Fatal("fixture advisory lock unavailable")
		}
		if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != ErrBusy {
			t.Fatal("same request did not refuse busy")
		}
		f.exec(t, `SELECT pg_advisory_unlock($1)`, operationKey(f.request.RequestID))
		tx, err := f.conn.Begin(context.Background())
		if err != nil {
			t.Fatal("fixture transaction unavailable")
		}
		if _, err = tx.Exec(context.Background(), `SELECT id FROM users WHERE id='fixture-user' FOR UPDATE`); err != nil {
			t.Fatal("fixture row lock unavailable")
		}
		if _, err = Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != ErrBusy {
			t.Fatal("native user lock did not refuse busy")
		}
		_ = tx.Rollback(context.Background())
		noBinding(t, f)
	})

	t.Run("two_request_race_has_one_binding_and_one_audit", func(t *testing.T) {
		f := postgresFixture(t)
		p := f.plan(t)
		before := f.snapshot(t)
		requests := []Request{f.request, f.request}
		requests[1].RequestID = uuid.NewString()
		start := make(chan struct{})
		results := make(chan error, 2)
		var group sync.WaitGroup
		for _, request := range requests {
			group.Add(1)
			go func(r Request) {
				defer group.Done()
				<-start
				_, err := Execute(context.Background(), f.dsn, r, true, p.PlannedAuthoritySHA256, requestDigest(r))
				results <- err
			}(request)
		}
		close(start)
		group.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if err != ErrBusy && err != ErrBound {
				t.Fatal("unexpected race outcome")
			}
		}
		if success != 1 || f.count(t, "audit_log") != 1 {
			t.Fatal("competing requests did not produce exactly one atomic outcome")
		}
		sameSnapshot(t, before, f.snapshot(t))
	})
	t.Run("matching_request_refuses_corrupted_audit_or_binding", func(t *testing.T) {
		for _, mode := range []string{"actor", "action", "target", "user", "binding"} {
			t.Run(mode, func(t *testing.T) {
				f := postgresFixture(t)
				p := f.plan(t)
				if _, err := Execute(context.Background(), f.dsn, f.request, true, p.PlannedAuthoritySHA256, requestDigest(f.request)); err != nil {
					t.Fatal("fixture bind failed")
				}
				r := f.request
				switch mode {
				case "actor":
					f.exec(t, `UPDATE audit_log SET actor_user_id='fixture-user' WHERE id=$1`, r.RequestID)
				case "action":
					f.exec(t, `UPDATE audit_log SET action='wrong.action' WHERE id=$1`, r.RequestID)
				case "target":
					f.exec(t, `UPDATE audit_log SET target='{}' WHERE id=$1`, r.RequestID)
				case "user":
					r.UserID = "other-user"
				case "binding":
					f.exec(t, `UPDATE users SET sso_subject='wrong-binding' WHERE id='fixture-user'`)
				}
				before := f.snapshot(t)
				if _, err := Execute(context.Background(), f.dsn, r, false, "", ""); err == nil {
					t.Fatal("wrong audit/user/binding reconciled")
				}
				sameSnapshot(t, before, f.snapshot(t))
				if f.count(t, "audit_log") != 1 {
					t.Fatal("reconciliation refusal wrote audit")
				}
			})
		}
	})

	if !t.Failed() && os.Getenv("FLARE_TEST_DATABASE_URL") != "" {
		t.Log("OIDC_PRELINK_POSTGRES_REQUIRED_PASSED")
	}
}

func TestRequestAndAuditOutputNeverContainRawSubject(t *testing.T) {
	r := fixtureRequest()
	target := target(r, strings.Repeat("a", 64))
	if strings.Contains(target, r.Subject) {
		t.Fatal("raw subject in audit")
	}
	raw, _ := json.Marshal(Result{Status: "planned", RequestID: r.RequestID, CurrentRole: r.ExpectedRole})
	if strings.Contains(string(raw), r.Subject) || strings.Contains(string(raw), r.Issuer) || strings.Contains(string(raw), r.UserID) {
		t.Fatal("private identity in public output")
	}
}
