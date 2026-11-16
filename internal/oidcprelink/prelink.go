package oidcprelink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const Action = "sso.prelink.operator"

type Result struct {
	Status                          string `json:"status"`
	RequestID                       string `json:"request_id"`
	RequestSHA256                   string `json:"request_sha256"`
	Changed                         bool   `json:"changed"`
	CurrentRole                     string `json:"current_role"`
	CurrentAuthoritySHA256          string `json:"current_authority_sha256"`
	PlannedAuthoritySHA256          string `json:"planned_authority_sha256"`
	OriginalAuthorityMatchesCurrent bool   `json:"original_authority_matches_current"`
}

type state struct {
	org, role, issuer, subject string
	user, config               []byte
	configIssuer, client       string
	enabled                    bool
}
type auditTarget struct {
	Version         int    `json:"version"`
	RequestSHA256   string `json:"request_sha256"`
	UserID          string `json:"user_id"`
	SubjectSHA256   string `json:"subject_sha256"`
	IssuerSHA256    string `json:"issuer_sha256"`
	ClientSHA256    string `json:"client_sha256"`
	AuthoritySHA256 string `json:"authority_sha256"`
}
type audit struct {
	org, action, target string
	actor               *string
}

func hash(raw []byte) string         { v := sha256.Sum256(raw); return hex.EncodeToString(v[:]) }
func requestDigest(r Request) string { raw, _ := json.Marshal(r); return hash(raw) }

func validHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == hex.EncodeToString(raw)
}
func operationKey(requestID string) int64 {
	v := sha256.Sum256([]byte("flare-oidc-prelink-v1\x00" + requestID))
	return int64(binary.BigEndian.Uint64(v[:8]))
}
func authority(s state) string {
	// RawMessage retains future columns and exact JSON numbers; no password hash,
	// secret, session epoch or other raw authority is ever returned or logged.
	raw, _ := json.Marshal(struct{ User, Config json.RawMessage }{s.user, s.config})
	return hash(raw)
}
func target(r Request, planned string) string {
	raw, _ := json.Marshal(r)
	t := auditTarget{1, hash(raw), r.UserID, hash([]byte(r.Subject)), hash([]byte(r.Issuer)), hash([]byte(r.ClientID)), planned}
	raw, _ = json.Marshal(t)
	return string(raw)
}
func dbError(err error) error {
	var p *pgconn.PgError
	if errors.As(err, &p) && (p.Code == "55P03" || p.Code == "57014") {
		return ErrBusy
	}
	return ErrDatabase
}
func readState(ctx context.Context, tx pgx.Tx, r Request) (state, error) {
	var s state
	err := tx.QueryRow(ctx, `SELECT u.org_id,u.role,u.sso_issuer,u.sso_subject,
 (to_jsonb(u)-'sso_issuer'-'sso_subject')::text,to_jsonb(c)::text,c.issuer,c.client_id,c.enabled
 FROM users u JOIN oidc_config c ON c.org_id=u.org_id WHERE u.id=$1`, r.UserID).
		Scan(&s.org, &s.role, &s.issuer, &s.subject, &s.user, &s.config, &s.configIssuer, &s.client, &s.enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrProfile
	}
	if err != nil {
		return s, dbError(err)
	}
	if s.org != r.OrgID || s.configIssuer != r.Issuer || s.client != r.ClientID {
		return s, ErrProfile
	}
	return s, nil
}
func readAudit(ctx context.Context, tx pgx.Tx, id string) (*audit, error) {
	a := new(audit)
	err := tx.QueryRow(ctx, `SELECT org_id,actor_user_id,action,target FROM audit_log WHERE id=$1`, id).Scan(&a.org, &a.actor, &a.action, &a.target)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, dbError(err)
	}
	return a, nil
}
func initial(s state, r Request) error {
	if s.enabled {
		return ErrProfile
	}
	if s.role != r.ExpectedRole {
		return ErrRole
	}
	if s.issuer != "" || s.subject != "" {
		return ErrBound
	}
	return nil
}
func result(s state, r Request, status, planned string, changed bool) Result {
	current := authority(s)
	raw, _ := json.Marshal(r)
	return Result{Status: status, RequestID: r.RequestID, RequestSHA256: hash(raw), Changed: changed, CurrentRole: s.role, CurrentAuthoritySHA256: current, PlannedAuthoritySHA256: planned, OriginalAuthorityMatchesCurrent: current == planned}
}
func reconcile(s state, r Request, a *audit, expected string) (Result, error) {
	if a == nil {
		return Result{}, ErrBound
	}
	var t auditTarget
	d := json.NewDecoder(bytes.NewBufferString(a.target))
	d.DisallowUnknownFields()
	if d.Decode(&t) != nil || !validHash(t.AuthoritySHA256) || a.org != r.OrgID || a.actor != nil || a.action != Action ||
		a.target != target(r, t.AuthoritySHA256) || s.issuer != r.Issuer || s.subject != r.Subject {
		return Result{}, ErrAudit
	}
	if expected != "" && expected != t.AuthoritySHA256 {
		return Result{}, ErrAuthority
	}
	// Legitimate later native authority and provider enabling are NOT rewound.
	return result(s, r, "reconciled", t.AuthoritySHA256, false), nil
}

// Execute opens one dedicated connection and never retries a transaction/write.
// The session advisory lock precedes the first audit read, survives the plan-to-
// apply transaction boundary, and is released by closing this owned connection.
// Read-only planning/reconciliation uses READ COMMITTED after lock acquisition.
func Execute(ctx context.Context, dsn string, r Request, apply bool, expected, expectedRequest string) (Result, error) {
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	if apply && !validHash(expected) {
		return Result{}, ErrAuthority
	}
	if apply && (!validHash(expectedRequest) || requestDigest(r) != expectedRequest) {
		return Result{}, ErrRequest
	}
	if dsn == "" {
		return Result{}, ErrDatabase
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return Result{}, ErrDatabase
	}
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["statement_timeout"] = "5000"
	cfg.RuntimeParams["lock_timeout"] = "250"
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
	cfg.RuntimeParams["application_name"] = "oidc-prelink"
	cfg.RuntimeParams["timezone"] = "UTC"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return Result{}, ErrDatabase
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()
	var acquired bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, operationKey(r.RequestID)).Scan(&acquired); err != nil {
		return Result{}, dbError(err)
	}
	if !acquired {
		return Result{}, ErrBusy
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Result{}, dbError(err)
	}
	a, err := readAudit(ctx, tx, r.RequestID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return Result{}, err
	}
	s, err := readState(ctx, tx, r)
	if err != nil {
		_ = tx.Rollback(ctx)
		return Result{}, err
	}
	if a != nil {
		out, e := reconcile(s, r, a, expected)
		_ = tx.Rollback(ctx)
		return out, e
	}
	if err = initial(s, r); err != nil {
		_ = tx.Rollback(ctx)
		return Result{}, err
	}
	planned := authority(s)
	if !apply {
		_ = tx.Rollback(ctx)
		return result(s, r, "planned", planned, false), nil
	}
	if planned != expected {
		_ = tx.Rollback(ctx)
		return Result{}, ErrAuthority
	}
	if err = tx.Rollback(ctx); err != nil {
		return Result{}, dbError(err)
	}
	tx, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Result{}, dbError(err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	// Config share lock prevents a concurrent enable/repoint; user NOWAIT lock
	// serializes competing request IDs without waiting on a native writer.
	var locked string
	err = tx.QueryRow(ctx, `SELECT org_id FROM oidc_config WHERE org_id=$1 FOR SHARE NOWAIT`, r.OrgID).Scan(&locked)
	if err != nil {
		return Result{}, dbError(err)
	}
	err = tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT`, r.UserID).Scan(&locked)
	if err != nil {
		return Result{}, dbError(err)
	}
	a, err = readAudit(ctx, tx, r.RequestID)
	if err != nil {
		return Result{}, err
	}
	s, err = readState(ctx, tx, r)
	if err != nil {
		return Result{}, err
	}
	if a != nil {
		return reconcile(s, r, a, expected)
	}
	if err = initial(s, r); err != nil {
		return Result{}, err
	}
	if authority(s) != expected {
		return Result{}, ErrAuthority
	}
	original := s
	tag, err := tx.Exec(ctx, `UPDATE users SET sso_issuer=$1,sso_subject=$2 WHERE id=$3 AND org_id=$4 AND sso_issuer='' AND sso_subject=''`, r.Issuer, r.Subject, r.UserID, r.OrgID)
	if err != nil {
		var p *pgconn.PgError
		if errors.As(err, &p) && p.Code == "23505" {
			return Result{}, ErrIdentity
		}
		return Result{}, dbError(err)
	}
	if tag.RowsAffected() != 1 {
		return Result{}, ErrBound
	}
	after, err := readState(ctx, tx, r)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(original.user, after.user) || !bytes.Equal(original.config, after.config) || after.issuer != r.Issuer || after.subject != r.Subject {
		return Result{}, ErrPreservation
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(id,org_id,actor_user_id,action,target) VALUES($1,$2,NULL,$3,$4)`, r.RequestID, r.OrgID, Action, target(r, expected))
	if err != nil {
		var p *pgconn.PgError
		if errors.As(err, &p) && p.Code == "23505" {
			return Result{}, ErrAudit
		}
		return Result{}, dbError(err)
	}
	// Recheck after the audit too: a native/future trigger must not smuggle
	// changes into nonbinding user/config authority or replace our audit.
	final, err := readState(ctx, tx, r)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(original.user, final.user) || !bytes.Equal(original.config, final.config) {
		return Result{}, ErrPreservation
	}
	writtenAudit, err := readAudit(ctx, tx, r.RequestID)
	if err != nil {
		return Result{}, err
	}
	if _, err = reconcile(final, r, writtenAudit, expected); err != nil {
		return Result{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Result{}, ErrUnknown
	}
	return result(final, r, "applied", expected, true), nil
}
