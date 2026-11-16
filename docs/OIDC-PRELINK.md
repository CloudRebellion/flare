# Explicit existing-account OIDC prelinks

`cmd/oidc-prelink` is a standalone operator, not a server subcommand. It imports
no server startup, migrations, analytics or telemetry. It never enables a
provider, creates a user, matches an email, changes a role, or replaces a binding.
It is not automatically added to the runtime image by this source change.

Create a canonical, regular, non-symlink, single-link JSON file owned by the
executing UID with permissions `0600`. Parent symlink paths are refused. Keep
its contents private. The closed request schema is:

```json
{
  "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "user_id": "proved-existing-user-id",
  "org_id": "proved-existing-org-id",
  "expected_role": "owner",
  "issuer": "https://issuer.example.test",
  "client_id": "reviewed-existing-client",
  "subject": "proved-provider-subject"
}
```

Use a fresh canonical UUIDv4 for one reviewed operation. IDs are exact: do not
infer them from an owner, email, display name, slug or account ordering. Subject
is exact UTF-8, nonempty, at most255bytes, with no surrounding whitespace or
control characters. Unknown/duplicate JSON fields and trailing values refuse.
The issuer/client must already match this organization's existing provider row.

Pass the existing authorized database connection only through `DATABASE_URL`.
Do not put it or the subject in command arguments, shell traces or logs. The
operator returns fixed error classes, hashes, request UUID and current role;
it never prints a DSN, password hash, client secret or subject.

Default invocation reads a plan in a PostgreSQL READ ONLY/READ COMMITTED
transaction and makes no persistent database change:

```sh
./oidc-prelink --request /private/operator/request.json
```

Record the `request_sha256` (canonical request) and `planned_authority_sha256`.
The authority covers **all** nonbinding user columns plus the entire provider
configuration row, using PostgreSQL JSON including future columns. Raw rows,
password hashes, secret columns and native session state are never output.
Review the protected request and plan together; keep the exact request unchanged
between plan and apply. A new/different request requires a new review, even if a
user's nonbinding authority hash happens to match.

Only an explicit apply with BOTH the exact planned authority hash and canonical
request hash may bind. Changing subject, request UUID or any other request field
refuses even when the nonbinding row authority is unchanged:

```sh
./oidc-prelink --request /private/operator/request.json --apply \
  --expected-authority-sha256 <planned-authority-sha256> \
  --expected-request-sha256 <request-sha256>
```

For an initial binding the request digest must match, provider must be disabled, current role must equal
the expected role, both binding columns must be empty and the complete authority
hash must match. One owned connection takes a nonblocking per-request advisory
lock **before** reading its audit, retaining it across the plan/apply transaction
boundary and releasing it by closing that connection. Apply share-locks the
provider and update-locks the exact user with NOWAIT; query/lock/transaction and
connection deadlines bound work. It sets only `users.sso_issuer/sso_subject`,
then rechecks every nonbinding column and provider row. A native `audit_log`
record is inserted in the same transaction with ID=request UUID,
`action=sso.prelink.operator`, NULL actor, and a versioned target holding the
canonical request/subject/profile hashes. It does not impersonate a human.
Unique identity/audit conflicts or failed audit writes roll back the binding.
There is no automatic retry and no schema change.

A same-request outcome with matching audit, user/org, exact current issuer/client
profile and binding reconciles read-only. This can happen after the provider is
legitimately enabled or native password, role, session-revocation or future
columns have changed. The result reports the **current** role/hash, original
planned hash, and whether they match; it never rewinds or claims original
current authority. A wrong audit, changed request/profile/user/binding or an
unaudited existing binding refuses. Reconciliation does not authenticate a user
or establish that account is enabled; it only verifies this operation's outcome.

`COMMIT_OUTCOME_UNKNOWN` must be preserved. Do not rerun apply blindly or invent
an alternate UUID. Use the same protected request in default read-only mode to
reconcile once current transport/state can be inspected. A busy/timeout result
is refusal, not permission to bypass locks. No database rollback, identity
reassignment, provider activation, application access grant or login is included.

## Qualification requirements

The package and command use Unix file semantics on Linux/macOS and cross-compile
for Linux with `CGO_ENABLED=0`;
they import pgx, not the analytics/HTTP application. Integration tests use only
a disposable operator-supplied `FLARE_TEST_DATABASE_URL`, isolated random
schemas and exact relevant native migrations001/011/012/016/022 embedded in the
test binary. They add a future-column sentinel and test real PostgreSQL locks,
unique conflicts, simultaneous requests, audit failure/trigger rollback,
all-other-row preservation and same-request reconciliation after legitimate
native changes. They never invoke the production migration runner.

Set `FLARE_OIDC_PRELINK_REQUIRE_DB=1` and select the complete top-level
`TestPostgresPrelink`. Missing DB then fails instead of skips. Require exit0,
all its subtests, and `OIDC_PRELINK_POSTGRES_REQUIRED_PASSED`; marker absence is
not a pass. Pure private-file/closed-JSON/CLI-redaction tests are separate. Run
only through the normal admitted build/test process; no new module/cache,
privilege, network or production test is implied. Source authoring is not a
compile, PostgreSQL qualification, deployment, binding or SSO-acceptance claim.
